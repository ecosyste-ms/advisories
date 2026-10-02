class AdvisoryRecord < ApplicationRecord
  belongs_to :source
  belongs_to :advisory, optional: true

  CACHE_FIELDS = %w[affected_versions unaffected_versions statistics].freeze
  PAYLOAD_FIELDS = %w[uuid url title description origin severity published_at withdrawn_at classification cvss_score cvss_vector references source_kind identifiers epss_percentage epss_percentile packages].freeze

  def self.identity_keys(payload)
    [payload.fetch('uuid'), *payload.fetch('identifiers', [])].compact.map(&:downcase).uniq.sort
  end

  def self.base_packages(packages)
    packages.map { |package| package.except(*CACHE_FIELDS) }
  end

  def self.write_lock
    transaction do
      connection.execute("SELECT pg_advisory_xact_lock(hashtextextended('advisory_records', 0))")
      yield
    end
  end

  def self.for_import(source, external_id)
    record = where(source: source).find_by('lower(external_id) = ?', external_id.downcase)
    record ||= new(source: source, external_id: external_id)
    record.advisory ||= source.advisories.find_by(uuid: external_id) if record.new_record?
    record
  end

  def self.stage(source, entries, token)
    write_lock do
      entries.each do |attributes, raw|
        payload = attributes.as_json.slice(*PAYLOAD_FIELDS)
        record = for_import(source, payload.fetch('uuid'))
        if record.pending_sync_token == token
          payload['packages'] = merge_package_ranges(record.pending_payload.fetch('packages'), payload.fetch('packages'))
          raw = (record.pending_raw + raw.as_json).uniq
        end
        record.update!(pending_payload: payload, pending_raw: raw, pending_sync_token: token)
      end
    end
  end

  def self.merge_package_ranges(previous, incoming)
    (previous + incoming).group_by { |package| [package['ecosystem'].downcase, package['package_name'].downcase] }.values.map do |packages|
      packages.first.merge('versions' => packages.flat_map { |package| package.fetch('versions', []) }.uniq)
    end
  end

  def self.publish(source, token)
    where(source: source, pending_sync_token: token).find_in_batches(batch_size: 100) do |batch|
      result = write_lock do
        records = batch.map do |pending|
          pending.reload
          pending.update!(payload: pending.pending_payload, raw: pending.pending_raw,
                          identifiers: identity_keys(pending.pending_payload), pending_payload: nil,
                          pending_raw: nil, pending_sync_token: nil)
          pending
        end
        reconcile(records)
      end
      yield result
    end
  end

  def self.import(source, entries)
    write_lock do
      records = entries.map do |attributes, raw|
        payload = attributes.as_json.slice(*PAYLOAD_FIELDS)
        record = for_import(source, payload.fetch('uuid'))
        record.assign_attributes(payload: payload, raw: raw, identifiers: identity_keys(payload))
        record.save! if record.changed?
        record
      end
      reconcile(records)
    end
  end

  def self.connected_records(seeds)
    records = seeds.index_by(&:id)
    keys = Set.new
    advisory_ids = Set.new
    frontier = seeds
    until frontier.empty?
      new_keys = frontier.flat_map(&:identifiers).to_set - keys
      new_ids = frontier.filter_map(&:advisory_id).to_set - advisory_ids
      keys.merge(new_keys)
      advisory_ids.merge(new_ids)
      neighbors = where('identifiers && ARRAY[?]::text[]', new_keys.to_a)
      neighbors = neighbors.or(where(advisory_id: new_ids.to_a)) if new_ids.any?
      frontier = neighbors.to_a.reject { |record| records.key?(record.id) }
      frontier.each { |record| records[record.id] = record }
    end
    records.values.reject { |record| record.payload.empty? }
  end

  def self.alias_groups(records)
    parents = records.to_h { |record| [record.id, record.id] }
    root = lambda do |id|
      current = id
      current = parents.fetch(current) until parents.fetch(current) == current
      while id != current
        following = parents.fetch(id)
        parents[id] = current
        id = following
      end
      current
    end
    owners = {}
    records.each do |record|
      record.identifiers.each do |identifier|
        if owners.key?(identifier)
          parents[root.call(record.id)] = root.call(owners[identifier])
        else
          owners[identifier] = record.id
        end
      end
    end
    records.group_by { |record| root.call(record.id) }.values
  end

  def self.reconcile(seeds)
    records = connected_records(seeds)
    sources = Source.where(id: records.map(&:source_id).uniq).index_by(&:id)
    existing = Advisory.where(id: records.filter_map(&:advisory_id).uniq).index_by(&:id)
    related_identifiers = existing.values.flat_map(&:identifiers)
    result = { advisory_ids: Set.new, packages: Set.new }
    kept = Set.new
    groups = alias_groups(records).map do |group|
      group.sort_by { |record| [sources.fetch(record.source_id).kind.downcase == 'github' ? 0 : 1, record.external_id, record.source_id] }
    end
    groups.sort_by { |group| [sources.fetch(group.first.source_id).kind.downcase == 'github' ? 0 : 1, group.first.external_id] }.each do |ranked|
      primary = ranked.first
      attributes = primary.payload.deep_dup
      attributes['source_id'] = primary.source_id
      attributes['identifiers'] = (ranked.flat_map { |record| record.payload.fetch('identifiers', []) } + ranked.drop(1).map(&:external_id)).uniq.sort
      attributes['references'] = ranked.flat_map { |record| record.payload.fetch('references', []) }.uniq
      github, others = ranked.partition { |record| sources.fetch(record.source_id).kind.downcase == 'github' }
      github_packages = merge_package_ranges([], github.flat_map { |record| record.payload.fetch('packages', []) })
      other_packages = merge_package_ranges([], others.flat_map { |record| record.payload.fetch('packages', []) })
      attributes['packages'] = (github_packages + other_packages)
        .uniq { |package| [package['ecosystem'].downcase, package['package_name'].downcase] }

      candidates = ranked.filter_map { |record| existing[record.advisory_id] }.uniq.reject { |record| kept.include?(record.id) }
      advisory = candidates.find { |record| record.uuid == attributes['uuid'] } || candidates.first || Advisory.new
      old_packages = advisory.packages
      packages_changed = base_packages(old_packages) != attributes['packages']
      attributes['packages'] = old_packages unless packages_changed
      attributes['identifiers'] = advisory.identifiers if advisory.identifiers.sort == attributes['identifiers'].sort
      advisory.assign_attributes(attributes)
      advisory.importing = true
      if advisory.changed?
        # Source records, rather than model validation, determine identity during a merge.
        advisory.save!(validate: false)
        if packages_changed || advisory.saved_change_to_repository_url?
          advisory.related_packages.delete_all
        end
        advisory.cache_affected_versions!
        result[:advisory_ids].add(advisory.id)
        (old_packages + advisory.packages).each { |package| result[:packages].add([package['ecosystem'], package['package_name']]) }
      end
      where(id: ranked.map(&:id)).where.not(advisory_id: advisory.id).or(where(id: ranked.map(&:id), advisory_id: nil)).update_all(advisory_id: advisory.id)
      kept.add(advisory.id)
      related_identifiers.concat(advisory.identifiers)
    end

    existing.each_value do |advisory|
      next if kept.include?(advisory.id)
      advisory.packages.each { |package| result[:packages].add([package['ecosystem'], package['package_name']]) }
      advisory.importing = true
      advisory.destroy!
      result[:advisory_ids].merge(kept)
    end
    Advisory.where('identifiers && ARRAY[?]::varchar[]', related_identifiers.uniq)
      .or(Advisory.where(id: kept.to_a)).find_each(&:cache_related_advisories!)
    result
  end

  def self.backfill
    Source.where('lower(kind) IN (?)', %w[github osv]).find_each do |source|
      source.with_sync_lock do
        source.advisories.find_in_batches(batch_size: 100) do |advisories|
          result = write_lock do
            records = advisories.filter_map do |advisory|
              record = for_import(source, advisory.uuid)
              next unless record.payload.empty?
              payload = advisory.attributes.slice(*PAYLOAD_FIELDS)
              payload['packages'] = base_packages(payload['packages'])
              record.update!(advisory: advisory, payload: payload, identifiers: identity_keys(payload))
              record
            end
            reconcile(records) if records.any?
          end
          next unless result
          source.source_instance.enqueue_related_sync(result[:advisory_ids])
          result[:packages].each { |ecosystem, name| PackageSyncWorker.perform_async(ecosystem, name) }
        end
      end
    end
  end
end
