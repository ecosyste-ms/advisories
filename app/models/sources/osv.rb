require 'tempfile'

module Sources
  class Osv < Base
    BASE_URL = 'https://storage.googleapis.com/osv-vulnerabilities'.freeze
    # Each export covers every release of a distribution. Only packages in the listed
    # OSV ecosystem are kept, stored under the ecosystem it maps to.
    EXPORTS = {
      'Debian' => { 'Debian:13' => 'debian' },
      'Ubuntu' => { 'Ubuntu:24.04:LTS' => 'ubuntu' }
    }.freeze
    ARCHIVE_LIMIT = 4.gigabytes
    RECORD_LIMIT = 64.megabytes
    # Past this many changed records, one archive download is cheaper than fetching each.
    INCREMENTAL_LIMIT = 2000
    BATCH_SIZE = 500
    CVSS_TYPES = %w[CVSS_V4 CVSS_V3 CVSS_V2].freeze

    def initialize(source, http: PatchIndex::Http.new(interval: 0), batch_size: BATCH_SIZE)
      super(source)
      @http = http
      @batch_size = batch_size
    end

    def sync_advisories
      Advisory.connection_pool.with_connection do |db|
        locked = db.uncached { db.select_value("SELECT pg_try_advisory_lock(hashtext('advisories:sync:osv'))") }
        return 0 unless locked
        begin
          EXPORTS.keys.sum { |export| sync_export(export) }
        ensure
          db.uncached { db.select_value("SELECT pg_advisory_unlock(hashtext('advisories:sync:osv'))") }
        end
      end
    end

    def sync_export(export)
      index = modified_index(export)
      since = source.metadata.dig('osv_synced', export)&.then { |time| Time.iso8601(time) }
      pending = since ? index.take_while { |modified, _| modified > since } : index
      return 0 if pending.empty?

      records = if since && pending.size <= INCREMENTAL_LIMIT
        pending.reverse_each.lazy.map { |_, id| fetch_record(export, id) }
      else
        each_archive_record(export)
      end
      known = source.advisories.pluck(:uuid, :id, :updated_at).to_h { |uuid, id, updated_at| [uuid, [id, updated_at]] }
      count = 0
      enqueued = Set.new
      mapped = records.lazy.filter_map { |osv| map_advisory(osv, EXPORTS.fetch(export)) || retire(osv, known) }
      mapped.each_slice(@batch_size) do |batch|
        saved = save_batch(batch, known)
        next if saved.empty?
        # Follow-up work runs with its batch, so a later failure cannot strand it.
        refresh_related(saved.map(&:first))
        packages = saved.flat_map(&:last).select { |key| enqueued.add?(key) }
        PackageSyncWorker.perform_bulk(packages) if packages.any?
        count += saved.size
      end
      # Bulk inserts skip the counter cache.
      source.update_column(:advisories_count, source.advisories.count)
      synced = source.metadata.fetch('osv_synced', {}).merge(export => index.first.first.iso8601(9))
      source.update!(metadata: source.metadata.merge('osv_synced' => synced))
      Rails.logger.info "Synced #{count} OSV advisories for #{export}"
      count
    rescue IOError, JSON::ParserError, ArgumentError => e
      Rails.logger.error "OSV sync for #{export} stopped: #{e.class}: #{e.message}"
      0
    end

    # Newest first, as published.
    def modified_index(export)
      @http.get("#{BASE_URL}/#{export}/modified_id.csv").each_line(chomp: true).map do |line|
        modified, id = line.split(',', 2)
        [Time.iso8601(modified), id]
      end
    end

    def fetch_record(export, id)
      JSON.parse(@http.get("#{BASE_URL}/#{export}/#{URI.encode_uri_component(id)}.json", limit: RECORD_LIMIT), symbolize_names: true)
    end

    def each_archive_record(export)
      return enum_for(__method__, export) unless block_given?

      Tempfile.create(['osv', '.zip'], binmode: true) do |file|
        @http.download("#{BASE_URL}/#{export}/all.zip", file, limit: ARCHIVE_LIMIT)
        file.flush
        PatchIndex::ArchiveReader.open(file.path) do |archive|
          archive.each do |entry|
            yield JSON.parse(entry.read(RECORD_LIMIT), symbolize_names: true) if entry.regular? && entry.name.end_with?('.json')
          end
        end
      end
    end

    # Inserts new advisories in one statement and updates changed ones.
    # Returns [uuid, package keys] for each advisory written.
    def save_batch(batch, known)
      batch = batch.reject { |advisory| (stored = known[advisory[:uuid]]) && stored.last >= advisory[:updated_at].floor(6) }
      fresh, changed = batch.partition { |advisory| known[advisory[:uuid]].nil? }
      now = Time.current
      if fresh.any?
        # Package records arrive later, from the package sync, which fills these in.
        rows = fresh.map do |advisory|
          packages = advisory[:packages].map { |package| package.merge(affected_versions: [], unaffected_versions: []) }
          advisory.merge(source_id: source.id, created_at: now, packages: packages)
        end
        Advisory.insert_all(rows)
        cache_known_packages(fresh)
      end
      changed.each do |advisory|
        record = Advisory.find(known.fetch(advisory[:uuid]).first)
        record.update_columns(advisory.except(:uuid))
        record.cache_affected_versions!
      end
      batch.map { |advisory| [advisory[:uuid], advisory[:packages].map { |package| package.values_at(:ecosystem, :package_name) }] }
    end

    # A package that has already synced will not refresh these advisories unless its version list changes.
    def cache_known_packages(fresh)
      keys = fresh.flat_map { |advisory| advisory[:packages].map { |package| package.values_at(:ecosystem, :package_name) } }.uniq
      synced = Package.for_identities(keys).where.not(last_synced_at: nil).pluck(:ecosystem, :name).to_set
      return if synced.empty?

      uuids = fresh.select { |advisory| advisory[:packages].any? { |package| synced.include?(package.values_at(:ecosystem, :package_name)) } }.pluck(:uuid)
      source.advisories.where(uuid: uuids).find_each(&:cache_affected_versions!)
    end

    # A stored advisory that no longer names a tracked package is marked withdrawn,
    # at OSV's withdrawal time when it gives one. Always returns nil.
    def retire(osv, known)
      id, stored_at = known[osv[:id]]
      modified = Time.iso8601(osv[:modified])
      return unless id && stored_at < modified.floor(6)

      Advisory.where(id: id).update_all(withdrawn_at: osv[:withdrawn] || modified, updated_at: modified)
      nil
    end

    # Rebuilds the related list of every advisory sharing a CVE with the ones just written, in one read and one write.
    def refresh_related(uuids)
      cves = source.advisories.where(uuid: uuids).pluck(:identifiers).flatten.grep(/\ACVE-/).to_set
      return if cves.empty?

      rows = Advisory.where('identifiers && ARRAY[?]::varchar[]', cves.to_a).order(:id)
        .pluck(:id, :uuid, :source_kind, :url, :identifiers, :cached_related_advisories)
      sharing = Hash.new { |hash, cve| hash[cve] = [] }
      rows.each { |row| row[4].each { |identifier| sharing[identifier] << row if cves.include?(identifier) } }
      updates = rows.filter_map do |row|
        cve = row[4].find { |identifier| identifier.start_with?('CVE-') }
        next unless cves.include?(cve)
        related = sharing[cve].reject { |other| other[0] == row[0] }.map { |other| { 'uuid' => other[1], 'source_kind' => other[2], 'url' => other[3] } }
        [row[0], related] unless related == row[5]
      end
      return if updates.empty?

      db = Advisory.connection
      values = updates.map { |id, related| "(#{id.to_i}, #{db.quote(related.to_json)}::jsonb)" }.join(', ')
      db.execute("UPDATE advisories SET cached_related_advisories = v.related FROM (VALUES #{values}) AS v(id, related) WHERE advisories.id = v.id")
    end

    def map_advisory(osv, ecosystems)
      packages = extract_packages(osv[:affected] || [], ecosystems)
      return if packages.empty?

      vector, score = cvss(osv[:severity])
      {
        uuid: osv[:id],
        url: (osv[:references] || []).find { |reference| reference[:type] == 'ADVISORY' }&.dig(:url) || "https://osv.dev/vulnerability/#{osv[:id]}",
        title: osv[:summary].presence || osv[:details].to_s.squish.truncate(120).presence,
        description: osv[:details],
        origin: 'OSV',
        severity: severity_from_score(score),
        published_at: osv[:published],
        updated_at: Time.iso8601(osv[:modified]),
        withdrawn_at: osv[:withdrawn],
        cvss_score: score,
        cvss_vector: vector,
        references: (osv[:references] || []).filter_map { |reference| reference[:url] },
        source_kind: 'osv',
        identifiers: [osv[:id], *osv[:aliases], *osv[:upstream]].compact.uniq,
        packages: packages
      }
    end

    # Returns the first vector the scorer accepts, newest CVSS version first.
    def cvss(severity)
      Array(severity).sort_by { |entry| CVSS_TYPES.index(entry[:type]) || CVSS_TYPES.size }.each do |entry|
        score = parse_cvss_score(entry[:score])
        return [entry[:score], score] if score
      end
      nil
    end

    def extract_packages(affected, ecosystems)
      affected.each_with_object({}) do |entry, packages|
        ecosystem = ecosystems[entry.dig(:package, :ecosystem)]
        name = entry.dig(:package, :name)
        next unless ecosystem && name.present?

        versions = (entry[:ranges] || []).flat_map { |range| version_ranges(range) }
        next if versions.empty?

        package = packages[[ecosystem, name]] ||= { ecosystem: ecosystem, package_name: name, versions: [] }
        package[:versions] |= versions
      end.values
    end

    # The per-version lists are ignored: the ranges say the same thing in a fraction of the size.
    def version_ranges(range)
      return [] unless range[:type] == 'ECOSYSTEM'

      introduced = nil
      ranges = []
      (range[:events] || []).each do |event|
        if event[:introduced]
          introduced = event[:introduced]
        elsif introduced && (event[:fixed] || event[:last_affected])
          ranges << { vulnerable_version_range: range_string(introduced, event), first_patched_version: event[:fixed] }
          introduced = nil
        end
      end
      ranges << { vulnerable_version_range: range_string(introduced, {}), first_patched_version: nil } if introduced
      ranges
    end

    def range_string(introduced, event)
      upper = event[:fixed] ? "< #{event[:fixed]}" : ("<= #{event[:last_affected]}" if event[:last_affected])
      lower = ">= #{introduced}" unless introduced == '0' && upper
      [lower, upper].compact.join(', ')
    end
  end
end
