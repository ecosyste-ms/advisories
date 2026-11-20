module PatchIndex
  class DebianCatalog
    def initialize(blob_directory)
      @blobs = blob_directory
    end

    def import(row, extracted, archive_url:)
      sha = row.fetch('sha256')
      raise IOError, 'wrong archive' unless extracted.fetch('archive_sha256') == sha
      name, version = row.values_at('source', 'version')
      identity = { distribution: 'debian', package_name: name, version: version, revision: version.rpartition('-').last }
      snapshot = { 'suite' => 'trixie', 'archive_sha256' => sha, 'archive_url' => archive_url,
        'row_sha256' => Digest::SHA256.hexdigest(row.to_json) }
      PatchRelease.transaction do
        release = PatchRelease.find_or_create_by!(identity) do |record|
          record.assign_attributes(source_url: archive_url, metadata: {}, imported_at: Time.current,
            component: { 'reason' => 'upstream identity has not been assessed' })
        end
        release.lock!
        metadata = release.metadata.merge('debian_catalog' => snapshot)
        if extracted.key?('repository_files')
          sources = SourceRepository.debian_sources(metadata, extracted.fetch('repository_files'))
          metadata['source_repository'] = SourceRepository.declaration(sources, archive_sha256: sha)
        elsif release.source_repository && release.source_repository['archive_sha256'] != sha
          metadata.delete('source_repository')
        end
        if release.metadata['debian_catalog'] == snapshot
          missing = Patch.where(id: release.patch_occurrences.select(:patch_id)).where.missing(:patch_body)
          missing.pluck(:sha256).each { |digest| PatchBody.store!(digest, @blobs.join(digest.first(2), digest).binread) }
          release.update!(metadata: metadata) unless metadata == release.metadata
          next
        end
        entries = declarations(row, extracted, archive_url)
        patches = entries.uniq { |e| e[:sha256] }.map { |e| e.slice(:sha256, :headers) }
        Patch.insert_all(patches, unique_by: :sha256)
        ids = Patch.where(sha256: patches.pluck(:sha256)).pluck(:sha256, :id).to_h
        existing = release.patch_occurrences.index_by(&:name)
        additions = []
        entries.each do |entry|
          PatchBody.store!(entry.fetch(:sha256), entry.fetch(:body))
          patch_id = ids.fetch(entry.fetch(:sha256))
          if (occurrence = existing[entry.fetch(:name)])
            raise IOError, "different bytes for existing #{entry[:name]}" unless occurrence.patch_id == patch_id
            old = occurrence.declaration.fetch('advisory_evidence', {}).transform_values { |fields| fields.reject { |f| f.start_with?('udd.') } }.reject { |_, fields| fields.empty? }
            evidence = old.merge(Document.udd_references(entry[:declaration]['udd'])) { |_, a, b| a | b }
            occurrence.update!(advisory_ids: evidence.keys, declaration: occurrence.declaration.merge(
              'udd' => entry[:declaration]['udd'], 'advisory_evidence' => evidence))
          else
            additions << entry.except(:headers, :sha256, :body).merge(patch_id: patch_id, patch_release_id: release.id,
              mapping: { status: 'unresolved', reason: 'upstream identity has not been assessed for this patch' })
          end
        end
        PatchOccurrence.insert_all!(additions) if additions.any?
        release.update!(metadata: metadata, imported_at: Time.current)
      end
    end

    def declarations(row, extracted, url)
      udd = row.fetch('patches').index_by { |patch| patch.fetch('patch') }
      quilt_entries(row.fetch('source'), row.fetch('version'), extracted, url, udd: udd)
    end

    def quilt_entries(package, version, extracted, url, udd: nil)
      names = udd ? udd.keys : extracted.fetch('members').keys
      changes = Debian.new.named_changes(extracted.fetch('changelog'), package, version, names)
      names.map do |name|
        member = extracted.fetch('members').fetch(name)
        sha = member.fetch('sha256')
        raise IOError, "missing patch bytes for #{name}" unless sha&.match?(/\A[0-9a-f]{64}\z/)
        position, options = member['series']
        raise IOError, "missing series declaration for #{name}" unless position
        strip = options.empty? ? 1 : options.first[/\A-p(\d+)\z/, 1]&.to_i if options.size <= 1
        bytes = @blobs.join(sha.first(2), sha).binread
        doc = Document.new(bytes, strip: strip)
        raise IOError, "patch checksum mismatch for #{name}" unless doc.sha256 == sha
        declaration = { 'member' => "debian/patches/#{name}", 'quilt_options' => options, 'position' => position,
          'archive_sha256' => extracted.fetch('archive_sha256'), 'series_path' => extracted.fetch('series_path', 'debian/patches/series') }
        declaration['udd'] = udd.fetch(name) if udd
        if changes.key?(name)
          declaration['changelog'] = { 'url' => url, 'member' => 'debian/changelog', 'items' => changes.fetch(name) }
        end
        entry = doc.entry(name: name, source_url: url, declaration: declaration)
        entry[:scope_evidence]['reason'] ||= 'changed paths have not been checked against upstream source'
        entry
      end
    end
  end
end
