class PatchRelease < ApplicationRecord
  has_many :patch_occurrences, dependent: :delete_all

  def source_repository
    metadata['source_repository']
  end

  def self.for_source_repository(purl)
    where("metadata #>> '{source_repository,purl}' = ?", purl)
  end

  def display_version
    case distribution
    when 'conda-forge' then "#{version} (#{revision})"
    when 'homebrew' then "#{version} (revision #{revision})"
    when 'nixpkgs' then "#{version} (#{[metadata['system'], revision.first(12)].compact.join(', ')})"
    else version
    end
  end

  def self.record!(identity, source_url:, metadata:, component:, entries:)
    transaction do
      release = create_or_find_by!(identity) do |record|
        record.assign_attributes(source_url: source_url, metadata: metadata, component: component, imported_at: Time.current)
      end
      release.lock!
      catalog = release.metadata.slice('debian_catalog')
      if release.distribution == 'homebrew'
        sources = PatchIndex::SourceRepository.homebrew_sources(metadata)
        metadata = metadata.merge('source_repository' => PatchIndex::SourceRepository.declaration(sources))
      elsif !metadata.key?('source_repository') && (sha = release.source_repository&.fetch('archive_sha256', nil))
        archived = Array(metadata['files']).any? { |file| file['sha256'] == sha }
        if archived || (metadata['files'].nil? && catalog.dig('debian_catalog', 'archive_sha256') == sha)
          metadata = metadata.merge('source_repository' => release.source_repository)
        end
      end
      release.update!(source_url: source_url, metadata: metadata.merge(catalog), component: component, imported_at: Time.current)
      catalog_entries = if catalog.present?
        release.patch_occurrences.where("declaration ? 'udd'").preload(:patch).index_by(&:name)
      else
        {}
      end

      names = entries.map do |entry|
        if (previous = catalog_entries.delete(entry.fetch(:name)))
          raise IOError, "archive digest differs for #{previous.name}" unless previous.patch.sha256 == entry.fetch(:sha256)
          udd = previous.declaration.fetch('udd')
          refs = entry.fetch(:declaration).fetch('advisory_evidence').merge(PatchIndex::Document.udd_references(udd)) { |_, a, b| a | b }
          entry = entry.merge(advisory_ids: refs.keys, declaration: entry.fetch(:declaration).merge('udd' => udd, 'advisory_evidence' => refs))
        end
        patch = Patch.find_or_create_by!(sha256: entry.fetch(:sha256)) { |p| p.headers = entry.fetch(:headers) }
        patch.update!(headers: entry.fetch(:headers)) if patch.headers != entry.fetch(:headers)
        PatchBody.store!(patch.sha256, entry[:body]) if entry.key?(:body)
        occurrence = release.patch_occurrences.find_or_initialize_by(name: entry.fetch(:name))
        occurrence.assign_attributes(entry.except(:headers, :sha256, :body).merge(patch: patch))
        occurrence.resolve!
        occurrence.name
      end
      raise IOError, 'incomplete series relative to the indexed catalog' if catalog_entries.any?
      raise ArgumentError, 'duplicate declaration name' unless names.uniq == names
      release.patch_occurrences.where.not(name: names).delete_all
      release
    end
  end
end
