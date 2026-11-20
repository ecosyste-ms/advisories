require_relative 'catalog_files'

counts = Hash.new(0)

if (name = ENV['DEBIAN_PACKAGE'].presence)
  CatalogFiles.each_row do |row|
    next unless row.fetch('source') == name
    release = PatchRelease.find_by!(distribution: 'debian', package_name: name, version: row.fetch('version'))
    release.with_lock do
      sha = row.fetch('sha256')
      raise 'catalog archive changed' unless sha == release.metadata.dig('debian_catalog', 'archive_sha256')
      files = CatalogFiles.archive_members(CatalogFiles.path(row), sha)
      sources = PatchIndex::SourceRepository.debian_sources(release.metadata, files)
      declaration = PatchIndex::SourceRepository.declaration(sources, archive_sha256: sha)
      release.update!(metadata: release.metadata.merge('source_repository' => declaration))
      counts['catalog'] += 1 if declaration
    end
  end
end

PatchRelease.where(distribution: 'homebrew').find_each do |release|
  release.with_lock do
    sources = PatchIndex::SourceRepository.homebrew_sources(release.metadata)
    declaration = PatchIndex::SourceRepository.declaration(sources)
    release.update!(metadata: release.metadata.merge('source_repository' => declaration))
    counts['homebrew'] += 1 if declaration
  end
end
puts JSON.generate(counts)
