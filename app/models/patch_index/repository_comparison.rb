module PatchIndex
  module RepositoryComparison
    def self.for_occurrence(occurrence)
      release = occurrence.patch_release
      key = [release.distribution, release.package_name, release.version, occurrence.name, occurrence.patch.sha256]
      audit, patch = index[key]
      return unless audit && audit['repository'] == release.source_repository['purl']
      return unless audit['archive_sha256'] == release.source_repository['archive_sha256']
      return unless Array(release.metadata['files']).include?(audit.fetch('debian_original'))
      return unless patch.fetch('changed_paths').sort == Array(occurrence.scope_evidence['files']).sort
      return unless [nil, 'path missing or nested'].include?(occurrence.scope_evidence['reason'])

      audit.slice('commit_checked', 'debian_original').merge(patch.slice('paths', 'identical', 'differing_or_absent', 'all_paths_corroborated'))
    end

    def self.index
      @index ||= load_index(Rails.application.config.x.patch_catalog_directory)
    end

    def self.load_index(directory)
      directory.glob('repository-*.json').each_with_object({}) do |file, results|
        audit = JSON.parse(file.read)
        audit.fetch('patches').each do |patch|
          key = audit.values_at('distribution', 'package', 'version') + patch.values_at('patch', 'sha256')
          results[key] = [audit, patch]
        end
      end
    end
  end
end
