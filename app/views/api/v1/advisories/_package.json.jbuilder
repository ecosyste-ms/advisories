json.ecosystem package['ecosystem']
json.package_name package['package_name']
json.versions package['versions']
json.purl PurlParser.generate_purl(
  ecosystem: package['ecosystem'],
  package_name: package['package_name']
)

if package_record&.last_synced_at
  json.statistics do
    json.dependent_packages_count package_record.dependent_packages_count
    json.dependent_repos_count package_record.dependent_repos_count
    json.downloads package_record.downloads
    json.downloads_period package_record.downloads_period
  end

  json.affected_versions package['affected_versions'] || []
  json.unaffected_versions package['unaffected_versions'] || []
end