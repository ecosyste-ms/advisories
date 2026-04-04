json.ecosystem package['ecosystem']
json.package_name package['package_name']
json.versions package['versions']
json.purl PurlParser.generate_purl(
  ecosystem: package['ecosystem'],
  package_name: package['package_name']
)

if package['statistics']
  json.statistics do
    json.dependent_packages_count package['statistics']['dependent_packages_count']
    json.dependent_repos_count package['statistics']['dependent_repos_count']
    json.downloads package['statistics']['downloads']
    json.downloads_period package['statistics']['downloads_period']
  end

  json.affected_versions package['affected_versions'] || []
  json.unaffected_versions package['unaffected_versions'] || []
end