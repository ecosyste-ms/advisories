json.extract! package, :ecosystem, :package_name, :versions

if package_record&.last_synced_at
  json.statistics do
    json.dependent_packages_count package_record.dependent_packages_count
    json.dependent_repos_count package_record.dependent_repos_count
    json.downloads package_record.downloads
    json.downloads_period package_record.downloads_period
  end
  
  vulnerable_range = package['versions'].map { |v| v['vulnerable_version_range'] }.join(' || ')
  json.affected_versions package_record.affected_versions(vulnerable_range)
  json.unaffected_versions package_record.fixed_versions(vulnerable_range)
end