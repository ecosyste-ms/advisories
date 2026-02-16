json.array! @related_packages do |related|
  json.ecosystem related.package.ecosystem
  json.name related.package.name
  json.purl related.package.purl
  json.registry_url related.package.registry_url
  json.name_match related.name_match
  json.repo_fork related.repo_fork
  json.repo_package_count related.repo_package_count
end
