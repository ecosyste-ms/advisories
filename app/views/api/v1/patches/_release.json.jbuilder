json.extract! release, :distribution, :package_name, :version, :upstream_version, :repository_url,
  :upstream_ecosystem, :upstream_package_name, :upstream_purl, :source_url, :imported_at
json.package_url ecosystem_package_url(release.distribution, release.package_name, tab: 'patches')
