json.extract! advisory, :uuid, :url, :title, :description, :origin, :severity, :published_at, :withdrawn_at, :classification, :cvss_score, :cvss_vector, :references, :source_kind, :identifiers, :repository_url, :blast_radius, :created_at, :updated_at, :epss_percentage, :epss_percentile
json.api_url api_v1_advisory_url(advisory)
json.html_url advisory_url(advisory)

json.packages advisory.packages do |package|
  json.partial! 'package', package: package
end

json.related_packages_url related_packages_api_v1_advisory_url(advisory)

json.related_advisories advisory.cached_related_advisories do |related|
  json.uuid related['uuid']
  json.source_kind related['source_kind']
  json.url related['url']
end
