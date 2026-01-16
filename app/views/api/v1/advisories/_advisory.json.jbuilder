json.extract! advisory, :uuid, :url, :title, :description, :origin, :severity, :published_at, :withdrawn_at, :classification, :cvss_score, :cvss_vector, :references, :source_kind, :identifiers, :repository_url, :blast_radius, :created_at, :updated_at, :epss_percentage, :epss_percentile

json.packages advisory.packages_with_records do |package, package_record|
  json.partial! 'package', package: package, package_record: package_record
end

json.related_advisories advisory.related_advisories do |related|
  json.extract! related, :uuid, :source_kind, :url
end
