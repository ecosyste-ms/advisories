json.extract! patch, :sha256, :byte_size, :headers
json.api_url api_v1_patch_url(patch)
json.html_url patch_url(patch)
json.download_url download_patch_url(patch)
occurrences = @occurrences.fetch(patch.id, [])
json.occurrences occurrences do |occurrence|
  json.extract! occurrence, :name, :position, :source_url, :advisory_ids, :advisory_roles, :declaration
  json.html_url patch_url(patch, anchor: dom_id(occurrence))
  json.release { json.partial! 'api/v1/patches/release', release: occurrence.patch_release }
end
identifiers = occurrences.flat_map(&:advisory_ids).uniq
json.referenced_advisories identifiers.flat_map { |id| @advisories.fetch(id, []) }.uniq do |advisory|
  json.extract! advisory, :uuid, :url, :withdrawn_at
  json.matched_identifiers advisory.patch_identifiers.intersection(identifiers)
  json.api_url api_v1_advisory_url(advisory)
  json.html_url advisory_url(advisory)
end
