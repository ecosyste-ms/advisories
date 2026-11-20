json.extract! patch, :id, :sha256, :headers
json.api_url api_v1_patch_url(patch)
json.html_url patch_url(patch.sha256)
json.download_url download_patch_url(patch.sha256) if @downloadable.include?(patch.sha256)
occurrences = @occurrences.fetch(patch.id, [])
json.occurrences occurrences do |occurrence|
  json.status 'declared'
  json.html_url patch_url(patch.sha256, anchor: dom_id(occurrence))
  json.assertions occurrence.assertions
  json.advisory_roles occurrence.advisory_roles
  json.extract! occurrence, :name, :source_url, :declaration, :project_purl, :purl, :mapping, :scope_evidence, :advisory_ids
  if (key = occurrence.upstream_package_key)
    json.upstream_package_url ecosystem_package_url(*key)
  end
  if (repository = occurrence.source_repository)
    json.source_repository do
      json.merge! repository
      json.patches_api_url api_v1_patches_url(purl: repository.fetch('purl'))
      json.patches_html_url patches_url(purl: repository.fetch('purl'))
    end
  end
  json.downstream do
    release = occurrence.patch_release
    json.extract! release, :distribution, :package_name, :version, :revision, :source_url, :imported_at
    json.package_url ecosystem_package_url(release.distribution, release.package_name)
  end
end
identifiers = occurrences.flat_map(&:advisory_ids).uniq
json.referenced_advisories identifiers.flat_map { |id| @advisories.fetch(id, []) }.uniq do |advisory|
  json.extract! advisory, :uuid, :url, :withdrawn_at
  json.affected_packages Array(advisory.packages) do |package|
    json.extract! package, 'ecosystem', 'package_name', 'versions'
  end
  json.matched_identifiers (Array(advisory.identifiers) + [advisory.uuid]).intersection(identifiers)
  json.api_url api_v1_advisory_url(advisory)
  json.html_url advisory_url(advisory)
end
