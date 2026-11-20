require_relative 'catalog_files'
require 'zlib'

root = CatalogFiles::ROOT
expected = {}
CatalogFiles.each_row do |row|
  members = JSON.parse(root.join('members', row.fetch('sha256') + '.json').read).fetch('members')
  expected[[row['source'], row['version']]] = members.transform_values { |m| m.fetch('sha256') }
end
catalog_count = expected.values.sum(&:size)
metrics = Hash.new { |h, k| h[k] = { count: 0, hashes: Set.new } }
per_source = Hash.new(0)
projects = Hash.new { |h, k| h[k] = Set.new }
reuse = Hash.new { |h, k| h[k] = Set.new }
occurrences_by_hash = Hash.new(0)
scope = PatchOccurrence.joins(:patch_release).where("patch_releases.metadata ? 'debian_catalog' AND patch_occurrences.declaration ? 'udd'")
path = root.join('trixie-patches.jsonl.gz')
Zlib::GzipWriter.open(path.to_s + '.part') do |output|
  scope.preload(:patch, :patch_release).find_each do |occ|
    release = occ.patch_release
    members = expected[[release.package_name, release.version]]
    next unless members&.key?(occ.name)
    sha = occ.patch.sha256
    raise "digest differs for #{release.package_name}/#{occ.name}" unless members.delete(occ.name) == sha
    udd = occ.declaration.fetch('udd')
    status = udd.fetch('upstream_status')
    ids = occ.advisory_ids
    origin = udd['origin'].to_s
    # Require an explicit commit locator or a full Git object ID in the origin field.
    origin_commit = origin.match?(%r{/(?:commit|commits)/[0-9a-f]{7,40}\b|\b(?:commit[: ]+)?[0-9a-f]{40}\b}i)
    upstream_header_commit = status == 'comes-from-upstream' && occ.patch.headers['commit'].present?
    roles = occ.advisory_roles
    tags = ['all', "udd_#{status}"]
    tags << 'applied_upstream_field' if udd['applied_upstream'].present?
    tags << 'advisory' if ids.any?
    tags << 'cve' if ids.any? { |id| id.start_with?('CVE-') }
    tags << 'ghsa' if ids.any? { |id| id.start_with?('GHSA-') }
    tags << 'cve_or_ghsa' if ids.any? { |id| id.start_with?('CVE-', 'GHSA-') }
    tags << 'origin_commit' if origin_commit
    tags << 'advisory_with_origin_commit' if ids.any? && origin_commit
    tags << 'advisory_with_upstream_commit_evidence' if ids.any? && (origin_commit || upstream_header_commit)
    tags << 'explicit_fix' if roles.value?('explicit_fix')
    tags << 'mapped' if occ.project_purl
    tags << 'versioned' if occ.purl && occ.project_purl != occ.purl
    tags.each do |tag|
      metrics[tag][:count] += 1
      metrics[tag][:hashes] << sha
    end
    per_source[release.package_name] += 1
    projects[occ.project_purl] << sha if occ.project_purl
    reuse[sha] << release.package_name
    occurrences_by_hash[sha] += 1
    output.puts({ distribution: 'debian', suite: 'trixie', source: release.package_name, version: release.version,
      patch: occ.name, sha256: sha, archive: release.metadata.fetch('debian_catalog').slice('archive_url', 'archive_sha256'),
      headers: occ.patch.headers, source_url: occ.source_url, udd: udd, declaration: occ.declaration.except('udd'), advisory_roles: roles, mapping: occ.mapping, purl: occ.purl,
      scope_evidence: occ.scope_evidence }.to_json)
  end
end
raise 'incomplete export' if expected.any? { |_, remaining| remaining.any? }
File.rename(path.to_s + '.part', path)
reused = reuse.select { |sha, names| sha != Patch::EMPTY_SHA256 && names.many? }
report = {
  catalog_sha256: Digest::SHA256.file(root.join('catalog.jsonl')).hexdigest, releases: expected.size,
  occurrences: catalog_count, distinct: reuse.size,
  reused_across_source_packages: reused.size, occurrences_of_reused_patches: reused.keys.sum { |sha| occurrences_by_hash.fetch(sha) },
  packages_with_reused_patches: reused.values.reduce(Set.new, :|).size,
  most_reused: reused.max_by(5) { |_, names| names.size }.map { |sha, names| { sha256: sha, packages: names.to_a.sort } },
  most_patches: per_source.sort_by { |name, n| [-n, name] }.first(10).to_h,
  upstream_projects: projects.size, most_mapped_patches: projects.transform_values(&:size).sort_by { |k, n| [-n, k] }.first(10).to_h,
  metrics: metrics.transform_values { |v| { occurrences: v[:count], distinct: v[:hashes].size } }
}
puts JSON.pretty_generate(report)
