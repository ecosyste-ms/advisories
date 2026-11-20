require_relative 'catalog_files'
require 'open3'

report, name, checkout, commit, source_manifest = ARGV
abort 'supply a Debian source manifest (JSONL)' unless source_manifest
abort 'expected a full commit SHA' unless commit&.match?(/\A[0-9a-f]{40}\z/)
release = File.foreach(report).lazy.map { |line| JSON.parse(line) }.find { |r| r['package'] == name }
origin, ok = Open3.capture2('git', '-C', checkout, 'remote', 'get-url', 'origin')
repository = PatchIndex::SourceRepository.github_purl(origin.strip.sub(/\Agit@github\.com:/, 'https://github.com/'))
abort 'repository differs from Debian evidence' unless ok.success? && repository && release.fetch('repository_candidates') == [repository]
tree, ok = Open3.capture2('git', '-C', checkout, 'ls-tree', '-rz', "#{commit}^{commit}")
abort 'unable to read upstream commit' unless ok.success?
blobs = tree.split("\0").filter_map do |entry|
  info, path = entry.split("\t", 2)
  mode, type, oid = info.split
  [path, oid] if type == 'blob' && %w[100644 100755].include?(mode)
end.to_h
sources = File.foreach(source_manifest).lazy.map { |line| JSON.parse(line) }
row = sources.find { |r| r.values_at('name', 'version') == release.values_at('package', 'version') }
orig = row.fetch('files').select { |f| f['name'].include?('.orig.tar.') }.sole
sha = orig.fetch('sha256')
files = CatalogFiles.archive_members(CatalogFiles.path('sha256' => sha), sha)
roots = files.keys.map { |path| path.split('/').first }.uniq
if roots.one? && files.keys.all? { |path| path.include?('/') }
  files = files.transform_keys { |path| path.split('/', 2).last }
end
patches = release.fetch('patches').map do |patch|
  paths = patch.fetch('paths')
  matches = paths.select do |path|
    bytes = files[path]
    bytes && Digest::SHA1.hexdigest("blob #{bytes.bytesize}\0".b + bytes) == blobs[path]
  end
  supported = [nil, 'path missing or nested'].include?(patch['scope_reason']) && paths.any? &&
    paths.none? { |path| path.match?(PatchIndex::Component::BOUNDARY) } && matches.size == paths.size
  { patch: patch.fetch('patch'), sha256: patch.fetch('sha256'), changed_paths: paths, paths: paths.size, identical: matches.size,
    differing_or_absent: paths - matches, all_paths_corroborated: supported }
end
puts JSON.pretty_generate(distribution: 'debian', package: name, version: release.fetch('version'),
  archive_sha256: release.fetch('archive').fetch('sha256'), repository: repository, commit_checked: commit, debian_original: orig, patches: patches)
