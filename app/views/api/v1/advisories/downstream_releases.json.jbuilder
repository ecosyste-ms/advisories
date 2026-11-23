json.array! @releases do |release|
  json.partial! 'api/v1/patches/release', release: release
  json.affected @advisory.affects_release?(release)
  json.patches_count @patch_counts.fetch(release.id, 0)
end
