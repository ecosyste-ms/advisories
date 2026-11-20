require 'test_helper'

class PatchIndex::DebianCatalogTest < ActiveSupport::TestCase
  test 'catalog imports verify bytes and preserve independent enrichment in either import order' do
    bytes = "Description: Link options\n--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-a\n+b\n"
    sha = Digest::SHA256.hexdigest(bytes)
    name = 'flags.patch'
    archive = 'a' * 64
    udd = { 'patch' => name, 'upstream_status' => 'merged', 'upstream_bug' => 'CVE-2099-5678' }
    row = { 'source' => 'rust-alias', 'version' => '1-1', 'sha256' => archive, 'patches' => [udd] }
    members = { 'archive_sha256' => archive, 'changelog' => '', 'members' => { name => { 'sha256' => sha, 'series' => [1, []] } } }
    Dir.mktmpdir do |dir|
      root = Pathname.new(dir)
      root.join(sha.first(2)).mkpath
      file = root.join(sha.first(2), sha)
      file.binwrite(bytes)
      importer = PatchIndex::DebianCatalog.new(root)
      url = 'https://example.org/packaging.tar.xz'
      2.times { importer.import(row, members, archive_url: url) }
      assert_equal bytes, PatchBody.sole.contents
      PatchBody.sole.delete
      importer.import(row, members, archive_url: url)
      assert_equal bytes, PatchBody.sole.contents
      occurrence = PatchOccurrence.sole
      assert_nil occurrence.purl
      assert_equal ['udd.upstream_bug'], occurrence.declaration.dig('advisory_evidence', 'CVE-2099-5678')
      entry = PatchIndex::Document.new(bytes, strip: 1).entry(name: name, source_url: 'https://example.org/flags.patch', declaration: {})
      identity = { distribution: 'debian', package_name: 'rust-alias', version: '1-1', revision: '1' }
      component = { 'identity' => { 'ecosystem' => 'cargo', 'name' => 'canonical', 'version' => '1.0' } }
      release = PatchRelease.record!(identity, source_url: url, metadata: { 'files' => [] }, component: component, entries: [entry])
      assert_equal archive, release.metadata.dig('debian_catalog', 'archive_sha256')
      assert_equal 'pkg:cargo/canonical@1.0', occurrence.reload.purl
      assert_equal udd, occurrence.declaration['udd']
      assert_equal ['CVE-2099-5678'], occurrence.advisory_ids
      row['patches'] = [udd.except('upstream_bug')]
      importer.import(row, members, archive_url: url)
      assert_empty occurrence.reload.advisory_ids
      assert_equal 'pkg:cargo/canonical@1.0', occurrence.purl
      file.binwrite('corrupted')
      row['patches'] = [udd]
      assert_raises(IOError) { importer.import(row, members, archive_url: url) }
      assert_empty occurrence.reload.advisory_ids
    end
  end
end
