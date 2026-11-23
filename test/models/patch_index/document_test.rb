require 'test_helper'

class PatchIndex::DocumentTest < ActiveSupport::TestCase
  test 'headers are read from the preamble and advisory references name the field they came from' do
    bytes = "Description: Fix overflow\n in parser\nOrigin: upstream, https://github.com/example/project/commit/abc\n" \
      "Bug: https://example.org/ghsa-2345-6789-cfgh\n\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-CVE-2020-0001\n+b\n"
    document = PatchIndex::Document.new(bytes)

    assert_equal "Fix overflow\nin parser", document.headers['Description']
    entry = document.entry(name: 'CVE-2024-0001.patch', position: 1, source_url: 'https://example.org/a',
      declaration: { 'changelog' => ['Mentions cve-2024-0003 in passing'] })
    assert_equal({ 'GHSA-2345-6789-cfgh' => ['header.Bug'], 'CVE-2024-0001' => ['name'], 'CVE-2024-0003' => ['changelog'] },
      entry.dig(:declaration, 'advisory_evidence'))
    assert_equal Digest::SHA256.hexdigest(bytes), entry[:sha256]
  end

  test 'a git commit patch supplies its commit and subject, and binary bytes do not break parsing' do
    document = PatchIndex::Document.new("From #{'a' * 40} Mon Sep 17 00:00:00 2001\nSubject: [PATCH] Fix \xFF thing\n\n---\n".b)
    assert_equal 'a' * 40, document.headers['commit']
    assert_equal "[PATCH] Fix � thing", document.headers['Subject']
  end

  test 'changelog bullets count only for the newest entry and when they name one patch' do
    text = "example (1-2) unstable; urgency=medium\n\n  * Add a.patch to fix CVE-2024-0001.\n  * Refresh a.patch and b.patch.\n" \
      "  * Drop ba.patch\n\n -- M <m@example.org>  Mon, 01 Jan 2024 00:00:00 +0000\n\nexample (1-1) unstable; urgency=medium\n\n  * Add b.patch\n"
    assert_equal({ 'a.patch' => ['Add a.patch to fix CVE-2024-0001.'] }, PatchIndex::Changelog.items(text, 'example', '1-2', %w[a.patch b.patch]))
    assert_empty PatchIndex::Changelog.items(text, 'example', '1-3', %w[a.patch])
  end

  test 'repository URLs normalise to one form and unsupported hosts or nested groups are ignored' do
    repository = PatchIndex::Repository
    assert_equal 'https://github.com/rack/rack', repository.normalize('git://github.com/Rack/rack.git')
    assert_equal 'https://github.com/curl/curl', repository.normalize('https://github.com/curl/curl/archive/refs/tags/v1.tar.gz')
    assert_equal 'https://gitlab.com/group/project', repository.normalize('https://gitlab.com/group/project/-/tree/main')
    assert_nil repository.normalize('https://gitlab.com/group/sub/project')
    assert_nil repository.normalize('https://rack.github.io/')
    assert_equal ['debian/copyright:Source', 'https://github.com/example/project'],
      repository.debian('https://example.org', 'debian/upstream/metadata' => "Repository: https://example.org/git\n",
        'debian/copyright' => "Format: x\nSource: https://github.com/example/project\n\nFiles: *\nSource: https://github.com/other/thing\n")
    assert_equal '2.3.4', PatchIndex::Apt.upstream_version('1:2.3.4+dfsg1-2ubuntu1')
  end

  test 'a redirect to plain HTTP is refused' do
    stub_request(:get, 'https://example.org/a').to_return(status: 302, headers: { 'Location' => 'http://example.org/a' })
    assert_raises(PatchIndex::Http::Error) { PatchIndex::Http.new(interval: 0).get('https://example.org/a') }
    assert_raises(PatchIndex::Http::Error) { PatchIndex::Http.new(interval: 0).get('http://example.org/a') }
  end
end
