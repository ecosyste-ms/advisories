require 'test_helper'

class RepositoryPurlLookupTest < ActionDispatch::IntegrationTest
  test 'repository lookup scopes shared patches to their release and distinguishes a partial Git comparison' do
    audit = { 'distribution' => 'debian', 'package' => 'rust-axum', 'version' => '1-13',
      'repository' => 'pkg:github/tokio-rs/axum', 'archive_sha256' => 'a' * 64, 'commit_checked' => 'c' * 40,
      'debian_original' => { 'name' => 'source.tar.gz', 'sha256' => 'd' * 64 } }
    audit['patches'] = [[], ['axum-extra/build.rs']].map.with_index do |missing, index|
      paths = ['src/lib.rs'] + missing
      { 'patch' => "#{index}.patch", 'sha256' => Digest::SHA256.hexdigest(index.to_s), 'changed_paths' => paths,
        'paths' => paths.size, 'identical' => 1, 'differing_or_absent' => missing, 'all_paths_corroborated' => missing.empty? }
    end
    Dir.mktmpdir do |dir|
      directory = Pathname(dir)
      directory.join('repository-test.json').write(JSON.generate(audit))
      PatchIndex::RepositoryComparison.stubs(:index).returns(PatchIndex::RepositoryComparison.load_index(directory))
    end
    repo = audit.fetch('repository')
    github = 'https://github.com/tokio-rs/axum'
    entries = [true, false].map do |full|
      member = audit.fetch('patches').find { |p| p['all_paths_corroborated'] == full }
      { name: member.fetch('patch'), sha256: member.fetch('sha256'), source_url: 'https://example.org/source',
        headers: {}, advisory_ids: [], declaration: {}, scope_evidence: { 'files' => member.fetch('changed_paths') } }
    end
    src = PatchIndex::SourceRepository.debian_sources({}, { 'debian/upstream/metadata' => "Repository: #{github}.git\n" })
    metadata = { 'source_repository' => PatchIndex::SourceRepository.declaration(src, archive_sha256: audit.fetch('archive_sha256')),
      'files' => [audit.fetch('debian_original')] }
    identity = { distribution: 'debian', package_name: audit.fetch('package'), version: audit.fetch('version'), revision: '13' }
    release = PatchRelease.record!(identity, source_url: github, metadata: metadata, component: {}, entries: entries)
    PatchRelease.record!(identity.merge(distribution: 'homebrew'), source_url: github, metadata: {}, component: {}, entries: entries)

    get api_v1_patches_path, params: { purl: 'pkg:github/Tokio-RS/Axum' }
    assert_response :success
    declarations = response.parsed_body.map { |p| p.fetch('occurrences').sole }
    assert_equal [release.distribution], declarations.map { |o| o.dig('downstream', 'distribution') }.uniq
    assert_equal %w[changed_file_match release_source_declaration], declarations.map { |o| o.dig('source_repository', 'kind') }.sort
    partial = declarations.find { |o| o.dig('source_repository', 'kind') == 'release_source_declaration' }
    assert_nil partial.fetch('purl')
    assert_equal audit.fetch('commit_checked'), partial.dig('source_repository', 'comparison', 'commit_checked')
    assert_equal ['axum-extra/build.rs'], partial.dig('source_repository', 'comparison', 'differing_or_absent')

    get patches_path, params: { purl: repo }
    assert_response :success
    assert_select 'tbody tr', count: 2
    assert_select 'tbody td:last-child', text: repo, count: 2
    assert_select 'tbody a[href=?]', patches_path(purl: repo), text: repo, count: 2
    get patch_path(entries.last.fetch(:sha256))
    assert_select 'a[href=?]', patches_path(purl: repo)
    assert_select '.patch-declaration', text: /1 of 2 changed paths matched/
    assert_select 'a[href=?]', "#{github}/commit/#{audit.fetch('commit_checked')}"

    get api_v1_patches_path, params: { purl: "#{repo}@#{audit.fetch('commit_checked')}" }
    assert_response :success
    assert_empty response.parsed_body
    get api_v1_patches_path, params: { purl: repo, distribution: 'homebrew' }
    assert_empty response.parsed_body
    get api_v1_patches_path, params: { purl: repo, version_range: '>= 1' }
    assert_response :bad_request

    release.update!(metadata: metadata.merge('files' => []))
    get api_v1_patches_path, params: { purl: repo }
    assert response.parsed_body.all? { |p| p.fetch('occurrences').sole.dig('source_repository', 'kind') == 'release_source_declaration' }
  end

  test 'Homebrew source archive enters repository lookup independently of registry package identity' do
    url = 'https://github.com/lloyd/yajl/archive/refs/tags/2.1.0.tar.gz'
    formula = { 'name' => 'yajl', 'tap' => 'homebrew/core', 'tap_git_head' => 'a' * 40, 'ruby_source_path' => 'Formula/y/yajl.rb',
      'versions' => { 'stable' => '2.1.0' }, 'revision' => 1, 'urls' => { 'stable' => { 'url' => url } }, 'variations' => {},
      'patches' => [{ 'url' => 'https://example.org/fix.patch', 'strip' => 'p1' }] }
    stub_request(:get, 'https://example.org/fix.patch').to_return(body: "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-a\n+b\n")
    importer = PatchIndex::Homebrew.new(PatchIndex::Http.new(cache: ActiveSupport::Cache::NullStore.new, interval: 0))
    importer.import('yajl', formula: formula)
    get api_v1_patches_path, params: { purl: 'pkg:github/lloyd/yajl' }
    occurrence = response.parsed_body.sole.fetch('occurrences').sole
    assert_equal 'release_source_declaration', occurrence.dig('source_repository', 'kind')
    assert_equal url, occurrence.dig('source_repository', 'sources').sole.fetch('url')
    assert_nil occurrence.fetch('project_purl')
    refute occurrence.fetch('source_repository').key?('comparison')

    formula['urls']['stable']['url'] = 'https://example.org/yajl.tar.gz'
    importer.import('yajl', formula: formula)
    get api_v1_patches_path, params: { purl: 'pkg:github/lloyd/yajl' }
    assert_empty response.parsed_body
  end
end
