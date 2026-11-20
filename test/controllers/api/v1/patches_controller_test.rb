require 'test_helper'

class Api::V1::PatchesControllerTest < ActionDispatch::IntegrationTest
  setup do
    @bytes = "Description: sample\n continuation\nAuthor: Maintainer\n--- a/lib.rb\n+++ b/lib.rb\n@@ -1 +1 @@\n-a\n+b\n"
    @id = 'CVE-2099-1234'
    @package = { 'ecosystem' => 'rubygems', 'package_name' => 'some_gem', 'versions' => [{ 'vulnerable_version_range' => '>= 1.0, < 1.5' }] }
    @release = record('debian', '1.2.0', @id)
    record('debian', '1.6.0', @id)
    record('homebrew', '1.4.0', 'CVE-2099-9999')
    record('debian', nil, @id)
    @advisory = create(:advisory, identifiers: [@id, 'GHSA-f8vr-r385-rh5r'], packages: [@package])
  end

  def record(distribution, version, id, bytes = @bytes)
    source = { 'manifest' => 'project.gemspec', 'url' => 'https://example.org/spec', 'body' => "s.name = 'some_gem'.freeze\ns.version = '#{version}'\n" }
    source['body'] = "s.name = 'some_gem'\ns.version = dynamic_version\n" unless version
    doc = PatchIndex::Document.new(bytes, strip: 1)
    entry = doc.entry(name: "#{id}.patch", source_url: 'https://example.org/fix', declaration: {})
    PatchRelease.record!({ distribution: distribution, package_name: 'renamed', version: version || 'unknown', revision: '1' },
      source_url: 'https://example.org/release', metadata: {}, component: source, entries: [entry])
  end

  test 'range combined with distribution and advisory returns only matching declarations' do
    get api_v1_patches_url, params: { distribution: 'Debian', purl: 'pkg:gem/some_gem', version_range: '>= 1.0, < 1.5', advisory: @id.downcase }
    assert_response :success
    patch = response.parsed_body.sole
    occurrence = patch.fetch('occurrences').sole
    assert_equal 'pkg:gem/some_gem@1.2.0', occurrence['purl']
    assert_equal 'declared', occurrence['status']
    assert_equal({ @id => 'patch_name' }, occurrence['advisory_roles'])
    assertions = occurrence.fetch('assertions')
    assert_equal @release.source_url, assertions.dig('declared', 'source_url')
    assert_equal({ 'kind' => 'advisory_reference', 'identifier' => @id, 'fields' => ['name'] }, assertions['attributed'].sole)
    assert_nil assertions.fetch('verified')
    assert_equal "sample\ncontinuation", patch.dig('headers', 'Description')
    linked = patch.fetch('referenced_advisories').sole
    assert_equal @advisory.uuid, linked['uuid']
    assert_equal [@package], linked['affected_packages']
    get api_v1_patches_url, params: { advisory: 'GHSA-f8vr-r385-rh5r', purl: 'pkg:gem/some_gem@1.2.0' }
    assert_equal patch['id'], response.parsed_body.sole['id']
    get api_v1_patch_url(patch['id'])
    assert_equal 4, response.parsed_body['occurrences'].size
    get api_v1_patches_url, params: { distribution: 'Homebrew', advisory: @id }
    assert_empty response.parsed_body
    get api_v1_patches_url, params: { purl: 'pkg:gem/some_gem@1.3.0', advisory: @id }
    assert_empty response.parsed_body
  end

  test 'pagination keeps patch identity and invalid filters return a client error' do
    record('debian', '2.0.0', @id, @bytes + "\n")
    get api_v1_patches_url, params: { per_page: 1, page: 1 }
    first = response.parsed_body.sole.fetch('id')
    get api_v1_patches_url, params: { per_page: 1, page: 2 }
    refute_equal first, response.parsed_body.sole.fetch('id')
    get api_v1_patches_url, params: { version_range: '< 1.3' }
    assert_response :bad_request
    get api_v1_patches_url, params: { purl: 'nonsense' }
    assert_response :bad_request
  end

  test 'links lead from a filtered result to the full patch, declaration, packages, advisory and bytes' do
    get api_v1_patches_url, params: { purl: 'pkg:gem/some_gem@1.2.0' }
    patch = response.parsed_body.sole
    occurrence = patch.fetch('occurrences').sole
    get patch.fetch('api_url')
    assert_response :success
    assert_equal 4, response.parsed_body.fetch('occurrences').size
    assert_equal patch.fetch('html_url'), response.parsed_body.fetch('html_url')

    page = URI.parse(occurrence.fetch('html_url'))
    anchor = page.fragment
    page.fragment = nil
    assert_equal patch.fetch('html_url'), page.to_s
    get page.to_s
    assert_response :success
    assert_select "section##{anchor}.patch-declaration h3", text: /renamed.*1\.2\.0/m

    get occurrence.fetch('upstream_package_url')
    assert_response :success
    get css_select('.nav-tabs a').find { |a| a.text == 'Patches' }['href']
    assert_select '#downstream-patches a[href=?]', page.path
    get occurrence.fetch('downstream').fetch('package_url')
    assert_response :success
    get css_select('.nav-tabs a').find { |a| a.text == 'Patches' }['href']
    assert_select '#downstream-patches a[href=?]', page.path
    get patch.fetch('referenced_advisories').sole.fetch('html_url')
    assert_response :success

    get patch.fetch('download_url')
    assert_response :success
    assert_equal @bytes, response.body
    PatchBody.find(patch.fetch('sha256')).delete
    get patch.fetch('api_url')
    refute response.parsed_body.key?('download_url')
  end

  test 'resolve uses stored manifest without a fetch' do
    occurrence = @release.patch_occurrences.sole
    source = @release.component.merge('body' => "s.name = 'canonical'\ns.version = '1.2.0'")
    @release.update!(component: source)
    occurrence.resolve!
    assert_equal 'pkg:gem/canonical@1.2.0', occurrence.reload.purl
  end
end
