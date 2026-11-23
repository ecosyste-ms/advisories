require 'test_helper'

class PatchesControllerTest < ActionDispatch::IntegrationTest
  include ActionView::RecordIdentifier
  setup do
    @contents = "Subject: Fix <b>overflow</b>\n\n--- a/lib/x.rb\n+++ b/lib/x.rb\n@@ -1 +1 @@\n-<script>\n+safe\n"
    @patch = create(:patch, contents: @contents, headers: { 'Subject' => 'Fix <b>overflow</b>' })
    @debian = create(:patch_release, distribution: 'debian', package_name: 'rust-h2', version: '0.4.4-1', upstream_version: '0.4.4',
      repository_url: 'https://github.com/hyperium/h2', metadata: { 'repository_field' => 'debian/upstream/metadata:Repository' })
    @ubuntu = create(:patch_release, distribution: 'ubuntu', package_name: 'rust-h2', version: '0.4.4-1ubuntu1', upstream_version: '0.4.4',
      repository_url: 'https://github.com/hyperium/h2')
    @fix = create(:patch_occurrence, patch: @patch, patch_release: @debian, name: 'CVE-2024-27308.patch', advisory_ids: ['CVE-2024-27308'],
      declaration: { 'advisory_evidence' => { 'CVE-2024-27308' => ['name'] }, 'changelog' => ['Add CVE-2024-27308.patch to fix CVE-2024-27308.'] })
    create(:patch_occurrence, patch: @patch, patch_release: @ubuntu, name: 'overflow.patch')
    @other = create(:patch_occurrence, patch: create(:patch, contents: 'x' * 5000), name: 'unrelated.patch')
    @advisory = create(:advisory, uuid: 'GHSA-8r5v-vm4m-4g25', identifiers: %w[GHSA-8r5v-vm4m-4g25 CVE-2024-27308])
  end

  def listed
    css_select('tbody th a').map { |link| link['href'] }
  end

  test 'identical bytes appear once with every distribution that declares them' do
    get patches_path
    assert_response :success
    assert_equal [patch_path(@other.patch), patch_path(@patch)], listed
    assert_select 'tbody tr:last-child td', text: /Debian \/ rust-h2\s+Ubuntu \/ rust-h2/
    assert_select "a[href='#{patches_path(repository_url: 'https://github.com/hyperium/h2')}']"

    get patches_path(sort: 'smallest')
    assert_equal [patch_path(@patch), patch_path(@other.patch)], listed
    get patches_path(distribution: 'ubuntu')
    assert_equal [patch_path(@patch)], listed
  end

  test 'a registry package PURL finds patches through its repository and its version through the upstream version' do
    create(:package, ecosystem: 'cargo', name: 'h2', repository_url: 'https://github.com/Hyperium/h2')
    create(:patch_occurrence, patch_release: create(:patch_release, distribution: 'homebrew',
      repository_url: 'https://github.com/hyperium/h2', upstream_version: '0.3.0'))

    get patches_path(purl: 'pkg:cargo/h2@0.4.4')
    assert_equal [patch_path(@patch)], listed
    get patches_path(purl: 'pkg:cargo/h2')
    assert_equal 2, listed.size
    get patches_path(purl: 'pkg:github/hyperium/h2', distribution: 'debian')
    assert_equal [patch_path(@patch)], listed
    get patches_path(purl: 'pkg:deb/debian/rust-h2@0.4.4-1')
    assert_equal [patch_path(@patch)], listed
    get patches_path(repository_url: 'https://github.com/hyperium/h2.git', purl: 'pkg:deb/ubuntu/rust-h2')
    assert_equal [patch_path(@patch)], listed

    get patches_path(purl: 'pkg:cargo/unknown')
    assert_select 'p', text: /No matching patches/
    get patches_path(purl: 'not a purl')
    assert_response :bad_request
  end

  test 'an advisory filter matches any of the advisory identifiers' do
    get patches_path(advisory: 'ghsa-8r5v-vm4m-4g25')
    assert_equal [patch_path(@patch)], listed
    get patches_path(advisory: 'CVE-2024-27308', distribution: 'ubuntu')
    assert_empty listed
    get patches_path(advisory: 'CVE-1999-0001')
    assert_empty listed
  end

  test 'the patch page escapes the diff, links each release and says how an advisory is referenced' do
    get patch_path(@patch)
    assert_response :success
    assert_select 'h1', text: 'Fix <b>overflow</b>'
    assert_select 'pre.patch-diff-preview .text-danger', text: '-<script>'
    assert_select 'pre script', count: 0
    assert_select "##{dom_id(@fix)} a[href='#{advisory_path(@advisory.uuid)}']", text: 'CVE-2024-27308'
    assert_select "##{dom_id(@fix)}", text: /Identified as a fix/
    assert_select "##{dom_id(@fix)}", text: /debian\/upstream\/metadata:Repository/
    assert_select "a[href='#{ecosystem_package_path('ubuntu', 'rust-h2', tab: 'patches')}']"
    assert_select "a[href='https://github.com/hyperium/h2']"

    get download_patch_path(@patch)
    assert_equal @contents.b, response.body.b
    assert_match(/attachment; filename="#{@patch.sha256}\.patch"/, response.headers['Content-Disposition'])
  end

  test 'a long patch is previewed in part and a patch nobody declares is hidden' do
    long = create(:patch_occurrence, patch: create(:patch, contents: "--- a\n+++ b\n" + ("+line\n" * 600))).patch
    get patch_path(long)
    assert_select 'p', text: /Preview truncated/

    orphan = create(:patch)
    get patch_path(orphan)
    assert_response :not_found
    get download_patch_path(orphan)
    assert_response :not_found
  end

  test 'package pages list patches for a distro package by name and for a registry package by repository' do
    create(:package, ecosystem: 'cargo', name: 'h2', repository_url: 'https://github.com/hyperium/h2')

    get ecosystem_package_path('debian', 'rust-h2', tab: 'patches')
    assert_response :success
    assert_select "#downstream-patches a[href='#{patch_path(@patch)}']", count: 1
    assert_select '#downstream-patches', text: /Declared by Debian \/ rust-h2 0\.4\.4-1/
    assert_select '#downstream-patches', text: /Ubuntu/, count: 0

    get ecosystem_package_path('cargo', 'h2', tab: 'patches')
    assert_select '#downstream-patches li', count: 1
    assert_select '#downstream-patches', text: /Ubuntu \/ rust-h2 0\.4\.4-1ubuntu1/
    get ecosystem_package_path('cargo', 'h2', tab: 'patches', version: '9.9.9')
    assert_select '#downstream-patches', text: /No matching patches found/

    get ecosystem_package_path('cargo', 'h2')
    assert_select "a.nav-link[href='#{ecosystem_package_path('cargo', 'h2', tab: 'patches')}']", text: 'Patches'
    assert_select '#downstream-patches', count: 0
  end

  test 'the advisory page lists the patches that name it' do
    get advisory_path(@advisory.uuid)
    assert_response :success
    assert_select '#downstream-patches + p + div tbody tr', count: 1
    assert_select "a[href='#{patch_path(@patch, anchor: dom_id(@fix))}']", text: 'CVE-2024-27308.patch'
    assert_select 'td', text: 'Debian / rust-h2 0.4.4-1'
    assert_select 'td', text: 'Identified as a fix'

    get advisory_path(create(:advisory).uuid)
    assert_select '#downstream-patches', count: 0
  end
end
