require 'test_helper'
require_relative '../../script/patch_index/patch_similarity'

class PatchesControllerTest < ActionDispatch::IntegrationTest
  def declare(distribution, names, bytes, package_name: 'yajl', component: {}, version: '2.1.0')
    identity = { distribution: distribution, package_name: package_name, version: version, revision: '1' }
    source = "https://example.org/#{distribution}/#{package_name}"
    entries = Array(names).map do |name|
      PatchIndex::Document.new(bytes, strip: 1).entry(name: name, source_url: "#{source}/#{name}", declaration: {})
    end
    PatchRelease.record!(identity, source_url: source, metadata: {}, component: component, entries: entries)
  end

  test 'a shared diff is escaped for display and downloads with its original bytes' do
    bytes = "Description: Sample\0patch\n--- a/build\n+++ b/build\n@@ -1 +1 @@\n-old\n+<script>hi</script>\xff\0\r\n".b
    declare('debian', 'build.patch', bytes)
    declare('homebrew', 'build.diff', bytes)
    digest = Digest::SHA256.hexdigest(bytes)
    assert_equal bytes, PatchBody.sole.contents

    get patch_path(digest)
    assert_response :success
    assert_select '#patch-diff details:not([open]) code', text: "Description: Sample�patch"
    assert_match(/\A--- a\/build/, css_select('#patch-diff > pre code').sole.text)
    assert_select '#patch-diff code .text-success', text: /<script>hi<\/script>��/
    assert_select '#patch-diff script', count: 0
    assert_select '#patch-diff a[href=?]', download_patch_path(digest)
    get download_patch_path(digest)
    assert_response :success
    assert_equal 'application/octet-stream', response.media_type
    assert_match(/attachment/, response.headers['Content-Disposition'])
    assert_equal bytes, response.body.b
  end

  test 'empty patch files keep each declaration and download under one digest' do
    declare('debian', %w[debian-changes empty.patch], '')
    declare('homebrew', 'empty.diff', '')
    declare('ubuntu', 'newline.patch', "\n")
    digest = Digest::SHA256.hexdigest('')

    get patches_path
    assert_select 'tbody th a[href=?]', patch_path(digest), text: 'Empty patch file', count: 1
    assert_select 'tbody th a', text: 'newline.patch'
    get patch_path(digest)
    assert_response :success
    assert_select 'h1', 'Empty patch file'
    assert_select 'p', 'Observed in 2 downstream releases'
    %w[debian-changes empty.patch empty.diff].each do |name|
      assert_select '.patch-declaration a', text: name
    end
    assert_select '#patch-diff pre', count: 0
    assert_select '#patch-diff a[href=?]', download_patch_path(digest)
    get download_patch_path(digest)
    assert_response :success
    assert_equal '', response.body
  end

  test 'preview limits both long lines and many short lines while the download remains complete' do
    ["x" * (PatchBody::PREVIEW_BYTES + 1), "x\n" * (PatchBody::PREVIEW_LINES + 1)].each do |prefix|
      bytes = prefix + 'omitted-tail'
      digest = Digest::SHA256.hexdigest(bytes)
      declare('debian', 'large.patch', bytes)
      get patch_path(digest)
      assert_response :success
      assert_select '#patch-diff p', text: /Preview truncated/
      refute_includes css_select('#patch-diff pre').first.text, 'omitted-tail'
      get download_patch_path(digest)
      assert_equal bytes, response.body
    end
  end

  test 'older records without stored bodies still show their declarations' do
    release = declare('debian', 'old.patch', 'sample')
    patch = release.patch_occurrences.sole.patch
    patch.patch_body.delete
    get patch_path(patch.sha256)
    assert_response :success
    assert_select '#patch-diff p', text: /haven’t been imported/
    assert_select '#patch-diff a', count: 0
    get download_patch_path(patch.sha256)
    assert_response :not_found
  end

  test 'different Rack patch digests link in both directions with downstream release evidence' do
    patches = %w[debian ubuntu].map do |distribution|
      bytes = file_fixture("patch_index/rack/#{distribution}.patch").binread
      release = declare(distribution, 'skip-unreadable-dir-test.patch', bytes, package_name: 'ruby-rack')
      release.patch_occurrences.sole.patch
    end
    Dir.mktmpdir do |dir|
      output = Pathname(dir).join('pairs.gz')
      assert_empty PatchIndex::Similarity.load_index(output)
      patches.each { |patch| File.binwrite(File.join(dir, patch.sha256), patch.patch_body.contents) }
      PatchSimilarity.generate([dir], output)
      PatchIndex::Similarity.stubs(:index).returns(PatchIndex::Similarity.load_index(output))
    end
    patches.permutation.each do |patch, other|
      get patch_path(patch.sha256)
      assert_response :success
      assert_select '#similar-patches a[href=?]', patch_path(other.sha256), count: 1
      assert_select '#similar-patches', text: /Same hunks and context/
      assert_select '#similar-patches .small', text: /ruby-rack/
      get css_select('#similar-patches a').find { |a| a.text == 'Compare' }['href']
      assert_response :success
      ubuntu_lines = patch == patches.first ? '.addition' : '.removal'
      assert_select ".patch-comparison #{ubuntu_lines}", text: /Index: ruby-rack/
      assert_select '.patch-comparison .annotation', text: /@@/
      assert_select '#comparison-key, [aria-describedby="comparison-key"]', count: 0
      assert_select '.patch-comparison .addition, .patch-comparison .removal', text: /\+    skip/, count: 0
    end
    get ecosystem_package_path('ubuntu', 'ruby-rack', tab: 'patches')
    assert_response :success
    assert_select '#downstream-patches a[href=?]', patch_path(patches.last.sha256)
  end

  test 'comparison uses complete bodies and keeps diff markers separate from literal patch text' do
    prefix = "context\n" * (PatchBody::PREVIEW_LINES + 1)
    left = declare('debian', 'one.diff', prefix + "+old\n").patch_occurrences.sole.patch
    right = declare('ubuntu', 'two.diff', prefix.b + "+<script>x</script>\xff\r\n".b).patch_occurrences.sole.patch
    path = compare_patch_path(left.sha256, right.sha256)
    get path
    assert_response :not_found
    PatchIndex::Similarity.stubs(:index).returns({ left.sha256 => { right.sha256 => { 'jaccard' => [6, 7] } } })
    get path
    assert_response :success
    assert_select '.patch-comparison .removal', text: '-+old'
    assert_select '.patch-comparison .addition', text: '++<script>x</script>\\xFF\\x0D'
    assert_select '.patch-comparison script', count: 0
    right.patch_body.delete
    get path
    assert_response :success
    assert_select 'p', text: /yet to be imported/
    assert_select '.patch-comparison', count: 0
  end

  test 'source filter lists shared patches once with source-specific filenames and packages' do
    declare('debian', 'debian.patch', 'shared')
    declare('Homebrew', %w[brew.patch alias.patch], 'shared', package_name: 'brew-package')
    declare('debian', 'debian-only.patch', 'other')
    get patches_path, params: { distribution: 'Homebrew' }
    assert_response :success
    assert_select 'form[method=get] select[name=distribution] option[selected][value=homebrew]'
    assert_select 'tbody tr', count: 1
    assert_select 'tbody th a', text: 'brew.patch'
    assert_select 'tbody td', text: /Homebrew \/ brew-package/
    assert_select 'tbody td', text: /Debian/, count: 0

    get patches_path, params: { distribution: '' }
    assert_select 'tbody tr', count: 2
    get patches_path, params: { distribution: 'unknown' }
    assert_select 'tbody tr', count: 0
    assert_select 'a[href=?]', patches_path, text: 'Show all sources'
  end

  test 'pagination retains the source and sort and the filter form starts on page one' do
    26.times { |i| declare('ubuntu', 'changes.patch', "change #{i}", version: i.to_s) }
    get patches_path, params: { distribution: 'ubuntu', sort: 'smallest' }
    assert_select 'tbody tr', count: 25
    next_page = css_select('nav[aria-label="Pages"] a[aria-label="Next"]').first
    assert next_page
    get next_page['href']
    assert_response :success
    assert_select 'tbody tr', count: 1
    assert_select 'option[selected][value=ubuntu]'
    assert_select 'option[selected][value=smallest]'
    assert_select 'form[action=?] input[name=page]', patches_path, count: 0
  end

  test 'index sorts within a source by index order or exact size, with unknown sizes last' do
    declare('debian', 'first', 'ab', version: '1')
    declare('debian', 'large', 'xyz', version: '2')
    declare('debian', 'tie', 'cd', version: '3')
    missing = declare('debian', 'missing', 'absent', version: '4')
    missing.patch_occurrences.sole.patch.patch_body.delete
    declare('ubuntu', 'other', 'elsewhere')

    {
      'newest' => %w[missing tie large first],
      'oldest' => %w[first large tie missing],
      'largest' => %w[large tie first missing],
      'smallest' => %w[tie first large missing],
      'invalid' => %w[missing tie large first]
    }.each do |sort, expected|
      get patches_path, params: { distribution: 'debian', sort: sort }
      assert_response :success
      assert_equal expected, css_select('tbody th a').map(&:text)
      assert_select 'select[name=sort] option[selected][value=?]', sort == 'invalid' ? 'newest' : sort
    end
  end

  test 'index shows original sizes in decimal kilobytes and distinguishes missing bodies' do
    declare('debian', 'unicode.patch', 'é' * 625)
    release = declare('ubuntu', 'missing.patch', 'missing')
    release.patch_occurrences.sole.patch.patch_body.delete
    get patches_path
    assert_response :success
    assert_select 'th', text: 'Size (KB)'
    assert_select 'tbody tr', text: /unicode.patch.*1\.25/m
    assert_select 'tbody tr', text: /missing.patch.*Unknown/m
  end

  test 'index links to one digest page for identical bytes across downstream sources' do
    bytes = "Subject: Fix linking\nDescription: References CVE-2099-1234\n--- a/build\n+++ b/build\n@@ -1 +1 @@\n-old\n+new\n"
    declare('debian', 'fix-linking.patch', bytes)
    declare('homebrew', 'link.diff', bytes)
    digest = Digest::SHA256.hexdigest(bytes)
    advisory = create(:advisory, identifiers: ['CVE-2099-1234'])

    get patches_path
    assert_response :success
    assert_select 'nav a[href=?]', patches_path, text: 'Patches'
    assert_select 'tbody tr', count: 1
    assert_select "tbody a[href='/patches/#{digest}']", text: 'Fix linking', count: 1
    get patch_path(digest)
    assert_response :success
    assert_select 'code', text: digest
    assert_select 'p', text: 'Observed in 2 downstream releases'
    assert_select 'section.patch-declaration', count: 2
    assert_select 'section p', text: /Upstream mapping unresolved/, count: 2
    assert_select 'section a[href="https://example.org/debian/yajl/fix-linking.patch"]', text: 'fix-linking.patch'
    assert_select 'section a[href="https://example.org/homebrew/yajl/link.diff"]', text: 'link.diff'
    assert_select "a[href='#{advisory_path(advisory)}']", text: 'CVE-2099-1234'
    assert_select '.patch-declaration li', text: /CVE-2099-1234\s+Contextual mention/
    assert_select '.patch-declaration details:not([open]) p', text: /CVE-2099-1234 · header.Description/
    assert_select "a[href='#{api_v1_patch_path(Patch.find_by!(sha256: digest).id)}']", text: 'JSON'
  end

  test 'counts a release once when it declares identical patch bytes under two names' do
    bytes = "--- a/build\n+++ b/build\n@@ -1 +1 @@\n-old\n+new\n"
    declare('debian', %w[build.patch build-alias.patch], bytes)

    get patch_path(Digest::SHA256.hexdigest(bytes))
    assert_response :success
    assert_select 'p', text: 'Observed in 1 downstream release'
    assert_select 'section.patch-declaration', count: 1
    assert_select '.patch-declaration h3', count: 1
    assert_select '.patch-declaration details:not([open]) summary', text: 'build.patch'
    assert_select '.patch-declaration details:not([open]) summary', text: 'build-alias.patch'
    PatchOccurrence.find_each do |occurrence|
      assert_select "#patch_occurrence_#{occurrence.id}", count: 1
    end
  end

  test 'downstream package links work before sync and keep release provenance separate' do
    debian = declare('debian', 'fix.patch', 'shared bytes')
    brew = declare('homebrew', 'brew.patch', 'shared bytes')
    create(:registry, ecosystem: 'homebrew', name: 'formulae.brew.sh')
    package = create(:package, ecosystem: 'homebrew', name: 'yajl', last_synced_at: Time.current)
    patch = debian.patch_occurrences.sole.patch

    get patch_path(patch.sha256)
    assert_response :success
    [debian, brew].each do |release|
      assert_select '.patch-declaration h3 a[href=?]', ecosystem_package_path(release.distribution, 'yajl', tab: 'patches'), text: 'yajl'
      assert_select '.patch-declaration details a[href=?]', release.source_url, text: 'Release source'
    end
    assert_select '.patch-declaration a', text: 'Packages.ecosyste.ms', count: 1
    assert_select '.patch-declaration details a[href=?]', package.packages_url, text: 'Packages.ecosyste.ms'
    get css_select('.patch-declaration h3 a').find { |a| a['href'] == ecosystem_package_path('debian', 'yajl', tab: 'patches') }['href']
    assert_response :success
    assert_select '#downstream-patches a[href=?]', patch_path(patch.sha256)
  end

  test 'explains an unrecognized archive without inferring the package language' do
    bytes = "--- a/build\n+++ b/build\n@@ -1 +1 @@\n-old\n+new\n"
    declare('homebrew', 'build.patch', bytes, package_name: 'gdb',
      component: { 'reason' => 'no supported language registry archive' })

    get patch_path(Digest::SHA256.hexdigest(bytes))
    assert_response :success
    assert_select 'section p', text: 'The source archive URL does not identify a package in a supported registry.'
  end

  test 'only declared patches are visible' do
    digest = Digest::SHA256.hexdigest('old')
    Patch.create!(sha256: digest)
    get patches_path
    assert_response :success
    assert_select 'p', text: 'No patches have been indexed.'
    get patch_path(digest)
    assert_response :not_found
    get patch_path('0' * 64)
    assert_response :not_found
  end

  test 'compares the exact digest in observed Debian version order' do
    declare('debian', 'fix.patch', 'new', version: '1-10')
    declare('debian', 'fix.patch', 'different bytes', version: '1-2')
    get patch_path(Digest::SHA256.hexdigest('new'))
    rows = css_select('details#release-history:not([open]) li').map { |li| li.text.squish }
    assert_equal ['1-2 Absent from this release’s series', '1-10 First observed declaration'], rows
  end

  test 'follows the h2 crate to the declared patch, maintainer attribution and local advisory' do
    example = JSON.parse(Rails.root.join('test/fixtures/files/patch_index/patch-h2.json').read)
    occurrence = example.fetch('occurrence')
    advisory = create(:advisory, identifiers: occurrence.fetch('advisory_ids'))
    create(:package, ecosystem: 'cargo', name: 'h2')
    release = occurrence.fetch('downstream')
    mapping = occurrence.fetch('mapping')
    entry = occurrence.slice('name', 'source_url', 'declaration', 'scope_evidence', 'advisory_ids').symbolize_keys
    entry.merge!(headers: example.fetch('headers'), sha256: example.fetch('sha256'))
    PatchRelease.record!(release.slice('distribution', 'package_name', 'version', 'revision'), source_url: release.fetch('source_url'),
      metadata: {}, component: mapping.slice('method', 'evidence').merge('identity' => mapping.fetch('candidate')), entries: [entry])
    get ecosystem_package_path('cargo', 'h2'), params: { version: '0.3.13' }
    get css_select('.nav-tabs a').find { |a| a.text == 'Patches' }['href']
    get css_select('#downstream-patches a').first['href']
    assert_response :success
    assert_select 'a[href=?]', ecosystem_package_path('cargo', 'h2', tab: 'patches'), text: 'pkg:cargo/h2@0.3.13'
    assert_select 'a[href=?]', mapping.dig('evidence', 'registry_release', 'versions_url'), text: '0.3.13'
    assert_select 'blockquote', text: /cherry picked from\s+upstream to fix/
    assert_select 'a[href=?]', occurrence.dig('declaration', 'changelog', 'url'), text: 'Changelog'
    assert_select 'li', text: /RUSTSEC-2023-0034.*Identified as a fix/m
    assert_select 'a[href=?]', advisory_path(advisory), text: 'CVE-2023-26964'
    get css_select("a[href='#{advisory_path(advisory)}']").first['href']
    assert_response :success
  end

  test 'package tabs preserve filters and paginate distinct patches independently' do
    package = ecosystem_package_path('debian', 'yajl')
    declare('debian', %w[first.patch alias.patch], 'first', version: '1.0')
    declare('debian', 'second.patch', 'second', version: '1.1')
    get package, params: { severity: 'high', per_page: 1, page: 2 }
    assert_select '.nav-tabs a[aria-current=page]', text: 'Advisories'
    assert_select '#downstream-patches', count: 0

    get css_select('.nav-tabs a').find { |a| a.text == 'Patches' }['href']
    assert_response :success
    assert_select '.nav-tabs a[aria-current=page]', text: 'Patches'
    assert_select '#downstream-patches li', count: 1
    assert_select '#downstream-patches a', text: 'first.patch'
    assert_select 'form input[name=tab][value=patches]'
    assert_select 'h3', text: 'Filter by Severity', count: 0

    get css_select('.pagination a').find { |a| a.text == '2' }['href']
    assert_select '#downstream-patches a', text: 'second.patch'
    get css_select('.nav-tabs a').find { |a| a.text == 'Advisories' }['href']
    assert_select '.nav-tabs a[aria-current=page]', text: 'Advisories'
    assert_select 'form input[name=severity][value=high]'
    assert_nil request.query_parameters['page']
  end

  test 'package page lists each downstream patch once and scopes declarations to the requested release' do
    bytes = "--- a/build\n+++ b/build\n@@ -1 +1 @@\n-old\n+new\n"
    declare('debian', %w[build.patch alias.patch], bytes)
    declare('homebrew', 'brew.patch', bytes)
    get ecosystem_package_path('Debian', 'yajl'), params: { tab: 'patches', version: '2.1.0' }
    assert_response :success
    assert_select '#downstream-patches li', count: 1
    assert_select "#downstream-patches a[href='#{patch_path(Digest::SHA256.hexdigest(bytes))}']", text: 'build.patch'
    assert_select '#downstream-patches .small', text: 'Declared by Debian / yajl 2.1.0', count: 1

    get ecosystem_package_path('debian', 'yajl'), params: { tab: 'patches', version: '2.0' }
    assert_select '#downstream-patches p', text: 'No matching patches found.'
    get ecosystem_package_path('rubygems', 'yajl', tab: 'patches')
    assert_select '#downstream-patches p', text: 'No matching patches found.'
  end

  test 'upstream package page matches the inferred PURL and its version' do
    bytes = "--- a/lib/rack.rb\n+++ b/lib/rack.rb\n@@ -1 +1 @@\n-old\n+new\n"
    declare('debian', 'fix.patch', bytes, package_name: 'ruby-rack',
      component: { 'identity' => { 'ecosystem' => 'rubygems', 'name' => 'rack', 'version' => '2.2.8' } })

    get ecosystem_package_path('rubygems', 'rack', tab: 'patches')
    assert_response :success
    assert_select '#downstream-patches code', text: 'pkg:gem/rack@2.2.8'
    get ecosystem_package_path('rubygems', 'rack'), params: { tab: 'patches', version: '2.2.8' }
    assert_select '#downstream-patches .small', text: /Declared by Debian \/ ruby-rack 2\.1\.0\s+· Inferred upstream package/
    get ecosystem_package_path('rubygems', 'rack'), params: { tab: 'patches', version: '2.1.0' }
    assert_select '#downstream-patches p', text: 'No matching patches found.'
  end
end
