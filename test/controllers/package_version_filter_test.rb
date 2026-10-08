require "test_helper"

class PackageVersionFilterTest < ActionDispatch::IntegrationTest
  setup do
    @source = create(:source)
    @affected = create_advisory('widget', '>= 1.0.0, < 2.0.0')
    @other = create_advisory('widget', '>= 3.0.0, < 4.0.0')
    @filters = { ecosystem: 'npm', package_name: 'widget', version: '1.5.0' }
  end

  test "API filters ranges before pagination and preserves ordering and counts" do
    later = create_advisory('widget', '< 2.0.0')
    @affected.update!(published_at: 3.days.ago)
    @other.update!(published_at: 2.days.ago)
    later.update!(published_at: 1.day.ago)

    get api_v1_advisories_url, params: @filters.merge(per_page: 1, sort: 'published_at', order: 'asc')
    assert_response :success
    assert_equal [@affected.uuid], response.parsed_body.pluck('uuid')
    assert_equal '2', response.headers['total-count']

    get api_v1_advisories_url, params: @filters.merge(per_page: 1, page: 2, sort: 'published_at', order: 'asc')
    assert_response :success
    assert_equal [later.uuid], response.parsed_body.pluck('uuid')
  end

  test "API excludes fixed versions and retains unversioned behavior" do
    get api_v1_advisories_url, params: @filters.merge(version: '2.0.0')
    assert_response :success
    assert_empty response.parsed_body

    ['', nil].each do |version|
      get api_v1_advisories_url, params: @filters.merge(version: version)
      assert_response :success
      assert_equal [@affected.uuid, @other.uuid].sort, response.parsed_body.pluck('uuid').sort
    end
  end

  test "API matches ecosystem name and range on the same package entry" do
    @affected.update!(packages: [package_data('WiDgEt', '>= 1.0.0, < 2.0.0')])
    create(:advisory, source: @source, packages: [
      package_data('widget', '< 1.0.0'),
      package_data('other', '< 2.0.0'),
      package_data('widget', '< 2.0.0').merge('ecosystem' => 'pypi')
    ])

    get api_v1_advisories_url, params: @filters.merge(ecosystem: 'NPM', package_name: 'WIDGET')
    assert_response :success
    assert_equal [@affected.uuid], response.parsed_body.pluck('uuid')
  end

  test "API uses all ranges without requiring cached versions" do
    @affected.update!(packages: [package_data('widget', '< 1.0.0').merge(
      'affected_versions' => [],
      'versions' => [
        { 'vulnerable_version_range' => '< 1.0.0' },
        { 'vulnerable_version_range' => '>= 1.0.0-beta.1, < 2.0.0 || >= 5.0.0, < 6.0.0' }
      ]
    )])

    %w[1.0.0-beta.2 v1.5.0 5.5.0].each do |version|
      get api_v1_advisories_url, params: @filters.merge(version: version)
      assert_response :success
      assert_equal [@affected.uuid], response.parsed_body.pluck('uuid')
    end
  end

  test "API excludes missing and unparseable ranges" do
    [nil, '', '>='].each { |range| create_advisory('widget', range) }
    create(:advisory, source: @source, packages: [{ 'ecosystem' => 'npm', 'package_name' => 'widget' }])

    get api_v1_advisories_url, params: @filters
    assert_response :success
    assert_equal [@affected.uuid], response.parsed_body.pluck('uuid')
  end

  test "API rejects a version without an ecosystem and package name" do
    [@filters.except(:ecosystem), @filters.except(:package_name)].each do |filters|
      get api_v1_advisories_url, params: filters
      assert_response :bad_request
      assert_equal 'ecosystem and package_name are required when filtering by version', response.parsed_body['error']
    end
  end

  test "API rejects malformed and structured versions" do
    ['not-a-version', '>= 1.0.0', '1' * 257, ['1.5.0'], { number: '1.5.0' }].each do |version|
      get api_v1_advisories_url, params: @filters.merge(version: version)
      assert_response :bad_request
      assert_equal 'version must be a single version number', response.parsed_body['error']
    end
  end

  test "PURL lookup filters before deduplication" do
    @affected.update!(identifiers: ['CVE-TEST-VERSION'])
    @other.update!(identifiers: ['CVE-TEST-VERSION'])
    get lookup_api_v1_advisories_url, params: { purl: 'pkg:npm/widget@1.5.0' }
    assert_response :success
    assert_equal [@affected.uuid], response.parsed_body.pluck('uuid')

    get lookup_api_v1_advisories_url, params: { purl: 'pkg:npm/widget@2.0.0' }
    assert_response :success
    assert_empty response.parsed_body
  end

  test "PURL lookup preserves package namespaces" do
    scoped = create_advisory('@scope/widget', '< 2.0.0')
    get lookup_api_v1_advisories_url, params: { purl: 'pkg:npm/%40scope/widget@1.5.0' }
    assert_response :success
    assert_equal [scoped.uuid], response.parsed_body.pluck('uuid')
  end

  test "API supports ecosystem ranges and versions with fewer than three components" do
    [
      ['rubygems', 'widget-gem', '>= 1.0.0.beta1, < 2.0', '1.0.0.beta2', '2.0'],
      ['pypi', 'widget-python', '>= 1.0, < 2.0', '1.5', '2.0'],
      ['maven', 'org.example:widget', '[1.0,2.0)', '1.5', '2.0'],
      ['nuget', 'Widget.Net', '>= 1.0.0, < 2.0.0', '1.5.0.1', '2.0.0']
    ].each do |ecosystem, name, range, affected, fixed|
      advisory = create(:advisory, source: @source, packages: [package_data(name, range).merge('ecosystem' => ecosystem)])
      get api_v1_advisories_url, params: { ecosystem: ecosystem, package_name: name, version: affected }
      assert_response :success
      assert_equal [advisory.uuid], response.parsed_body.pluck('uuid')

      get api_v1_advisories_url, params: { ecosystem: ecosystem, package_name: name, version: fixed }
      assert_response :success
      assert_empty response.parsed_body
    end
  end

  test "package page filters advisories and preserves filter controls" do
    get ecosystem_package_url('npm', 'widget'), params: { version: '1.5.0', severity: 'high', sort: 'published_at', page: 2, per_page: 1 }
    assert_response :success
    assert_equal 1, assigns(:pagy).count
    assert_select 'form input[name=version][value="1.5.0"]'
    assert_select 'form input[name=severity][value=high]'
    assert_select 'form input[name=sort][value=published_at]'
    assert_select 'form input[name=page]', count: 0
    assert_select 'a', text: 'Clear Filters'
    assert_select 'p', text: 'No advisories with a matching affected version range were found.', count: 0

    get ecosystem_package_url('npm', 'widget'), params: { version: '1.5.0' }
    assert_response :success
    assert_select "a[href='#{advisory_path(@affected)}']"
    assert_select "a[href='#{advisory_path(@other)}']", count: 0
    assert_select 'a.list-group-item[href*="version=1.5.0"]'
  end

  test "package page excludes potential and withdrawn advisories for a version" do
    package = Package.find_by!(ecosystem: 'npm', name: 'widget')
    related = create_advisory('another-package', '< 2.0.0')
    create(:related_package, package: package, advisory: related)
    withdrawn = create_advisory('widget', '< 2.0.0')
    withdrawn.update!(withdrawn_at: Time.current)

    get ecosystem_package_url('npm', 'widget'), params: { version: '1.5.0' }
    assert_response :success
    assert_equal [@affected.id], assigns(:advisories).map(&:id)

    get ecosystem_package_url('npm', 'widget')
    assert_response :success
    assert_includes assigns(:advisories).map(&:id), related.id
  end

  test "package page explains empty matches and rejects invalid versions" do
    get ecosystem_package_url('npm', 'widget'), params: { version: '2.0.0' }
    assert_response :success
    assert_select 'p', text: 'No advisories with a matching affected version range were found.'

    get ecosystem_package_url('npm', 'widget'), params: { version: 'not-a-version' }
    assert_response :bad_request
    refute_match /max-age=3600/, response.headers['Cache-Control']
  end

  test "legacy package redirects preserve version" do
    get advisories_url, params: @filters
    assert_redirected_to ecosystem_package_url('npm', 'widget', version: '1.5.0')

    get advisories_url, params: @filters.except(:ecosystem)
    assert_redirected_to ecosystem_package_url('npm', 'widget', version: '1.5.0')
  end

  def package_data(name, range)
    { 'ecosystem' => 'npm', 'package_name' => name, 'versions' => [{ 'vulnerable_version_range' => range }] }
  end

  def create_advisory(name, range)
    create(:advisory, source: @source, packages: [package_data(name, range)])
  end
end
