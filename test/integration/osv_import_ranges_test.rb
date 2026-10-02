require 'test_helper'
require 'zip'
require_relative '../support/advisory_import_helpers'

class OsvImportRangesTest < ActionDispatch::IntegrationTest
  include AdvisoryImportHelpers

  setup do
    @source = create(:source, kind: 'osv')
  end

  test 'source sync retains disjoint intervals inclusive bounds and explicit affected versions' do
    record = osv_record('OSV-TEST-RANGES')
    record['affected'] = [
      {
        'package' => { 'ecosystem' => 'PyPI', 'name' => 'intervals' },
        'ranges' => [{ 'type' => 'SEMVER', 'events' => [
          { 'introduced' => '2.0.0' }, { 'fixed' => '2.5.0' },
          { 'introduced' => '0' }, { 'fixed' => '1.0.0' }, { 'introduced' => '3.0.0' }
        ] }],
        'versions' => ['1.5.0']
      },
      {
        'package' => { 'ecosystem' => 'PyPI', 'name' => 'inclusive' },
        'ranges' => [{ 'type' => 'ECOSYSTEM', 'events' => [
          { 'introduced' => '0' }, { 'last_affected' => '1.5.0' }
        ] }]
      },
      {
        'package' => { 'ecosystem' => 'PyPI', 'name' => 'exact' },
        'versions' => ['1.0.0', '2.5.0', '1.0.0']
      },
      {
        'package' => { 'ecosystem' => 'PyPI', 'name' => 'git-with-versions' },
        'ranges' => [{ 'type' => 'GIT', 'repo' => 'https://github.com/example/sample', 'events' => [{ 'introduced' => 'abc123' }] }],
        'versions' => ['2.0.0']
      }
    ]
    numbers = %w[0.5.0 1.0.0 1.5.0 2.0.0 2.5.0 3.0.0]
    expected = {
      'intervals' => %w[0.5.0 1.5.0 2.0.0 3.0.0],
      'inclusive' => %w[0.5.0 1.0.0 1.5.0],
      'exact' => %w[1.0.0 2.5.0],
      'git-with-versions' => ['2.0.0']
    }
    expected.each_key { |name| create(:package, ecosystem: 'pypi', name: name, version_numbers: numbers) }
    stub_osv([record])
    Sidekiq::Testing.fake! { @source.sync_advisories }

    advisory = @source.advisories.sole
    expected.each do |name, versions|
      package = advisory.packages.find { |item| item['package_name'] == name }
      assert_equal versions, package['affected_versions'].sort, name
      assert_equal numbers - versions, package['unaffected_versions'].sort, name
      get '/api/v1/advisories', params: { ecosystem: 'pypi', package_name: name }, as: :json
      assert_response :success
      assert_equal [advisory.uuid], response.parsed_body.map { |item| item['uuid'] }
      post '/v1/query', params: { package: { ecosystem: 'PyPI', name: name } }, as: :json
      assert_response :success
      assert_equal [advisory.uuid], response.parsed_body['vulns'].map { |item| item['id'] }
    end

    get "/v1/vulns/#{advisory.uuid}", as: :json
    assert_response :success
    affected = response.parsed_body['affected'].index_by { |item| item['package']['name'] }
    assert_equal 3, affected['intervals']['ranges'].size
    assert_equal ['1.5.0'], affected['intervals']['versions']
    assert_equal [{ 'introduced' => '0' }, { 'last_affected' => '1.5.0' }], affected['inclusive']['ranges'].sole['events']
    assert_equal %w[1.0.0 2.5.0], affected['exact']['versions']
    assert_empty affected['exact']['ranges']
    assert_equal ['2.0.0'], affected['git-with-versions']['versions']
    assert_empty affected['git-with-versions']['ranges']
  end

  test 'source sync excludes version-qualified distro archives before downloading' do
    stub_osv([osv_record('OSV-TEST-NON-DISTRO')])
    stub_request(:get, "#{Sources::Osv::BASE_URL}/ecosystems.txt")
      .to_return(status: 200, body: "PyPI\nDebian:12\nalpine:v3.17\nUbuntu:24.04\n")
    Sidekiq::Testing.fake! { @source.sync_advisories }
    assert_equal ['OSV-TEST-NON-DISTRO'], @source.advisories.pluck(:uuid)
    assert_not_requested :get, %r{#{Regexp.escape(Sources::Osv::BASE_URL)}/(?:Debian|alpine|Ubuntu)}
  end

  test 'source sync imports complete batches before parsing the rest of an archive' do
    records = 101.times.map { |index| osv_record("OSV-BATCH-#{index}") }
    stub_osv(records)
    imported_sizes = []
    parsed = 0
    original_parse = JSON.method(:parse)
    source = @source
    JSON.define_singleton_method(:parse) do |text, **options|
      if options[:symbolize_names] && text.include?('OSV-BATCH-')
        imported_sizes << source.advisories.count if parsed == 100
        parsed += 1
      end
      original_parse.call(text, **options)
    end
    begin
      Sidekiq::Testing.fake! { @source.sync_advisories }
    ensure
      JSON.define_singleton_method(:parse, original_parse)
    end
    assert_equal [100], imported_sizes
    assert_equal 101, parsed
    assert_equal 101, @source.advisories.count
  end

  test 'source sync propagates database failures while consuming an archive' do
    stub_osv([osv_record('OSV-TEST-FAILED')])
    AdvisoryRecord.expects(:import).raises(ActiveRecord::RecordInvalid)
    assert_raises(ActiveRecord::RecordInvalid) { @source.sync_advisories }
    assert_empty @source.advisories
  end
end
