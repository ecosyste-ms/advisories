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
      .to_return(status: 200, body: "PyPI\nDebian:12\nalpine:v3.17\nUbuntu:24.04\nRocky Linux:9\nred hat\nBellSoft Hardened Containers\n")
    Sidekiq::Testing.fake! { @source.sync_advisories }
    assert_equal ['OSV-TEST-NON-DISTRO'], @source.advisories.pluck(:uuid)
    assert_not_requested :get, %r{#{Regexp.escape(Sources::Osv::BASE_URL)}/(?:Debian|alpine|Ubuntu|Rocky|red|BellSoft)}
  end

  test 'source sync merges repeated OSV packages and ranges across aliases' do
    record = osv_record('OSV-TEST-REPEATED', aliases: ['OSV-TEST-SECONDARY'])
    second_package = record['affected'].first.deep_dup
    second_package['ranges'].first['events'] = [{ 'introduced' => '2.0.0' }, { 'fixed' => '3.0.0' }]
    record['affected'] << second_package
    secondary = osv_record('OSV-TEST-SECONDARY')
    secondary['affected'].first['versions'] = ['4.0.0']
    create(:package, ecosystem: 'pypi', name: 'sample', version_numbers: %w[0.5.0 1.0.0 2.0.0 3.0.0 4.0.0])
    stub_osv([record, secondary])

    Sidekiq::Testing.fake! { @source.sync_advisories }

    advisory = @source.advisories.sole
    package = advisory.packages.sole
    assert_equal %w[0.5.0 2.0.0 4.0.0], package['affected_versions']
    assert_equal %w[1.0.0 3.0.0], package['unaffected_versions']
    assert_equal 3, package['versions'].size
    get '/v1/vulns/OSV-TEST-SECONDARY', as: :json
    assert_response :success
    affected = response.parsed_body['affected'].sole
    assert_equal [
      [{ 'introduced' => '0' }, { 'fixed' => '1.0.0' }],
      [{ 'introduced' => '2.0.0' }, { 'fixed' => '3.0.0' }]
    ], affected['ranges'].map { |range| range['events'] }
    assert_equal ['4.0.0'], affected['versions']
  end

  test 'source sync imports records without descriptions and applies their withdrawals' do
    record = osv_record('OSV-TEST-NO-DESCRIPTION').except('summary')
    stub_osv([record])
    Sidekiq::Testing.fake! { @source.sync_advisories }
    advisory = @source.advisories.sole
    assert_equal 'sample', advisory.packages.sole['package_name']
    assert_nil advisory.withdrawn_at

    withdrawn = record.slice('id').merge('modified' => '2026-02-01T00:00:00Z', 'withdrawn' => '2026-02-01T00:00:00Z')
    stub_osv([withdrawn])
    Sidekiq::Testing.fake! { @source.sync_advisories }

    assert_equal Time.utc(2026, 2, 1), advisory.reload.withdrawn_at
    assert_empty advisory.packages
    get "/v1/vulns/#{advisory.uuid}", as: :json
    assert_response :success
    assert_equal '2026-02-01T00:00:00Z', response.parsed_body['withdrawn']
  end

  test 'source sync sorts ecosystem ranges outside the purl mapping' do
    record = osv_record('OSV-TEST-CRAN')
    record['affected'].first['package']['ecosystem'] = 'CRAN'
    record['affected'].first['ranges'].first['events'] = [{ 'fixed' => '2.0.0' }, { 'introduced' => '1.0.0' }]
    stub_osv([record])
    Sidekiq::Testing.fake! { @source.sync_advisories }

    package = @source.advisories.sole.packages.sole
    assert_equal 'cran', package['ecosystem']
    assert_equal '>= 1.0.0, < 2.0.0', package['versions'].sole['vulnerable_version_range']
  end

  test 'source sync logs malformed JSON and imports subsequent archive entries' do
    before = osv_record('OSV-TEST-BEFORE')
    after = osv_record('OSV-TEST-AFTER')
    stub_osv([])
    zip = Zip::OutputStream.write_buffer do |stream|
      { 'before.json' => before.to_json, 'broken.json' => '{', 'after.json' => after.to_json }.each do |name, content|
        stream.put_next_entry(name)
        stream.write(content)
      end
    end
    stub_request(:get, "#{Sources::Osv::BASE_URL}/PyPI/all.zip").to_return(status: 200, body: zip.string)
    Rails.logger.expects(:error).with(regexp_matches(/Failed to parse OSV advisory broken.json for PyPI:/))

    count = Sidekiq::Testing.fake! { @source.sync_advisories }

    assert_equal 2, count
    assert_equal %w[OSV-TEST-AFTER OSV-TEST-BEFORE], @source.advisories.order(:uuid).pluck(:uuid)
    get '/v1/vulns/OSV-TEST-AFTER', as: :json
    assert_response :success
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
