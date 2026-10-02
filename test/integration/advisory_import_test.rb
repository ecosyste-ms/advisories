require 'test_helper'
require 'zip'
require_relative '../support/advisory_import_helpers'

class AdvisoryImportTest < ActionDispatch::IntegrationTest
  include AdvisoryImportHelpers
  setup do
    @github = create(:source, kind: 'github')
    @osv = create(:source, kind: 'osv')
    @edge = github_edge
    stub_github([@edge])
    stub_osv([osv_record('GHSA-test-aaaa', aliases: ['CVE-TEST-1']),
              osv_record('PYSEC-TEST-1', aliases: ['CVE-TEST-1'])])
  end

  %w[github osv].each do |first|
    test "imports retain source evidence with #{first} first" do
      Sidekiq::Testing.fake! do
        sources = first == 'github' ? [@github, @osv] : [@osv, @github]
        sources.each(&:sync_advisories)
        assert_equal 1, Advisory.count
        advisory = Advisory.sole
        assert_equal 'GSA_test', advisory.uuid
        assert_equal 'GitHub summary', advisory.title
        assert_equal 0.42, advisory.epss_percentage
        assert_equal @github, advisory.source
        assert_equal %w[CVE-TEST-1 GHSA-test-aaaa PYSEC-TEST-1], advisory.identifiers.sort
        assert_equal 3, AdvisoryRecord.count
        assert_equal [@edge], @github.advisory_records.sole.raw
        assert_equal %w[GHSA-test-aaaa PYSEC-TEST-1], @osv.advisory_records.order(:external_id).pluck(:raw).map { |raw| raw['id'] }
        assert_equal '< 2.0.0', advisory.packages.sole['versions'].sole['vulnerable_version_range']
        before = advisory.attributes
        jobs = [PackageSyncWorker.jobs.size, RelatedPackagesSyncWorker.jobs.size]
        2.times { sources.reverse_each(&:sync_advisories) }
        assert_equal before, advisory.reload.attributes
        assert_equal jobs, [PackageSyncWorker.jobs.size, RelatedPackagesSyncWorker.jobs.size]

        %w[GSA_test GHSA-test-aaaa PYSEC-TEST-1 pysec-test-1].each do |id|
          get "/api/v1/advisories/#{id}", as: :json
          assert_response :success
          assert_equal 'GSA_test', response.parsed_body['uuid']
          get "/v1/vulns/#{id}", as: :json
          assert_response :success
        end
        get '/api/v1/advisories', params: { ecosystem: 'pypi', package_name: 'sample' }, as: :json
        assert_equal 1, response.parsed_body.size
        get '/api/v1/advisories/lookup', params: { purl: 'pkg:pypi/sample' }, as: :json
        assert_equal 1, response.parsed_body.size
        post '/v1/query', params: { package: { ecosystem: 'PyPI', name: 'sample' } }, as: :json
        assert_equal 1, response.parsed_body['vulns'].size
      end
    end
  end

  test 'GitHub refresh retains OSV aliases references and additional packages' do
    secondary = osv_record('PYSEC-TEST-1', aliases: ['GHSA-test-aaaa'])
    secondary['references'] = [{ 'type' => 'WEB', 'url' => 'https://example.com/secondary' }]
    secondary['affected'] << secondary['affected'].first.deep_dup.tap { |item| item['package']['name'] = 'extra' }
    stub_osv([secondary])
    Sidekiq::Testing.fake! do
      @github.sync_advisories
      @osv.sync_advisories
      @edge['node']['advisory']['summary'] = 'Updated GitHub summary'
      stub_github([@edge])
      @github.sync_advisories
    end
    advisory = Advisory.sole
    assert_equal 'Updated GitHub summary', advisory.title
    assert_includes advisory.identifiers, 'PYSEC-TEST-1'
    assert_includes advisory.references, 'https://example.com/secondary'
    assert_equal %w[sample extra], advisory.packages.map { |package| package['package_name'] }
    assert_equal '< 2.0.0', advisory.packages.first['versions'].sole['vulnerable_version_range']
  end

  test 'upstream timestamps remain in source records without backdating local changes' do
    travel_to Time.utc(2026, 2, 1) do
      Sidekiq::Testing.fake! do
        @github.sync_advisories
        @osv.sync_advisories
        advisory = Advisory.sole
        assert_equal Time.current, advisory.updated_at
        assert_equal '2026-01-02T00:00:00Z', @github.advisory_records.sole.raw.sole.dig('node', 'advisory', 'updatedAt')
        assert_equal ['2026-01-02T00:00:00Z'], @osv.advisory_records.pluck(:raw).map { |raw| raw['modified'] }.uniq
        @edge['node']['advisory']['updatedAt'] = '2026-01-03T00:00:00Z'
        stub_github([@edge])
        travel 1.day
        @github.sync_advisories
        assert_equal Time.utc(2026, 2, 1), advisory.reload.updated_at
        assert_equal '2026-01-03T00:00:00Z', @github.advisory_records.sole.raw.sole.dig('node', 'advisory', 'updatedAt')
        @edge['node']['advisory']['summary'] = 'Corrected summary'
        stub_github([@edge])
        @github.sync_advisories
        assert_equal Time.current, advisory.reload.updated_at
      end
    end
  end

  test 'aliases merge transitively across batches and corrected aliases split again' do
    records = [osv_record('OSV-TEST-A', aliases: ['OSV-TEST-X']),
               osv_record('OSV-TEST-C', aliases: ['OSV-TEST-Y'])]
    records += 98.times.map { |i| osv_record("OSV-SEPARATE-#{i}") }
    records << osv_record('OSV-TEST-B', aliases: ['OSV-TEST-X', 'OSV-TEST-Y'])
    records << osv_record('OSV-RELATED', upstream: ['OSV-TEST-A'], related: ['OSV-TEST-C'])
    stub_osv(records)
    Sidekiq::Testing.fake! do
      @osv.sync_advisories
      assert_equal 100, Advisory.count
      canonical = Advisory.find_by!(uuid: 'OSV-TEST-A')
      assert_equal %w[OSV-TEST-A OSV-TEST-B OSV-TEST-C OSV-TEST-X OSV-TEST-Y], canonical.identifiers
      bridge = records.find { |record| record['id'] == 'OSV-TEST-B' }
      bridge['aliases'] = []
      stub_osv(records)
      @osv.sync_advisories
      assert_equal 102, Advisory.count
      assert_equal %w[OSV-TEST-A OSV-TEST-X], canonical.reload.identifiers
      assert_equal 102, AdvisoryRecord.count
    end
  end

  test 'GitHub pages combine package ranges before publication and replace previous snapshots' do
    second = @edge.deep_dup
    second['node']['vulnerableVersionRange'] = '>= 3.0.0, < 4.0.0'
    second['node']['firstPatchedVersion']['identifier'] = '4.0.0'
    stub_request(:post, 'https://api.github.com/graphql').to_return(
      github_response([@edge], next_page: true), github_response([second])
    )
    Sidekiq::Testing.fake! do
      @github.sync_advisories
      assert_equal 2, Advisory.sole.packages.sole['versions'].size
      assert_equal [@edge, second], @github.advisory_records.sole.raw
      stub_github([second])
      @github.sync_advisories
      assert_equal [second], @github.advisory_records.sole.raw
      assert_equal ['>= 3.0.0, < 4.0.0'], Advisory.sole.packages.sole['versions'].map { |range| range['vulnerable_version_range'] }
    end
  end

  test 'a failed GitHub page leaves the published advisory intact and a retry discards staging' do
    Sidekiq::Testing.fake! do
      @github.sync_advisories
      before = Advisory.sole.attributes
      changed = @edge.deep_dup
      changed['node']['advisory']['summary'] = 'Incomplete feed'
      new_edge = github_edge(id: 'GSA_new', ghsa: 'GHSA-test-bbbb')
      stub_request(:post, 'https://api.github.com/graphql').to_return(
        github_response([changed, new_edge], next_page: true), { status: 500 }
      )
      assert_raises(Octokit::InternalServerError) { @github.sync_advisories }
      assert_equal before, Advisory.sole.attributes
      assert_nil Advisory.find_by_identifier('GHSA-test-bbbb')
      stub_github([@edge])
      @github.sync_advisories
      assert_equal before, Advisory.sole.attributes
      assert_equal [@edge], @github.advisory_records.find_by!(external_id: 'GSA_test').raw
    end
  end

  test 'multiple GitHub records for one alias family keep all their ranges' do
    second = github_edge(id: 'GSA_second', ghsa: 'GHSA-test-bbbb')
    second['node']['vulnerableVersionRange'] = '>= 3.0.0, < 4.0.0'
    second['node']['firstPatchedVersion']['identifier'] = '4.0.0'
    stub_github([@edge, second])
    Sidekiq::Testing.fake! { @github.sync_advisories }
    assert_equal 1, Advisory.count
    assert_equal 2, AdvisoryRecord.count
    assert_equal ['< 2.0.0', '>= 3.0.0, < 4.0.0'], Advisory.sole.packages.sole['versions'].map { |range| range['vulnerable_version_range'] }.sort
    assert_equal Advisory.sole, Advisory.find_by_identifier('GSA_test')
    assert_equal Advisory.sole, Advisory.find_by_identifier('GSA_second')
  end

  test 'changed package evidence clears derived links and queues their replacement' do
    Sidekiq::Testing.fake! do
      @github.sync_advisories
      advisory = Advisory.sole
      advisory.related_packages.create!(package: create(:package))
      @edge['node']['package']['name'] = 'renamed'
      stub_github([@edge])
      assert_difference 'RelatedPackagesSyncWorker.jobs.size', 1 do
        @github.sync_advisories
      end
      assert_empty advisory.reload.related_packages
      assert_equal 'renamed', advisory.packages.sole['package_name']
      assert_includes PackageSyncWorker.jobs.map { |job| job['args'] }, ['pypi', 'sample']
      assert_includes PackageSyncWorker.jobs.map { |job| job['args'] }, ['pypi', 'renamed']
    end
  end

  test 'backfill consolidates legacy rows and clears stale related data' do
    Sidekiq::Testing.fake! do
      github = Advisory.create!(Sources::Github.new(@github).map_advisories([@edge.deep_symbolize_keys]).sole.merge(source: @github))
      osv_raw = osv_record('PYSEC-TEST-1', aliases: ['GHSA-test-aaaa'])
      osv = Advisory.create!(Sources::Osv.new(@osv).map_osv_advisory(osv_raw.deep_symbolize_keys).merge(source: @osv))
      other_source = create(:source, kind: 'erlef')
      other = create(:advisory, source: other_source, identifiers: ['CVE-TEST-1'])
      other.cache_related_advisories!
      assert_equal 1, other.cached_related_advisories.size
      github.related_packages.create!(package: create(:package))
      AdvisoryRecord.create!(source: @github, advisory: github, external_id: github.uuid,
                             pending_sync_token: 'interrupted', pending_payload: { 'uuid' => github.uuid })
      require 'rake'
      load Rails.root.join('lib/tasks/advisories.rake') unless Rake::Task.task_defined?('advisories:backfill_records')
      Rake::Task.define_task(:environment) unless Rake::Task.task_defined?(:environment)
      task = Rake::Task['advisories:backfill_records']
      task.reenable
      task.invoke
      assert_equal 2, Advisory.count
      assert_equal 2, AdvisoryRecord.count
      assert_equal github.id, Advisory.find_by_identifier(osv.uuid).id
      assert_equal [github.uuid], other.reload.cached_related_advisories.map { |record| record['uuid'] }
      before = Advisory.order(:id).map(&:attributes)
      task.reenable
      task.invoke
      assert_equal before, Advisory.order(:id).map(&:attributes)
      @github.sync_advisories
      @osv.sync_advisories
      assert_equal 2, Advisory.count
      assert_includes github.reload.identifiers, 'PYSEC-TEST-1'
    end
  end

end
