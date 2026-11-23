require 'test_helper'

class OsvSourceTest < ActiveSupport::TestCase
  BASE = Sources::Osv::BASE_URL

  setup do
    @source = Source.create!(name: 'OSV', kind: 'osv', url: 'https://osv.dev')
    @osv = Sources::Osv.new(@source, http: PatchIndex::Http.new(interval: 0))
    @debian = record('DEBIAN-CVE-2023-26964', '2026-10-26T18:02:13.076151954Z', upstream: ['CVE-2023-26964'], affected: [
      affected('Debian:12', 'rust-h2', [{ introduced: '0' }, { fixed: '0.3.13-2' }]),
      affected('Debian:13', 'rust-h2', [{ introduced: '0' }, { fixed: '0.3.13-2' }], versions: %w[0.3.13-1 0.3.12-1])
    ])
    @old_release = record('DEBIAN-CVE-2019-0001', '2026-10-01T00:00:00Z', affected: [affected('Debian:11', 'zlib', [{ introduced: '0' }])])
    @ubuntu = record('UBUNTU-CVE-2026-33055', '2026-11-20T06:00:00Z', upstream: ['CVE-2026-33055'],
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }], affected: [
        affected('Ubuntu:24.04:LTS', 'rust-tar', [{ introduced: '0' }]),
        affected('Ubuntu:Pro:24.04:LTS', 'rust-tar', [{ introduced: '0' }, { fixed: '9' }])
      ])
    publish('Debian', [@debian, @old_release])
    publish('Ubuntu', [@ubuntu])
  end

  def record(id, modified, affected:, **rest)
    { id: id, modified: modified, published: '2023-04-11T14:15:07Z', details: "Details of #{id}.\nSecond line.",
      references: [{ type: 'ADVISORY', url: "https://security-tracker.debian.org/tracker/#{id}" }], affected: affected, **rest }
  end

  def affected(ecosystem, name, events, versions: [])
    { package: { ecosystem: ecosystem, name: name }, ranges: [{ type: 'ECOSYSTEM', events: events }], versions: versions }
  end

  # An uncompressed zip archive, which is all the reader needs.
  def zip(files)
    local = ''.b
    central = ''.b
    files.each do |name, body|
      sizes = [Zlib.crc32(body), body.bytesize, body.bytesize, name.bytesize, 0]
      central << [0x02014b50, 20, 20, 0, 0, 0, 0x21, *sizes, 0, 0, 0, 0, local.bytesize].pack('VvvvvvvVVVvvvvvVV') << name
      local << [0x04034b50, 20, 0, 0, 0, 0x21, *sizes].pack('VvvvvvVVVvv') << name << body
    end
    local + central + [0x06054b50, 0, 0, files.size, files.size, central.bytesize, local.bytesize, 0].pack('VvvvvVVv')
  end

  def publish(export, records)
    index = records.sort_by { |r| r[:modified] }.reverse.map { |r| "#{r[:modified]},#{r[:id]}" }.join("\n")
    stub_request(:get, "#{BASE}/#{export}/modified_id.csv").to_return(body: "#{index}\n")
    @archives ||= {}
    @archives[export] = stub_request(:get, "#{BASE}/#{export}/all.zip")
      .to_return(body: zip(records.to_h { |r| ["#{r[:id]}.json", r.to_json] }))
  end

  test 'the first sync reads each archive and keeps only packages in the tracked release' do
    github = create(:advisory, uuid: 'GSA_h2', identifiers: %w[GHSA-f8vr-r385-rh5r CVE-2023-26964])
    create(:package, ecosystem: 'debian', name: 'rust-h2', version_numbers: %w[0.3.13-1 0.3.13-2 0.4.4-1], last_synced_at: Time.current)

    Sidekiq::Testing.fake! do
      PackageSyncWorker.jobs.clear
      assert_equal 2, @osv.sync_advisories
      assert_equal [%w[debian rust-h2], %w[ubuntu rust-tar]], PackageSyncWorker.jobs.map { |job| job['args'] }.sort
      PackageSyncWorker.jobs.clear
    end

    assert_equal %w[DEBIAN-CVE-2023-26964 UBUNTU-CVE-2026-33055], @source.advisories.order(:uuid).pluck(:uuid)
    debian = @source.advisories.find_by!(uuid: 'DEBIAN-CVE-2023-26964')
    assert_equal %w[DEBIAN-CVE-2023-26964 CVE-2023-26964], debian.identifiers
    package = debian.packages.sole
    assert_equal ['debian', 'rust-h2', [{ 'vulnerable_version_range' => '< 0.3.13-2', 'first_patched_version' => '0.3.13-2' }]],
      package.values_at('ecosystem', 'package_name', 'versions')
    assert_equal [['0.3.13-1'], %w[0.3.13-2 0.4.4-1]], package.values_at('affected_versions', 'unaffected_versions')
    assert_equal 2, @source.reload.advisories_count
    assert debian.affects_version?('debian', 'rust-h2', '0.3.13-1')
    assert_not debian.affects_version?('debian', 'rust-h2', '0.3.13-2')
    assert_equal ['Details of DEBIAN-CVE-2023-26964. Second line.', 'osv', 'https://security-tracker.debian.org/tracker/DEBIAN-CVE-2023-26964'],
      [debian.title, debian.source_kind, debian.url]
    assert_equal [github.uuid], debian.cached_related_advisories.pluck('uuid')
    assert_equal [debian.uuid], github.reload.cached_related_advisories.pluck('uuid')

    ubuntu = @source.advisories.find_by!(uuid: 'UBUNTU-CVE-2026-33055')
    assert_equal [{ 'vulnerable_version_range' => '>= 0', 'first_patched_version' => nil }], ubuntu.packages.sole['versions']
    assert ubuntu.affects_version?('ubuntu', 'rust-tar', '0.4.40-1ubuntu0.1')
    assert_equal ['CRITICAL', 9.8], [ubuntu.severity, ubuntu.cvss_score]
    assert_equal({ 'Debian' => '2026-10-26T18:02:13.076151954Z', 'Ubuntu' => '2026-11-20T06:00:00.000000000Z' }, @source.reload.metadata['osv_synced'])
  end

  test 'later syncs fetch only the records modified since the last one' do
    @osv.sync_advisories
    assert_equal 0, @osv.sync_advisories
    @archives.each_value { |archive| assert_requested archive, times: 1 }

    fixed = @debian.merge(modified: '2026-11-23T15:00:06Z', affected: [affected('Debian:13', 'rust-h2', [{ introduced: '0' }, { fixed: '0.3.13-3' }])])
    publish('Debian', [fixed, @old_release])
    single = stub_request(:get, "#{BASE}/Debian/DEBIAN-CVE-2023-26964.json").to_return(body: fixed.to_json)

    assert_equal 1, @osv.sync_advisories
    assert_requested single, times: 1
    assert_requested :get, "#{BASE}/Debian/all.zip", times: 1
    advisory = @source.advisories.find_by!(uuid: 'DEBIAN-CVE-2023-26964')
    assert_equal '< 0.3.13-3', advisory.packages.sole.dig('versions', 0, 'vulnerable_version_range')
    assert_equal 2, @source.advisories.count
  end

  test 'a record that is withdrawn or stops naming a tracked release is marked withdrawn' do
    @osv.sync_advisories
    withdrawn = @debian.merge(modified: '2026-11-23T15:00:00Z', withdrawn: '2026-11-22T00:00:00Z', affected: [])
    moved = @ubuntu.merge(modified: '2026-11-23T16:00:00Z', affected: [affected('Ubuntu:22.04:LTS', 'rust-tar', [{ introduced: '0' }])])
    publish('Debian', [withdrawn, @old_release])
    publish('Ubuntu', [moved])
    stub_request(:get, "#{BASE}/Debian/DEBIAN-CVE-2023-26964.json").to_return(body: withdrawn.to_json)
    stub_request(:get, "#{BASE}/Ubuntu/UBUNTU-CVE-2026-33055.json").to_return(body: moved.to_json)

    @osv.sync_advisories

    assert_equal [Time.utc(2026, 11, 22), Time.utc(2026, 11, 23, 16)], @source.advisories.order(:uuid).pluck(:withdrawn_at)
    assert_empty Advisory.not_withdrawn.where(source: @source)
  end

  test 'a failure part way through keeps the follow-up work for the records already saved' do
    @osv.sync_advisories
    github = create(:advisory, uuid: 'GSA_new', identifiers: %w[GHSA-2222-3333-4444 CVE-2026-0001])
    first = record('DEBIAN-CVE-2026-0001', '2026-11-23T15:00:00Z', upstream: ['CVE-2026-0001'], affected: [affected('Debian:13', 'zlib', [{ introduced: '0' }])])
    second = record('DEBIAN-CVE-2026-0002', '2026-11-23T16:00:00Z', affected: [affected('Debian:13', 'curl', [{ introduced: '0' }])])
    publish('Debian', [first, second, @debian, @old_release])
    stub_request(:get, "#{BASE}/Debian/DEBIAN-CVE-2023-26964.json").to_return(body: @debian.to_json)
    stub_request(:get, "#{BASE}/Debian/DEBIAN-CVE-2026-0001.json").to_return(body: first.to_json)
    stub_request(:get, "#{BASE}/Debian/DEBIAN-CVE-2026-0002.json").to_return(status: 503)
    watermark = @source.reload.metadata.dig('osv_synced', 'Debian')

    Sidekiq::Testing.fake! do
      PackageSyncWorker.jobs.clear
      Sources::Osv.new(@source, http: PatchIndex::Http.new(interval: 0), batch_size: 1).sync_advisories
      assert_includes PackageSyncWorker.jobs.map { |job| job['args'] }, %w[debian zlib]
      PackageSyncWorker.jobs.clear
    end

    assert @source.advisories.exists?(uuid: 'DEBIAN-CVE-2026-0001')
    assert_equal ['DEBIAN-CVE-2026-0001'], github.reload.cached_related_advisories.pluck('uuid')
    assert_equal watermark, @source.reload.metadata.dig('osv_synced', 'Debian')
  end

  test 'a failed download leaves the export to be retried' do
    stub_request(:get, "#{BASE}/Debian/all.zip").to_return(status: 503)

    assert_equal 1, @osv.sync_advisories
    assert_equal ['Ubuntu'], @source.reload.metadata['osv_synced'].keys
  end
end
