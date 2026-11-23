require 'test_helper'
require 'open3'
require 'rubygems/package'
require 'rake'

class PatchIndex::DailySyncTest < ActiveSupport::TestCase
  CHANGELOG = <<~TEXT
    example (1-2) unstable; urgency=medium

      * Add fix.patch to fix CVE-2024-0001.
      * Refresh packaging.

     -- Maintainer <maintainer@example.org>  Mon, 01 Jan 2024 00:00:00 +0000
  TEXT

  setup do
    @http = PatchIndex::Http.new(interval: 0)
    @bytes = file_fixture('patch_index/relax-dep.patch').binread
    @apt = PatchIndex::Apt
  end

  def compress(text)
    result, status = Open3.capture2('xz', '-c', stdin_data: text, binmode: true)
    assert status.success?
    result
  end

  def tarball(files)
    buffer = StringIO.new(''.b)
    Gem::Package::TarWriter.new(buffer) do |tar|
      files.compact.each { |name, content| tar.add_file_simple(name, 0o644, content.bytesize) { |file| file.write(content) } }
    end
    Zlib.gzip(buffer.string)
  end

  def packaging(series, vendor_series: nil, extra: {})
    tarball({ 'debian/patches/series' => series, 'debian/patches/ubuntu.series' => vendor_series,
      'debian/patches/fix.patch' => @bytes }.merge(extra))
  end

  def apt_record(version, data, homepage: 'https://example.org')
    <<~APT
      Package: example
      Format: 3.0 (quilt)
      Version: #{version}
      Directory: pool/main/e/example
      Homepage: #{homepage}
      Checksums-Sha256:
       #{Digest::SHA256.hexdigest(data)} #{data.bytesize} example_#{version}.debian.tar.gz

    APT
  end

  def apt_indexes(source, catalogs)
    @apt::POCKETS.fetch(source).each do |base, suite|
      @apt::COMPONENTS.fetch(source).each do |component|
        stub_request(:get, "#{base}/dists/#{suite}/#{component}/source/Sources.xz")
          .to_return(body: compress(catalogs.fetch([suite, component], '')))
      end
    end
  end

  test 'Debian rake task works through the backlog and records repository, upstream version and changelog fixes' do
    data = packaging("fix.patch -p1\n", extra: { 'debian/changelog' => CHANGELOG,
      'debian/upstream/metadata' => "Repository: https://github.com/Example/Project.git\n",
      'debian/control' => "Source: example\nSection: rust\nX-Cargo-Crate: example_crate\n\nPackage: librust-example-dev\n" })
    current = apt_record('1-2', data)
    apt_indexes('debian', { ['trixie-updates', 'main'] => current, ['trixie', 'main'] => current + apt_record('1-1', data) })
    requests = %w[1-2 1-1].map do |version|
      stub_request(:get, "#{@apt::DEBIAN}/pool/main/e/example/example_#{version}.debian.tar.gz").to_return(body: data)
    end
    load Rails.root.join('lib/tasks/patches.rake') unless Rake::Task.task_defined?('patches:sync:debian')
    Rake::Task.define_task(:environment) unless Rake::Task.task_defined?(:environment)
    task = Rake::Task['patches:sync:debian']
    PatchIndex::Http.stubs(:new).returns(@http)
    ENV['PATCH_SYNC_LIMIT'] = '1'
    stats = 3.times.map do
      task.reenable
      JSON.parse(capture_io { task.invoke }.first)
    end

    assert_equal [1, 1, 0], stats.pluck('imported')
    assert_equal [1, 0, 0], stats.pluck('deferred')
    assert_equal 2, stats.last.fetch('unchanged')
    requests.each { |request| assert_requested(request, times: 1) }
    assert_equal 1, Patch.count
    assert_equal @bytes, PatchBody.find(Patch.sole.sha256).contents
    release = PatchRelease.find_by!(version: '1-2')
    assert_equal ['https://github.com/example/project', '1', 'debian/upstream/metadata:Repository'],
      [release.repository_url, release.upstream_version, release.metadata['repository_field']]
    assert_equal 'pkg:cargo/example_crate', release.upstream_purl
    occurrence = release.patch_occurrences.sole
    assert_equal ['-p1'], occurrence.declaration.fetch('quilt_options')
    assert_equal({ 'CVE-2024-0001' => 'explicit_fix' }, occurrence.advisory_roles)
    assert_empty PatchRelease.find_by!(version: '1-1').patch_occurrences.sole.advisory_ids
  ensure
    ENV.delete('PATCH_SYNC_LIMIT')
  end

  test 'Ubuntu retries a failed download, remembers a release that cannot be parsed and keeps earlier declarations' do
    sync = PatchIndex::DailySync.new('ubuntu', http: @http)
    url = "#{@apt::UBUNTU}/pool/main/e/example/example_1-1.debian.tar.gz"
    publish = ->(data) { apt_indexes('ubuntu', { ['noble-security', 'universe'] => apt_record('1-1', data, homepage: 'https://github.com/example/project') }) }
    initial = packaging("missing.patch\n", vendor_series: "fix.patch\n")
    publish.call(initial)
    download = stub_request(:get, url).to_return(body: initial)
    assert_equal 1, sync.run[:imported]
    occurrence = PatchOccurrence.sole
    assert_equal 'debian/patches/ubuntu.series', occurrence.declaration['series_path']
    assert_equal ['https://github.com/example/project', 'Sources:Homepage'],
      [occurrence.patch_release.repository_url, occurrence.patch_release.metadata['repository_field']]

    emptied = packaging('')
    publish.call(emptied)
    _, err = capture_io { assert_equal 1, sync.run[:failed] }
    assert_match(/exceeds #{emptied.bytesize} bytes/, err)
    assert_nil PatchRelease.sole.last_error

    broken = packaging("missing.patch\n")
    publish.call(broken)
    stub_request(:get, url).to_return(body: broken)
    _, err = capture_io { assert_equal 1, sync.run[:failed] }
    assert_match(/missing patch bytes/, err)
    assert_match(/missing patch bytes/, PatchRelease.sole.last_error)
    assert_equal occurrence.id, PatchOccurrence.sole.id
    assert_equal({ imported: 0, unchanged: 1, deferred: 0, failed: 0 }, sync.run)
    capture_io { assert_equal 1, sync.run(retry_failed: true)[:failed] }
    assert_requested download, times: 4

    publish.call(emptied)
    stub_request(:get, url).to_return(body: emptied)
    assert_equal 1, sync.run[:imported]
    assert_empty PatchOccurrence.all
    assert_nil PatchRelease.sole.last_error
  end

  test 'Homebrew imports formulae with patches, ignores unrelated tap commits and records a removal' do
    formula = { name: 'example', tap: 'homebrew/core', tap_git_head: '1' * 40, revision: 2, versions: { stable: '1.0' },
      homepage: 'https://example.org', ruby_source_path: 'Formula/e/example.rb', ruby_source_checksum: { sha256: '2' * 64 },
      urls: { stable: { url: 'https://github.com/Example/Project/archive/refs/tags/v1.0.tar.gz' } },
      patches: [{ strip: 'p1', file: 'Patches/e.patch' }], local_patch_checksums: { 'Patches/e.patch' => Digest::SHA256.hexdigest(@bytes) } }
    publish = -> { stub_request(:get, PatchIndex::Homebrew::INDEX).to_return(body: [formula, formula.merge(name: 'plain', patches: [])].to_json) }
    publish.call
    request = stub_request(:get, "#{PatchIndex::Homebrew::RAW}/#{'1' * 40}/Patches/e.patch").to_return(body: @bytes)
    sync = PatchIndex::DailySync.new('homebrew', http: @http)

    assert_equal({ imported: 1, unchanged: 0, deferred: 0, failed: 0 }, sync.run)
    release = PatchRelease.sole
    assert_equal ['example', '1.0_2', '1.0', 'https://github.com/example/project'],
      release.attributes.values_at('package_name', 'version', 'upstream_version', 'repository_url')
    assert_equal Digest::SHA256.hexdigest(@bytes), release.patch_occurrences.sole.patch.sha256

    formula[:tap_git_head] = '3' * 40
    publish.call
    assert_equal 1, sync.run[:unchanged]

    formula[:patches] = []
    publish.call
    assert_equal 1, sync.run[:imported]
    assert_equal 1, PatchRelease.count
    assert_empty PatchOccurrence.all
    assert_requested request, times: 1
  end

  test 'a database error is retried on the next run instead of being remembered' do
    data = packaging("fix.patch\n")
    apt_indexes('debian', { ['trixie', 'main'] => apt_record('1-1', data) })
    stub_request(:get, "#{@apt::DEBIAN}/pool/main/e/example/example_1-1.debian.tar.gz").to_return(body: data)
    sync = PatchIndex::DailySync.new('debian', http: @http)

    PatchRelease.stubs(:record!).raises(ActiveRecord::Deadlocked)
    _, err = capture_io { assert_equal 1, sync.run[:failed] }
    assert_match(/Deadlocked/, err)
    assert_empty PatchRelease.all

    PatchRelease.unstub(:record!)
    assert_equal 1, sync.run[:imported]
  end

  test 'Homebrew keeps going past a formula it cannot describe and stores patches that share a file name' do
    url = 'https://example.org/fix.diff'
    formula = { name: 'example', tap: 'homebrew/core', tap_git_head: '1' * 40, revision: 0, versions: { stable: '1.0' },
      ruby_source_path: 'Formula/e/example.rb', urls: {},
      patches: [{ strip: 'p1', url: url, directory: 'a' }, { strip: 'p1', url: url, directory: 'b' }] }
    broken = formula.merge(name: 'broken', tap_git_head: nil, patches: [{ strip: 'p1', file: 'Patches/e.patch' }])
    stub_request(:get, PatchIndex::Homebrew::INDEX).to_return(body: [broken, formula].to_json)
    stub_request(:get, url).to_return(body: @bytes)

    _, err = capture_io do
      assert_equal({ imported: 1, unchanged: 0, deferred: 0, failed: 1 }, PatchIndex::DailySync.new('homebrew', http: @http).run)
    end
    assert_match(/broken 1.0: failure not recorded/, err)
    assert_equal ['example'], PatchRelease.pluck(:package_name)
    assert_equal [['1-fix.diff', 'a'], ['2-fix.diff', 'b']], PatchOccurrence.order(:position).map { |o| [o.name, o.declaration['directory']] }
    assert_equal 1, Patch.count
  end

  test 'a Homebrew patch bundle keeps its security reference on the bundle and names each member' do
    bundle = tarball({ 'bundle-1/patches/one.diff' => @bytes, 'bundle-1/patches/CVE-2024-0002.diff' => "#{@bytes}\n" })
    url = 'https://example.org/bundle-1.tar.gz'
    formula = { 'name' => 'example', 'tap' => 'homebrew/core', 'tap_git_head' => '1' * 40, 'revision' => 0,
      'versions' => { 'stable' => '1.0' }, 'ruby_source_path' => 'Formula/e/example.rb', 'urls' => {},
      'patches' => [{ 'strip' => 'p0', 'url' => url, 'sha256' => Digest::SHA256.hexdigest(bundle),
        'apply' => %w[patches/one.diff patches/CVE-2024-0002.diff], 'resolves' => [{ 'type' => 'security', 'id' => 'CVE-2024-0001' }] }] }
    stub_request(:get, url).to_return(body: bundle)

    PatchIndex::Homebrew.new(@http).import(['example', '1.0'], 'digest', formula)

    one, named = PatchOccurrence.order(:id).to_a
    assert_equal ['patches/one.diff', 'bundle-1/patches/one.diff', []], [one.name, one.declaration['member'], one.advisory_ids]
    assert_equal [1, 2], [one.position, named.position]
    assert_equal [{ 'type' => 'security', 'id' => 'CVE-2024-0001' }], one.declaration['bundle_resolves']
    assert_equal({ 'CVE-2024-0002' => 'patch_name' }, named.advisory_roles)
  end
end
