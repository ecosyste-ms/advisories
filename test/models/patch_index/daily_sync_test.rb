require 'test_helper'
require 'open3'
require 'rubygems/package'
require 'rake'

class PatchIndex::DailySyncTest < ActiveSupport::TestCase
  setup do
    @http = PatchIndex::Http.new(cache: ActiveSupport::Cache::NullStore.new, interval: 0)
    @bytes = Rails.root.join('test/fixtures/files/patch_index/relax-dep.patch').binread
    @apt = PatchIndex::AptCatalog
    @empty_index = compress('')
  end

  def compress(text)
    result, status = Open3.capture2('xz', '-c', stdin_data: text, binmode: true)
    assert status.success?
    result
  end

  def archive(series, vendor_series: nil)
    buf = StringIO.new(''.b)
    Gem::Package::TarWriter.new(buf) do |tar|
      { 'series' => series, 'ubuntu.series' => vendor_series, 'fix.patch' => @bytes }.compact.each do |name, content|
        tar.add_file_simple("debian/patches/#{name}", 0o644, content.bytesize) { |f| f.write(content) }
      end
    end
    Zlib.gzip(buf.string)
  end

  def apt_record(package, version, data)
    <<~APT
      Package: #{package}
      Format: 3.0 (quilt)
      Version: #{version}
      Directory: pool/main/e/example
      Homepage: https://github.com/example/project
      Checksums-Sha256:
       #{Digest::SHA256.hexdigest(data)} #{data.bytesize} #{package}_#{version}.debian.tar.gz

    APT
  end

  def apt_indexes(source, catalogs)
    @apt::POCKETS.fetch(source).each do |base, suite|
      @apt::COMPONENTS.fetch(source).each do |component|
        bytes = catalogs.key?([suite, component]) ? compress(catalogs.fetch([suite, component])) : @empty_index
        stub_request(:get, "#{base}/dists/#{suite}/#{component}/source/Sources.xz").to_return(body: bytes)
      end
    end
  end

  test 'scheduled Debian rake discovers releases, resumes the backlog and keeps past revisions' do
    archive_bytes = archive("fix.patch -p1\n")
    current = apt_record('example', '1-2', archive_bytes)
    older = apt_record('example', '1-1', archive_bytes)
    apt_indexes('debian', { ['trixie-updates', 'main'] => current, ['trixie', 'main'] => current + older })
    requests = %w[1-2 1-1].map do |version|
      stub_request(:get, "#{@apt::DEBIAN}/pool/main/e/example/example_#{version}.debian.tar.gz").to_return(body: archive_bytes)
    end
    load Rails.root.join('lib/tasks/patches.rake') unless Rake::Task.task_defined?('patches:sync:debian')
    Rake::Task.define_task(:environment) unless Rake::Task.task_defined?(:environment)
    task = Rake::Task['patches:sync:debian']
    old_limit = ENV['PATCH_SYNC_LIMIT']
    ENV['PATCH_SYNC_LIMIT'] = '1'
    PatchIndex::Http.stubs(:new).returns(@http)
    stats = 3.times.map do
      task.reenable
      JSON.parse(capture_io { task.invoke }.first)
    end
    assert_equal [1, 1, 0], stats.pluck('imported')
    assert_equal [1, 0, 0], stats.pluck('deferred')
    assert_equal 2, stats.last.fetch('unchanged')
    assert_equal %w[1-1 1-2], PatchRelease.order(:version).pluck(:version)
    assert_equal 2, PatchOccurrence.count
    assert_equal 1, Patch.count
    assert_equal 'pkg:github/example/project', PatchRelease.first.source_repository.fetch('purl')
    assert_equal ['-p1'], PatchOccurrence.first.declaration.fetch('quilt_options')
    requests.each { |request| assert_requested(request, times: 1) }
  ensure
    ENV['PATCH_SYNC_LIMIT'] = old_limit
  end

  test 'Ubuntu retries a failed archive without removing claims and uses the Ubuntu series' do
    base = @apt::UBUNTU
    sync = PatchIndex::DailySync.new('ubuntu', http: @http)
    url = "#{base}/pool/main/e/example/example_1-1.debian.tar.gz"
    initial = archive("missing.patch\n", vendor_series: "fix.patch\n")
    apt_indexes('ubuntu', { ['noble-security', 'universe'] => apt_record('example', '1-1', initial) })
    stub_request(:get, url).to_return(body: initial)
    assert_equal 1, sync.run[:imported]
    occurrence = PatchOccurrence.sole
    assert_equal 'debian/patches/ubuntu.series', occurrence.declaration['series_path']
    changed = archive('')
    apt_indexes('ubuntu', { ['noble-security', 'universe'] => apt_record('example', '1-1', changed) })
    _, err = capture_io { assert_equal 1, sync.run[:failed] }
    assert_match(/SHA-256 mismatch/, err)
    assert_equal occurrence.id, PatchOccurrence.sole.id
    incomplete = archive("missing.patch\n")
    apt_indexes('ubuntu', { ['noble-security', 'universe'] => apt_record('example', '1-1', incomplete) })
    stub_request(:get, url).to_return(body: incomplete)
    _, err = capture_io { assert_equal 1, sync.run[:failed] }
    assert_match(/missing patch bytes/, err)
    assert_equal occurrence.id, PatchOccurrence.sole.id
    apt_indexes('ubuntu', { ['noble-security', 'universe'] => apt_record('example', '1-1', changed) })
    stub_request(:get, url).to_return(body: changed)
    assert_equal 1, sync.run[:imported]
    assert_empty PatchOccurrence.all
    assert_equal 1, sync.run[:unchanged]
  end

  test 'Homebrew imports changed defaults, skips unrelated tap commits and records a removal' do
    http_url = 'https://formulae.brew.sh/api/formula.json'
    formula = { name: 'example', tap: 'homebrew/core', tap_git_head: '1' * 40, revision: 0, versions: { stable: '1.0' },
      variations: {}, ruby_source_path: 'Formula/e/example.rb', ruby_source_checksum: { sha256: '2' * 64 },
      urls: { stable: { url: 'https://example.org/src.tar.gz' } }, patches: [{ strip: 'p1', file: 'Patches/e.patch' }],
      local_patch_checksums: { 'Patches/e.patch' => Digest::SHA256.hexdigest(@bytes) } }
    publish = -> { stub_request(:get, http_url).to_return(body: [formula, formula.merge(name: 'empty', patches: [])].to_json) }
    publish.call
    request = stub_request(:get, "https://raw.githubusercontent.com/Homebrew/homebrew-core/#{'1' * 40}/Patches/e.patch").to_return(body: @bytes)
    sync = PatchIndex::DailySync.new('homebrew', http: @http)
    assert_equal 1, sync.run[:imported]
    formula[:tap_git_head] = '3' * 40
    publish.call
    assert_equal 1, sync.run[:unchanged]
    assert_equal Digest::SHA256.hexdigest(@bytes), PatchOccurrence.sole.patch.sha256
    formula[:patches] = []
    publish.call
    assert_equal 1, sync.run[:imported]
    assert_equal 1, PatchRelease.count
    assert_empty PatchOccurrence.all
    assert_requested request, times: 1
  end
end
