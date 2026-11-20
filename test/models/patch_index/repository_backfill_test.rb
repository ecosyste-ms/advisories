require 'test_helper'
require 'rake'
require 'rubygems/package'
require_relative '../../../script/patch_index/catalog_files'

class PatchIndex::RepositoryBackfillTest < ActiveSupport::TestCase
  test 'the repository task maps the source URL stored with a Homebrew release' do
    identity = { distribution: 'homebrew', package_name: 'example', version: '1', revision: '0' }
    metadata = { 'urls' => { 'stable' => { 'url' => 'https://github.com/org/example/archive/v1.tar.gz' } } }
    release = PatchRelease.record!(identity, source_url: 'https://example.org/source', metadata: metadata, component: {}, entries: [])
    load Rails.root.join('lib/tasks/patches.rake') unless Rake::Task.task_defined?('patches:repositories')
    Rake::Task.define_task(:environment) unless Rake::Task.task_defined?(:environment)
    task = Rake::Task['patches:repositories']
    task.reenable
    assert_equal 1, JSON.parse(capture_io { task.invoke }.first).fetch('homebrew')
    assert_equal 'pkg:github/org/example', release.reload.source_repository.fetch('purl')
  end

  test 'the catalog verifies the archive digest and rejects conflicting duplicate members' do
    Dir.mktmpdir do |dir|
      path = Pathname(dir).join('packaging.tar.gz')
      write_archive(path, %w[one one])
      digest = Digest::SHA256.file(path).hexdigest
      assert_equal 'one', CatalogFiles.archive_members(path, digest).fetch('debian/copyright')
      write_archive(path, %w[one two])
      assert_match(/archive checksum mismatch/, assert_raises(IOError) { CatalogFiles.archive_members(path, digest) }.message)
      assert_match(/conflicting archive members/, assert_raises(IOError) { CatalogFiles.archive_members(path, Digest::SHA256.file(path).hexdigest) }.message)
    end
  end

  def write_archive(path, contents)
    tar = StringIO.new(''.b)
    Gem::Package::TarWriter.new(tar) do |writer|
      contents.each { |text| writer.add_file_simple('debian/copyright', 0o644, text.bytesize) { |io| io.write(text) } }
    end
    path.binwrite(Zlib.gzip(tar.string))
  end
end
