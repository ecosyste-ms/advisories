require 'test_helper'
require 'rubygems/package'
require_relative '../../script/patch_index/distribution_archives'

class DistributionArchivesTest < ActiveSupport::TestCase
  def add(writer, path, bytes)
    writer.add_file_simple(path, 0o644, bytes.bytesize) { |io| io.write(bytes) }
  end

  test 'Ubuntu series resolves a linked member and preserves options, line numbers and exact bytes' do
    Dir.mktmpdir do |dir|
      root = Pathname(dir)
      bytes = "payload\xff\r\n".b
      tar = StringIO.new(''.b)
      Gem::Package::TarWriter.new(tar) do |writer|
        add(writer, 'debian/copyright', "Source: https://example.org/upstream\n\nSource: vendor\n")
        add(writer, 'debian/patches/series', "# comment\nfix#1.patch -p0 # option\n")
        add(writer, 'debian/patches/original', bytes)
        writer.add_symlink('debian/patches/fix#1.patch', 'original', 0o777)
      end
      archive = Zlib.gzip(tar.string)
      sha = Digest::SHA256.hexdigest(archive)
      root.join(sha).binwrite(archive)
      row = { 'sha256' => sha, 'source' => 'Ubuntu' }
      declaration = DistributionArchives.collect([row], root, fetch: false).sole.fetch(:declarations).sole
      assert_equal 'debian/patches/fix#1.patch', declaration.fetch(:name)
      assert_equal 2, declaration.fetch(:series_line)
      assert_equal ['-p0'], declaration.fetch(:options)
      assert_equal bytes, root.join('blobs', declaration.fetch(:sha256)).binread
      reader = PatchIndex::QuiltArchive.new(root.join('members'))
      assert_equal "Source: https://example.org/upstream\n", reader.extract(root.join(sha), sha).dig('repository_files', 'debian/copyright')
      root.join(sha).binwrite('corrupt')
      assert_raises(IOError) { DistributionArchives.collect([row], root, fetch: false) }
    end
  end

  test 'Fedora spec declarations name the exact source archive member' do
    Dir.mktmpdir do |dir|
      tar = StringIO.new(''.b)
      Gem::Package::TarWriter.new(tar) do |writer|
        add(writer, 'demo.spec', "Name: demo\nPatch42: https://example.org/%{name}.patch\n")
        add(writer, 'demo.patch', "original\xff".b)
        add(writer, 'unused.patch', 'unused')
      end
      sha = Digest::SHA256.hexdigest(tar.string)
      root = Pathname(dir)
      root.join(sha).binwrite(tar.string)
      row = { 'sha256' => sha, 'source' => 'Fedora', 'package' => 'demo' }
      entry = DistributionArchives.collect([row], root, fetch: false).sole.fetch(:declarations).sole
      assert_equal ['demo.patch', 2, 'demo.spec'], entry.values_at(:name, :line, :spec)
      assert_equal "original\xff".b, root.join('blobs', entry.fetch(:sha256)).binread
    end
  end
end
