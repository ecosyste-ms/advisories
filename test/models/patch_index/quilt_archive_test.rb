require 'test_helper'
require 'rubygems/package'

class PatchIndex::QuiltArchiveTest < ActiveSupport::TestCase
  def archive(files, links = {})
    buffer = StringIO.new(''.b)
    Gem::Package::TarWriter.new(buffer) do |tar|
      files.each { |name, content| tar.add_file_simple(name, 0o644, content.bytesize) { |file| file.write(content) } }
      links.each { |name, target| tar.add_symlink(name, target, 0o777) }
    end
    file = Tempfile.create(['packaging', '.tar.gz'], binmode: true)
    file.write(Zlib.gzip(buffer.string))
    file.close
    file.path
  end

  test 'series entries keep their order and options, follow member links and skip comments' do
    path = archive({ 'debian/patches/series' => "# header\n./first.patch -p0 # note\nlinked.patch\n", 'debian/patches/first.patch' => 'one',
      'debian/patches/shared/real.patch' => 'two', 'debian/patches/unlisted.patch' => 'three',
      'debian/changelog' => 'example (1-1) unstable', 'debian/copyright' => "Source: https://github.com/example/project\n" },
      { 'debian/patches/linked.patch' => 'shared/real.patch' })

    quilt = PatchIndex::QuiltArchive.new(path, vendor: 'debian')

    assert_equal [['first.patch', ['-p0'], 'one'], ['linked.patch', [], 'two']], quilt.patches
    assert_equal 'debian/patches/series', quilt.series_path
    assert_equal 'example (1-1) unstable', quilt.changelog
    assert_equal ['debian/copyright'], quilt.metadata.keys
  end

  test 'a patch with a non-ASCII name is found through the series and through a link' do
    path = archive({ 'debian/patches/series' => "fürther.patch\nlinked.patch\n", 'debian/patches/fürther.patch' => 'one' },
      { 'debian/patches/linked.patch' => 'fürther.patch' })
    assert_equal [['fürther.patch', [], 'one'], ['linked.patch', [], 'one']], PatchIndex::QuiltArchive.new(path, vendor: 'debian').patches
  end

  test 'a vendor series wins and a series that escapes the archive or repeats a patch is rejected' do
    vendor = archive({ 'debian/patches/series' => "a.patch\n", 'debian/patches/debian.series' => "b.patch\n",
      'debian/patches/a.patch' => 'a', 'debian/patches/b.patch' => 'b' })
    assert_equal [['b.patch', [], 'b']], PatchIndex::QuiltArchive.new(vendor, vendor: 'debian').patches
    assert_equal [['a.patch', [], 'a']], PatchIndex::QuiltArchive.new(vendor, vendor: 'ubuntu').patches

    outside = archive({ 'debian/patches/series' => "a.patch\n" }, { 'debian/patches/a.patch' => '../../../etc/passwd' })
    assert_raises(IOError) { PatchIndex::QuiltArchive.new(outside, vendor: 'debian').patches }

    repeated = archive({ 'debian/patches/series' => "a.patch\na.patch\n", 'debian/patches/a.patch' => 'a' })
    assert_raises(IOError) { PatchIndex::QuiltArchive.new(repeated, vendor: 'debian').patches }

    linked = archive({ 'debian/patches/series' => '' }, { 'debian/patches' => '../elsewhere' })
    assert_raises(IOError) { PatchIndex::QuiltArchive.new(linked, vendor: 'debian') }
  end
end
