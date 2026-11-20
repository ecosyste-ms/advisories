require 'test_helper'
require 'open3'

class PatchIndex::CondaMetadataTest < ActiveSupport::TestCase
  def serve(bytes, extension, status: 206, etag: nil)
    name = 'bzip2-1.0.8-hda65f42_10'
    url = "https://conda.anaconda.org/conda-forge/linux-64/#{name}.#{extension}"
    md5 = Digest::MD5.hexdigest(bytes)
    @ranges = []
    stub_request(:get, url).to_return do |request|
      first, last = request.headers.fetch('Range').delete_prefix('bytes=').split('-').map(&:to_i)
      @ranges << (first..last)
      { status: status, body: bytes.byteslice(first..last),
        headers: { 'Content-Range' => "bytes #{first}-#{last}/#{bytes.bytesize}", 'ETag' => etag || %("#{md5}") } }
    end
    { 'name' => 'bzip2', 'version' => '1.0.8', 'build' => 'hda65f42_10', 'build_number' => 10, 'subdir' => 'linux-64',
      'archive_url' => url, 'size' => bytes.bytesize, 'md5' => md5 }
  end

  def metadata
    name = 'info-bzip2-1.0.8-hda65f42_10.tar.zst'
    bytes, status = Open3.capture2('bsdtar', '-xOf', file_fixture('patch_index/conda_nix/bzip2.conda').to_s, '--', name, binmode: true)
    assert_predicate status, :success?
    [name, bytes]
  end

  test 'a published build is indexed from a single suffix request including the recipe and patches' do
    Dir.mktmpdir do |dir|
      root = Pathname(dir)
      name, info = metadata
      root.join(name).binwrite(info)
      root.join('pkg.tar.zst').binwrite('a' * 500000)
      archive = root.join('build.conda')
      system('bsdtar', '--format', 'zip', '--options', 'zip:compression=store', '-cf', archive.to_s, '-C', dir,
        'pkg.tar.zst', name, exception: true)
      pin = serve(archive.binread, 'conda')
      importer = PatchIndex::Conda.new
      release = importer.import_build(pin, max_bytes: 8192)
      assert_equal 3, release.patch_occurrences.count
      assert_equal 'archive_byte_ranges', release.metadata.fetch('verification')
      assert_equal [((archive.size - 8192)..(archive.size - 1))], @ranges
      assert_equal 8192, importer.transferred
    end
  end

  test 'legacy bzip2 tar reads reject over-budget and unvalidated responses before recording a release' do
    _, info = metadata
    bytes, status = Open3.capture2('bsdtar', '-cjf', '-', '@-', stdin_data: info, binmode: true)
    assert_predicate status, :success?
    importer = PatchIndex::Conda.new
    pin = serve(bytes, 'tar.bz2', status: 200)
    assert_match(/byte range/, assert_raises(IOError) { importer.import_build(pin, max_bytes: bytes.size) }.message)
    pin = serve(bytes, 'tar.bz2', etag: 'W/"partial"')
    assert_match(/validator/, assert_raises(IOError) { importer.import_build(pin, max_bytes: bytes.size) }.message)
    pin = serve(bytes, 'tar.bz2')
    assert_match(/budget/, assert_raises(IOError) { importer.import_build(pin, max_bytes: 1) }.message)
    assert_equal 1, importer.transferred
    assert_empty PatchRelease.all
    assert_equal 3, importer.import_build(pin, max_bytes: bytes.size).patch_occurrences.size
  end
end
