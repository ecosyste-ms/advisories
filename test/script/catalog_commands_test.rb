require 'test_helper'
require 'open3'
require_relative '../../script/patch_index/evaluate_nix_channel'

class CatalogCommandsTest < ActiveSupport::TestCase
  test 'conda catalog command reads both repodata sections and respects the package filter' do
    Dir.mktmpdir do |dir|
      row = { name: 'one', version: '1.0', build_number: 0, build: 'abc_0', size: 15 }
      raw = { info: { subdir: 'noarch' }, packages: { 'one.tar.bz2' => row, 'two.tar.bz2' => row.merge(name: 'two') },
        'packages.conda' => { 'one.conda' => row } }
      compressed, status = Open3.capture2('zstd', '-qc', stdin_data: raw.to_json, binmode: true)
      assert_predicate status, :success?
      File.binwrite(File.join(dir, 'noarch.json.zst'), compressed)
      output, status = Open3.capture2(RbConfig.ruby, Rails.root.join('script/patch_index/conda_build_catalog.rb').to_s, dir, 'one')
      assert_predicate status, :success?
      rows = output.lines.map { |l| JSON.parse(l) }
      assert_equal ['one.conda', 'one.tar.bz2'], rows.map { |r| File.basename(r.fetch('archive_url')) }
      assert rows.all? { |r| r.fetch('subdir') == 'noarch' && r.fetch('name') == 'one' }
    end
  end

  test 'Nix checkpoints include only published outputs and record evaluation failures separately' do
    Dir.mktmpdir do |dir|
      root = Pathname(dir)
      root.join('.git-revision').write('a' * 40)
      stores = root.join('store-paths.xz').to_s
      manifest, ok = Open3.capture2('xz', '-c', stdin_data: "/nix/store/published\n", binmode: true)
      assert_predicate ok, :success?
      File.binwrite(stores, manifest)
      builds = [{ 'attr' => 'a', 'output' => '/nix/store/published' }, { 'attr' => 'b', 'output' => '/nix/store/other' },
        { 'attr' => 'c', 'error' => 'evaluation failed' }]
      PublishedNix.expects(:evaluate).once.returns(builds)
      2.times do
        capture_io { PublishedNix.run(dir, nil, stores, dir, systems: ['x86_64-linux'], packages: %w[a b c]) }
      end
      result = JSON.parse(root.glob('*/*/*.json').sole.read)
      assert_equal [builds.first], result.fetch('builds')
      assert_equal 1, result.fetch('unpublished')
      assert_equal ['c'], result.fetch('errors')
      assert_equal 3, result.fetch('examined')
    end
  end
end
