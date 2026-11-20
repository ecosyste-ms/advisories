require 'test_helper'

class PatchIndex::NixBuildTest < ActionDispatch::IntegrationTest
  test 'only published evaluated outputs contribute declarations and repeat imports reuse the build' do
    Dir.mktmpdir do |root|
      path = 'pkgs/example.patch'
      FileUtils.mkdir_p(File.join(root, 'pkgs'))
      bytes = file_fixture('patch_index/conda_nix/script-dir.patch').binread
      File.binwrite(File.join(root, path), bytes)
      File.write(File.join(root, '.git-revision'), 'a' * 40)
      output = '/nix/store/build-example'
      row = { 'pname' => 'example', 'version' => '1.0', 'attr' => 'example', 'system' => 'aarch64-linux',
        'output' => output, 'derivation' => '/nix/store/hash-example.drv', 'patches' => ["/release/#{path}"] }
      importer = PatchIndex::NixBuild.new(root: root, published: [output], release_url: 'https://example.org/release')
      assert_raises(IOError) { importer.import(row.merge('output' => '/nix/store/other')) }
      2.times { importer.import(row) }
      get api_v1_patches_path, params: { distribution: 'nixpkgs' }
      assert_response :success
      patch = response.parsed_body.sole
      assert_equal Digest::SHA256.hexdigest(bytes), patch['sha256']
      evidence = patch.fetch('occurrences').sole.fetch('declaration')
      assert_equal [output, 'aarch64-linux', 1], evidence.values_at('output', 'system', 'position')
      assert_nil patch.fetch('occurrences').sole.dig('assertions', 'verified')
    end
  end
end
