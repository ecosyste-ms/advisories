require 'test_helper'

class PatchIndex::DistributionReleaseTest < ActionDispatch::IntegrationTest
  test 'verified RPM members are discoverable by source with their original declaration' do
    Dir.mktmpdir do |tmp|
      directory = Pathname.new(tmp)
      directory.join('blobs').mkpath
      patch = "Subject: Update link flags\n--- a/build\n+++ b/build\n@@ -1 +1 @@\n-old\n+new\n"
      sha = Digest::SHA256.hexdigest(patch)
      file = directory.join('blobs', sha)
      file.binwrite(patch)
      row = { 'name' => 'link.patch', 'sha256' => sha, 'line' => 37, 'spec' => 'demo.spec', 'declaration' => 'Patch1: link.patch' }
      release = { 'source' => 'Fedora', 'package' => 'demo', 'version' => '1.0-2.fc44', 'suite' => '44', 'url' => 'https://example.org/demo.src.rpm',
        'sha256' => 'b' * 64, 'declarations' => [row] }
      importer = PatchIndex::DistributionRelease.new(directory)
      2.times { importer.import(release) }
      file.binwrite('different')
      assert_raises(IOError) { importer.import(release) }
      get api_v1_patches_path, params: { distribution: 'Fedora' }
      assert_response :success
      document = response.parsed_body.sole
      assert_equal sha, document.fetch('sha256')
      occurrence = document.fetch('occurrences').sole
      assert_equal 37, occurrence.dig('declaration', 'line')
      assert_equal 'demo.spec', occurrence.dig('declaration', 'spec')
      assert_equal '2.fc44', occurrence.dig('downstream', 'revision')
      assert_nil occurrence.fetch('purl')
    end
  end
end
