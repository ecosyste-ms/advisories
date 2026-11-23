FactoryBot.define do
  factory :patch do
    transient do
      contents { "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+new #{SecureRandom.hex(4)}\n" }
    end
    sha256 { Digest::SHA256.hexdigest(contents) }
    byte_size { contents.bytesize }
    headers { {} }
    after(:create) { |patch, evaluator| PatchBody.store!(patch.sha256, evaluator.contents) }
  end

  factory :patch_release do
    distribution { 'debian' }
    sequence(:package_name) { |n| "package#{n}" }
    version { '1.0-1' }
    upstream_version { '1.0' }
    source_url { "https://deb.debian.org/debian/pool/main/p/#{package_name}/#{package_name}_#{version}.debian.tar.xz" }
    imported_at { Time.current }
  end

  factory :patch_occurrence do
    patch
    patch_release
    sequence(:name) { |n| "fix-#{n}.patch" }
    position { 1 }
    source_url { patch_release.source_url }
  end
end
