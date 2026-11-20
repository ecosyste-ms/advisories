require 'test_helper'
require_relative '../../../script/patch_index/indexed_bodies'

class PatchIndex::IndexedBodiesTest < ActiveSupport::TestCase
  test 'body audit checks the original bytes before retaining and on replay' do
    bytes = "diff bytes\xff\r\n".b
    digest = Digest::SHA256.hexdigest(bytes)
    url = 'https://example.org/pinned/formula.rb'
    entry = PatchIndex::Document.new(bytes, strip: 1).entry(name: 'DATA', source_url: url, declaration: { 'data' => true })
    PatchRelease.record!({ distribution: 'homebrew', package_name: 'example', version: '1', revision: '0' },
      source_url: url, metadata: {}, component: {}, entries: [entry])

    Dir.mktmpdir do |tmp|
      cache = Pathname.new(tmp)
      http = PatchIndex::Http.new(cache: ActiveSupport::Cache::NullStore.new, interval: 0)
      audit = IndexedBodies.new(catalog: cache.join('catalog'), cache: cache, http: http)
      assert_equal 1, audit.verify[:missing]
      stub_request(:get, url).to_return(body: "__END__\nother")
      assert_raises(IOError) { audit.verify(fetch: true) }
      refute cache.join(digest).exist?
      stub_request(:get, url).to_return(body: "__END__\r\n".b + bytes)
      assert_equal({ verified: 1, bytes: bytes.bytesize, missing: 0 }, audit.verify(fetch: true))
      assert_equal bytes, cache.join(digest).binread
      PatchBody.find(digest).delete
      assert_equal 1, audit.verify(store: true)[:verified]
      assert_equal bytes, PatchBody.find(digest).contents
      assert_raises(PG::CheckViolation) do
        PatchBody.transaction(requires_new: true) { PatchBody.store!(digest, 'wrong bytes') }
      end
      assert_equal bytes, PatchBody.find(digest).contents
      assert_equal 0, audit.verify(store: true)[:verified]
      cache.join(digest).binwrite('corrupt')
      assert_raises(IOError) { audit.verify }
    end
  end
end
