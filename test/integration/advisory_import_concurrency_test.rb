require 'test_helper'
require 'zip'
require_relative '../support/advisory_import_helpers'

class AdvisoryImportConcurrencyTest < ActiveSupport::TestCase
  include AdvisoryImportHelpers
  self.use_transactional_tests = false

  test 'concurrent source syncs publish one advisory and retain both source records' do
    sources = [create(:source, kind: 'github'), create(:source, kind: 'osv')]
    stub_github([github_edge])
    stub_osv([osv_record('PYSEC-TEST-1', aliases: ['GHSA-test-aaaa'])])
    ready = Queue.new
    start = Queue.new
    threads = sources.map do |source|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          Sidekiq::Testing.fake! do
            ready << true
            start.pop
            3.times { Source.find(source.id).sync_advisories }
          end
        end
      end
    end
    2.times { ready.pop }
    2.times { start << true }
    threads.each(&:value)
    records = AdvisoryRecord.where(source: sources)
    assert_equal 2, records.count
    assert_equal 1, records.distinct.count(:advisory_id)
    assert_equal 1, Advisory.where(source: sources).count
    advisory = records.first.advisory
    assert_equal 'GSA_test', advisory.uuid
    assert_equal sources.first.id, advisory.source_id
    assert_includes advisory.identifiers, 'PYSEC-TEST-1'
    assert_equal 0.42, advisory.epss_percentage
  ensure
    threads&.each { |thread| thread.join if thread.alive? }
    if sources
      ids = Advisory.where(source: sources).pluck(:id)
      AdvisoryRecord.where(source: sources).delete_all
      RelatedPackage.where(advisory_id: ids).delete_all
      Advisory.where(id: ids).delete_all
      Source.where(id: sources.map(&:id)).delete_all
    end
  end
end
