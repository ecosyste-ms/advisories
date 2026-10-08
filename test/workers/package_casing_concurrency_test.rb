require 'test_helper'

class PackageCasingConcurrencyTest < ActiveSupport::TestCase
  self.use_transactional_tests = false

  test 'simultaneous sync jobs with different casing create one package' do
    name = "casing-test-#{SecureRandom.hex(8)}"
    ready = Queue.new
    start = Queue.new
    threads = [name, name.upcase].map do |spelling|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready << true
          start.pop
          PackageSyncWorker.new.perform('npm', spelling)
        end
      end
    end
    threads.size.times { ready.pop }
    threads.size.times { start << true }
    threads.each(&:value)

    assert_equal [name], Package.named(name).pluck(:name)
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
    threads&.each(&:join)
    Package.named(name).delete_all if name
  end
end
