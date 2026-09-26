require "test_helper"

class PackageSyncWorkerTest < ActiveSupport::TestCase
  test "caches affected versions while another range check evicts parser entries" do
    Sidekiq::Testing.fake! do
      create(:registry, name: "npmjs.org", ecosystem: "npm")
      package = create(:package, ecosystem: "npm", name: "@clerk/vue", version_numbers: [])
      advisory = create(:advisory, packages: [{
        "ecosystem" => "npm",
        "package_name" => package.name,
        "versions" => [{ "vulnerable_version_range" => ">= 1.0.0, < 2.0.0" }]
      }])
      versions = ["0.9.0", "1.0.0", "1.5.0", "2.0.0"]
      stub_request(:get, package.packages_api_url)
        .to_return(status: 200, body: { versions_count: versions.size }.to_json,
          headers: { "Content-Type" => "application/json" })
      stub_request(:get, "#{package.packages_api_url}/version_numbers")
        .to_return(status: 200, body: versions.to_json,
          headers: { "Content-Type" => "application/json" })

      cache = Vers::Parser.class_variable_get(:@@parser_cache)
      saved_cache = cache.dup
      cache.clear
      package.version_satisfies_range?("1.5.0", ">= 1.0.0, < 2.0.0", "npm")
      limit = Vers::Parser.class_variable_get(:@@cache_size_limit)
      (limit - cache.size).times do |i|
        package.version_satisfies_range?("1.5.0", "= #{i + 10}.0.0", "npm")
      end

      start = Queue.new
      running = Queue.new
      competitor = Thread.new do
        start.pop
        running << true
        advisory.version_satisfies_range?("1.5.0", "= 9999.0.0", "npm")
      end

      interrupted = false
      trace = TracePoint.new(:c_return) do |event|
        next unless event.method_id == :key? && event.self.equal?(cache) && event.return_value

        trace.disable
        interrupted = true
        start << true
        running.pop
        # Resume once the competing lookup finishes or blocks on the shared lock.
        Thread.pass while competitor.status == "run"
      end

      trace.enable(target_thread: Thread.current) do
        PackageSyncWorker.new.perform("npm", package.name)
      end
      competitor.value

      assert interrupted, "Expected to interrupt a parser cache hit"
      cached = advisory.reload.packages.first
      assert_equal ["1.0.0", "1.5.0"], cached["affected_versions"]
      assert_equal ["0.9.0", "2.0.0"], cached["unaffected_versions"]
      assert_equal versions, package.reload.version_numbers
      assert_equal 1, package.advisories_count
    ensure
      trace&.disable
      competitor&.kill
      competitor&.join
      cache&.replace(saved_cache) if saved_cache
    end
  end
end
