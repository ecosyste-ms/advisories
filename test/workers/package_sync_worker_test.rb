require "test_helper"

class PackageSyncWorkerTest < ActiveSupport::TestCase
  test "sync jobs do not insert packages with blank identities" do
    assert_no_difference 'Package.count' do
      [['npm', ''], [nil, 'widget']].each do |ecosystem, name|
        assert_raises(ArgumentError) { PackageSyncWorker.new.perform(ecosystem, name) }
      end
    end
  end

  test "reuses a legacy mixed-case package and refreshes advisory version caches" do
    Sidekiq::Testing.fake! do
      create(:registry, name: 'nuget.org', ecosystem: 'nuget')
      package = create(:package, ecosystem: 'nuget', name: 'microsoft.chakracore', version_numbers: [])
      package.update_columns(name: 'Microsoft.ChakraCore')
      advisory = create(:advisory, packages: [{
        'ecosystem' => 'nuget', 'package_name' => 'MICROSOFT.CHAKRACORE',
        'versions' => [{ 'vulnerable_version_range' => '< 2.0.0' }]
      }])
      stub_request(:get, package.packages_api_url)
        .to_return(status: 200, body: { versions_count: 2, dependent_packages_count: 10 }.to_json,
          headers: { 'Content-Type' => 'application/json' })
      stub_request(:get, "#{package.packages_api_url}/version_numbers")
        .to_return(status: 200, body: ['1.0.0', '2.0.0'].to_json,
          headers: { 'Content-Type' => 'application/json' })

      assert_no_difference 'Package.count' do
        PackageSyncWorker.new.perform('NuGet', 'microsoft.chakracore')
      end

      assert_equal 'Microsoft.ChakraCore', package.reload.name
      assert_equal 1, package.advisories_count
      assert_equal ['1.0.0'], advisory.reload.packages.first['affected_versions']
      assert_equal 10, advisory.packages.first.dig('statistics', 'dependent_packages_count')
    end
  end

  test "case variants in sync jobs create one package" do
    Sidekiq::Testing.fake! do
      assert_difference 'Package.count', 1 do
        %w[OpenClaw openclaw Openclaw].each do |name|
          PackageSyncWorker.new.perform('npm', name)
        end
      end
      assert_equal ['openclaw'], Package.named('OpenClaw').pluck(:name)
    end
  end

  test "sync jobs preserve distinct names in other ecosystems" do
    Sidekiq::Testing.fake! do
      assert_difference 'Package.count', 2 do
        %w[github.com/Owner/Widget github.com/owner/widget].each do |name|
          PackageSyncWorker.new.perform('go', name)
        end
      end
    end
  end

  test "syncing existing duplicates consistently reuses the oldest row without renaming them" do
    Sidekiq::Testing.fake! do
      keeper = create(:package, ecosystem: 'npm', name: 'openclaw', last_synced_at: Time.current)
      duplicate = create(:package, ecosystem: 'npm', name: 'legacy-openclaw', last_synced_at: Time.current)
      duplicate.update_columns(name: 'OpenClaw', advisories_count: 123)

      assert_no_difference 'Package.count' do
        PackageSyncWorker.new.perform('npm', 'OpenClaw')
      end
      assert_equal 0, keeper.reload.advisories_count
      assert_equal 123, duplicate.reload.advisories_count
      assert_equal 'OpenClaw', duplicate.name
    end
  end

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
