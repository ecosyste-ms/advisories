require "test_helper"

class AdvisoryTest < ActiveSupport::TestCase
  context ".ecosystem_counts" do
    should "return ecosystem counts sorted by count descending" do
      # Create advisories with different ecosystems
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "package1", "versions" => [] },
        { "ecosystem" => "rubygems", "package_name" => "package2", "versions" => [] }
      ])
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "package3", "versions" => [] }
      ])
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "package4", "versions" => [] }
      ])
      create(:advisory, withdrawn_at: Time.current, packages: [
        { "ecosystem" => "npm", "package_name" => "package5", "versions" => [] }
      ])

      result = Advisory.not_withdrawn.ecosystem_counts

      assert_equal [["npm", 3], ["rubygems", 1]], result
    end

    should "count ecosystems correctly when advisory has multiple packages" do
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "package1", "versions" => [] },
        { "ecosystem" => "npm", "package_name" => "package2", "versions" => [] },
        { "ecosystem" => "rubygems", "package_name" => "package3", "versions" => [] }
      ])

      result = Advisory.ecosystem_counts

      assert_equal [["npm", 2], ["rubygems", 1]], result
    end
  end

  context ".package_counts" do
    should "return package counts sorted by count descending" do
      # Create advisories with different packages
      package1 = { "ecosystem" => "npm", "package_name" => "lodash", "versions" => [] }
      package2 = { "ecosystem" => "npm", "package_name" => "express", "versions" => [] }

      create(:advisory, packages: [package1])
      create(:advisory, packages: [package1, package2])
      create(:advisory, packages: [package2])

      result = Advisory.package_counts

      # Both packages should have count of 2 (they're both used twice)
      assert_equal 2, result.length
      assert_equal 2, result[0][1]
      assert_equal 2, result[1][1]
      
      # Verify the packages are correct (order might vary for same count)
      package_names = result.map { |r| r[0]["package_name"] }
      assert_includes package_names, "lodash"
      assert_includes package_names, "express"
    end

    should "exclude versions from package data" do
      package_with_versions = {
        "ecosystem" => "npm",
        "package_name" => "test",
        "versions" => [{ "vulnerable_version_range" => "< 1.0.0" }]
      }
      create(:advisory, packages: [package_with_versions])

      result = Advisory.package_counts

      assert_equal 1, result.length
      assert_equal({ "ecosystem" => "npm", "package_name" => "test" }, result[0][0])
      assert_nil result[0][0]["versions"]
    end

    should "exclude withdrawn advisories when called on not_withdrawn scope" do
      package = { "ecosystem" => "npm", "package_name" => "test", "versions" => [] }
      create(:advisory, packages: [package])
      create(:advisory, withdrawn_at: Time.current, packages: [package])

      result = Advisory.not_withdrawn.package_counts

      assert_equal [[package.except("versions"), 1]], result
    end
  end

  context "#ping_packages_for_resync" do
    should "ping packages.ecosyste.ms for each package when advisory is created" do
      # Create registries for the ecosystems
      create(:registry, name: "npmjs.org", ecosystem: "npm")
      create(:registry, name: "rubygems.org", ecosystem: "rubygems")
      
      # Stub package sync requests (called by sync_packages callback)
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+})
        .to_return(status: 200, body: {}.to_json, headers: {'Content-Type' => 'application/json'})
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/version_numbers})
        .to_return(status: 200, body: [].to_json, headers: {'Content-Type' => 'application/json'})
      
      # Stub the ping HTTP request to packages.ecosyste.ms
      stub_request(:post, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/ping})
        .to_return(status: 200, body: "", headers: {})

      source = create(:source)
      advisory = build(:advisory, source: source, packages: [
        { "ecosystem" => "npm", "package_name" => "lodash", "versions" => [] },
        { "ecosystem" => "rubygems", "package_name" => "rails", "versions" => [] }
      ])

      # Creating the advisory should trigger the ping
      advisory.save!

      # Verify the requests were made
      assert_requested :post, "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages/lodash/ping"
      assert_requested :post, "https://packages.ecosyste.ms/api/v1/registries/rubygems.org/packages/rails/ping"
    end

    should "ping packages.ecosyste.ms for each package when advisory is updated" do
      # Create registry for npm ecosystem  
      create(:registry, name: "npmjs.org", ecosystem: "npm")
      
      # Stub package sync requests (called by sync_packages callback)
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+})
        .to_return(status: 200, body: {}.to_json, headers: {'Content-Type' => 'application/json'})
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/version_numbers})
        .to_return(status: 200, body: [].to_json, headers: {'Content-Type' => 'application/json'})
      
      # Stub the ping HTTP request to packages.ecosyste.ms
      stub_request(:post, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/ping})
        .to_return(status: 200, body: "", headers: {})

      advisory = create(:advisory)

      # Updating the advisory should trigger the ping
      advisory.update!(title: "Updated title")

      # Verify the request was made for the default test package (2 times: once for create, once for update)
      assert_requested :post, "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages/test-package/ping", times: 2
    end

    should "handle ping failures gracefully" do
      # Create registry for npm ecosystem  
      create(:registry, name: "npmjs.org", ecosystem: "npm")
      
      # Stub package sync requests (called by sync_packages callback)
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+})
        .to_return(status: 200, body: {}.to_json, headers: {'Content-Type' => 'application/json'})
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/version_numbers})
        .to_return(status: 200, body: [].to_json, headers: {'Content-Type' => 'application/json'})
      
      # Stub the ping HTTP request to fail
      stub_request(:post, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/ping})
        .to_raise(StandardError.new("Network error"))

      # Should not raise an error
      assert_nothing_raised do
        create(:advisory)
      end
    end
  end

  context ".ecosystem scope" do
    should "match ecosystems case insensitively" do
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "test1", "versions" => [] }
      ])
      create(:advisory, packages: [
        { "ecosystem" => "rubygems", "package_name" => "test2", "versions" => [] }
      ])

      npm_results = Advisory.ecosystem("NPM")  # Input is uppercase
      rubygems_results = Advisory.ecosystem("RUBYGEMS")  # Input is uppercase

      assert_equal 1, npm_results.count
      assert_equal 1, rubygems_results.count
    end

    should "match exact case as well" do
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "test1", "versions" => [] }
      ])

      results = Advisory.ecosystem("npm")
      assert_equal 1, results.count
    end
  end

  context ".package_name scope" do
    should "match package names case insensitively" do
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "LODASH", "versions" => [] }
      ])
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "express", "versions" => [] }
      ])

      lodash_results = Advisory.package_name("lodash")
      express_results = Advisory.package_name("EXPRESS")

      assert_equal 1, lodash_results.count
      assert_equal 1, express_results.count
    end

    should "match exact case as well" do
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "test-package", "versions" => [] }
      ])

      results = Advisory.package_name("test-package")
      assert_equal 1, results.count
    end
  end

  context "#affected_versions" do
    should "return original invalid versions that match the range after normalization" do
      package = { "ecosystem" => "nuget", "package_name" => "Mammoth" }
      advisory = build(:advisory, packages: [package])

      # Stub version_numbers to return versions including ones with extra dots
      versions = ["1.6.0", "1.7.0-alpha.2", "1.7.0-alpha.3", "1.10.0", "1.11.0", "1.12.0"]
      advisory.stubs(:version_numbers).returns(versions)

      affected = advisory.affected_versions(package, "< 1.11.0")

      # Should include the ORIGINAL alpha versions (not normalized)
      assert_includes affected, "1.7.0-alpha.2"
      assert_includes affected, "1.7.0-alpha.3"
      assert_includes affected, "1.6.0"
      assert_includes affected, "1.10.0"

      # Should not include versions >= 1.11.0
      refute_includes affected, "1.11.0"
      refute_includes affected, "1.12.0"
    end

    should "exclude completely invalid versions that don't look like semver" do
      package = { "ecosystem" => "npm", "package_name" => "test" }
      advisory = build(:advisory, packages: [package])

      versions = ["1.0.0", "not-a-version", "1.7.0-alpha.2", "abcdef", "2.0.0"]
      advisory.stubs(:version_numbers).returns(versions)

      affected = advisory.affected_versions(package, "< 3.0.0")

      # Should include valid and normalizable versions
      assert_includes affected, "1.0.0"
      assert_includes affected, "1.7.0-alpha.2"
      assert_includes affected, "2.0.0"

      # Should not include completely invalid versions
      refute_includes affected, "not-a-version"
      refute_includes affected, "abcdef"
    end

    should "handle both original versions being returned" do
      package = { "ecosystem" => "nuget", "package_name" => "test" }
      advisory = build(:advisory, packages: [package])

      # Both of these normalize to "1.7.0-alpha" but we should return both originals
      versions = ["1.7.0-alpha.2", "1.7.0-alpha.3"]
      advisory.stubs(:version_numbers).returns(versions)

      affected = advisory.affected_versions(package, "< 2.0.0")

      assert_equal 2, affected.count
      assert_includes affected, "1.7.0-alpha.2"
      assert_includes affected, "1.7.0-alpha.3"
    end
  end
end