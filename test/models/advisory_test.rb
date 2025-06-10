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
end