require "test_helper"

class VersionNormalizationTest < ActiveSupport::TestCase
  # Create a dummy class to test the concern
  class DummyModel
    include VersionNormalization
  end

  setup do
    @model = DummyModel.new
  end

  context "#clean_version" do
    should "return cleaned version for valid semver" do
      assert_equal "1.0.0", @model.clean_version("1.0.0")
    end

    should "handle versions with v prefix for Go packages" do
      assert_equal "1.0.0", @model.clean_version("v1.0.0")
      assert_equal "2.5.3", @model.clean_version("v2.5.3")
    end

    should "normalize prerelease versions with extra dots" do
      assert_equal "1.7.0-alpha", @model.clean_version("1.7.0-alpha.2")
      assert_equal "1.7.0-alpha", @model.clean_version("1.7.0-alpha.3")
      assert_equal "2.0.0-beta", @model.clean_version("2.0.0-beta.1")
      assert_equal "1.0.0-rc", @model.clean_version("1.0.0-rc.5")
    end

    should "normalize prerelease versions with v prefix" do
      assert_equal "1.7.0-alpha", @model.clean_version("v1.7.0-alpha.2")
    end

    should "return nil for completely invalid versions that don't look like semver" do
      assert_nil @model.clean_version("not-a-version")
      assert_nil @model.clean_version("abcdef")
      assert_nil @model.clean_version("random-string")
    end

    should "return nil for versions without x.x.x pattern" do
      assert_nil @model.clean_version("1.0")
      assert_nil @model.clean_version("latest")
      assert_nil @model.clean_version("v1.0")
    end
  end

  context "#build_version_map" do
    should "create hash mapping original to cleaned versions" do
      versions = ["1.0.0", "1.7.0-alpha.2", "v2.0.0"]
      result = @model.build_version_map(versions)

      assert_equal "1.0.0", result["1.0.0"]
      assert_equal "1.7.0-alpha", result["1.7.0-alpha.2"]
      assert_equal "2.0.0", result["v2.0.0"]
    end

    should "exclude invalid versions from map" do
      versions = ["1.0.0", "not-a-version", "1.7.0-alpha.2"]
      result = @model.build_version_map(versions)

      assert_equal 2, result.size
      assert_includes result, "1.0.0"
      assert_includes result, "1.7.0-alpha.2"
      refute_includes result, "not-a-version"
    end

    should "preserve multiple versions that normalize to same cleaned version" do
      versions = ["1.7.0-alpha.2", "1.7.0-alpha.3"]
      result = @model.build_version_map(versions)

      # Should have both originals as keys
      assert_equal 2, result.size
      assert_equal "1.7.0-alpha", result["1.7.0-alpha.2"]
      assert_equal "1.7.0-alpha", result["1.7.0-alpha.3"]
    end
  end

  context "#version_satisfies_range?" do
    should "return true for versions that satisfy range" do
      assert @model.version_satisfies_range?("1.0.0", "< 2.0.0", "npm")
      assert @model.version_satisfies_range?("1.5.0", ">= 1.0.0", "npm")
    end

    should "return false for versions that don't satisfy range" do
      refute @model.version_satisfies_range?("2.0.0", "< 2.0.0", "npm")
      refute @model.version_satisfies_range?("0.9.0", ">= 1.0.0", "npm")
    end

    should "check base version for prerelease versions" do
      # 1.7.0-alpha doesn't normally match "< 1.11.0" in semver
      # but we check if the base version 1.7.0 matches
      assert @model.version_satisfies_range?("1.7.0-alpha", "< 1.11.0", "nuget")
      assert @model.version_satisfies_range?("1.0.0-beta", "< 2.0.0", "npm")
    end

    should "return false for prerelease if base version doesn't satisfy" do
      refute @model.version_satisfies_range?("2.0.0-alpha", "< 2.0.0", "npm")
      refute @model.version_satisfies_range?("1.5.0-beta", "< 1.0.0", "npm")
    end
  end
end
