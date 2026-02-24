require "test_helper"

class VersionNormalizationTest < ActiveSupport::TestCase
  class DummyModel
    include VersionNormalization
  end

  setup do
    @model = DummyModel.new
  end

  context "#clean_version" do
    should "return version for valid semver" do
      assert_equal "1.0.0", @model.clean_version("1.0.0")
    end

    should "strip v prefix for Go packages" do
      assert_equal "1.0.0", @model.clean_version("v1.0.0")
      assert_equal "2.5.3", @model.clean_version("v2.5.3")
    end

    should "preserve prerelease versions" do
      assert_equal "1.7.0-alpha.2", @model.clean_version("1.7.0-alpha.2")
      assert_equal "2.0.0-beta.1", @model.clean_version("2.0.0-beta.1")
    end

    should "return nil for completely invalid versions" do
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
      assert_equal "1.7.0-alpha.2", result["1.7.0-alpha.2"]
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

    should "handle OR ranges with ||" do
      assert @model.version_satisfies_range?("1.5.0", ">= 1.0.0, < 2.0.0 || >= 3.0.0, < 4.0.0", "rubygems")
      assert @model.version_satisfies_range?("3.5.0", ">= 1.0.0, < 2.0.0 || >= 3.0.0, < 4.0.0", "rubygems")
      refute @model.version_satisfies_range?("2.5.0", ">= 1.0.0, < 2.0.0 || >= 3.0.0, < 4.0.0", "rubygems")
    end

    # Real advisory ranges from ecosyste.ms API

    # rubygems: rack CVE-2025-27610
    # ranges: >= 3.2.0, < 3.2.5 || >= 3.0.0.beta1, < 3.1.20 || < 2.2.22
    context "rubygems rack advisory" do
      setup do
        @range = ">= 3.2.0, < 3.2.5 || >= 3.0.0.beta1, < 3.1.20 || < 2.2.22"
      end

      should "match versions in first range" do
        assert @model.version_satisfies_range?("3.2.0", @range, "rubygems")
        assert @model.version_satisfies_range?("3.2.4", @range, "rubygems")
      end

      should "match versions in second range including prerelease" do
        assert @model.version_satisfies_range?("3.0.0.beta1", @range, "rubygems")
        assert @model.version_satisfies_range?("3.1.0", @range, "rubygems")
      end

      should "match versions in third range" do
        assert @model.version_satisfies_range?("2.2.21", @range, "rubygems")
        assert @model.version_satisfies_range?("1.0.0", @range, "rubygems")
      end

      should "not match fixed versions" do
        refute @model.version_satisfies_range?("3.2.5", @range, "rubygems")
        refute @model.version_satisfies_range?("3.1.20", @range, "rubygems")
        refute @model.version_satisfies_range?("2.2.22", @range, "rubygems")
      end
    end

    # rubygems: nokogiri
    # range: >= 1.5.1, < 1.19.1
    context "rubygems nokogiri advisory" do
      should "match affected versions" do
        assert @model.version_satisfies_range?("1.5.1", ">= 1.5.1, < 1.19.1", "rubygems")
        assert @model.version_satisfies_range?("1.16.0", ">= 1.5.1, < 1.19.1", "rubygems")
      end

      should "not match fixed or prior versions" do
        refute @model.version_satisfies_range?("1.5.0", ">= 1.5.1, < 1.19.1", "rubygems")
        refute @model.version_satisfies_range?("1.19.1", ">= 1.5.1, < 1.19.1", "rubygems")
      end
    end

    # npm: @astrojs/node
    # range: < 9.5.4
    context "npm astrojs advisory" do
      should "match affected versions" do
        assert @model.version_satisfies_range?("9.5.3", "< 9.5.4", "npm")
        assert @model.version_satisfies_range?("1.0.0", "< 9.5.4", "npm")
      end

      should "not match fixed versions" do
        refute @model.version_satisfies_range?("9.5.4", "< 9.5.4", "npm")
        refute @model.version_satisfies_range?("10.0.0", "< 9.5.4", "npm")
      end
    end

    # pypi: yt-dlp
    # range: >= 2023.06.21, < 2026.02.21
    context "pypi yt-dlp advisory with date-based versions" do
      should "match affected versions" do
        assert @model.version_satisfies_range?("2023.06.21", ">= 2023.06.21, < 2026.02.21", "pypi")
        assert @model.version_satisfies_range?("2025.01.15", ">= 2023.06.21, < 2026.02.21", "pypi")
      end

      should "not match fixed versions" do
        refute @model.version_satisfies_range?("2026.02.21", ">= 2023.06.21, < 2026.02.21", "pypi")
        refute @model.version_satisfies_range?("2023.06.20", ">= 2023.06.21, < 2026.02.21", "pypi")
      end
    end

    # maven: org.keycloak:keycloak-services
    # range: <= 26.5.3
    context "maven keycloak advisory" do
      should "match affected versions" do
        assert @model.version_satisfies_range?("26.5.3", "<= 26.5.3", "maven")
        assert @model.version_satisfies_range?("1.0.0", "<= 26.5.3", "maven")
      end

      should "not match fixed versions" do
        refute @model.version_satisfies_range?("26.5.4", "<= 26.5.3", "maven")
      end
    end

    # nuget: HtmlSanitizer
    # ranges: >= 9.1.878-beta, < 9.1.893-beta || < 9.0.892
    context "nuget HtmlSanitizer advisory with beta prerelease" do
      setup do
        @range = ">= 9.1.878-beta, < 9.1.893-beta || < 9.0.892"
      end

      should "match affected versions in first range" do
        assert @model.version_satisfies_range?("9.1.878-beta", @range, "nuget")
        assert @model.version_satisfies_range?("9.1.890-beta", @range, "nuget")
      end

      should "match affected versions in second range" do
        assert @model.version_satisfies_range?("9.0.891", @range, "nuget")
        assert @model.version_satisfies_range?("8.0.0", @range, "nuget")
      end

      should "not match fixed versions" do
        refute @model.version_satisfies_range?("9.1.893-beta", @range, "nuget")
        refute @model.version_satisfies_range?("9.0.892", @range, "nuget")
      end
    end

    # go: traefik
    # range: <= 3.6.7
    context "go traefik advisory" do
      should "match affected versions with v prefix stripped" do
        assert @model.version_satisfies_range?("3.6.7", "<= 3.6.7", "go")
        assert @model.version_satisfies_range?("3.0.0", "<= 3.6.7", "go")
      end

      should "not match fixed versions" do
        refute @model.version_satisfies_range?("3.6.8", "<= 3.6.7", "go")
      end
    end

    # cargo: static-web-server
    # range: >= 2.1.0, < 2.41.0
    context "cargo static-web-server advisory" do
      should "match affected versions" do
        assert @model.version_satisfies_range?("2.1.0", ">= 2.1.0, < 2.41.0", "cargo")
        assert @model.version_satisfies_range?("2.40.0", ">= 2.1.0, < 2.41.0", "cargo")
      end

      should "not match fixed or prior versions" do
        refute @model.version_satisfies_range?("2.0.0", ">= 2.1.0, < 2.41.0", "cargo")
        refute @model.version_satisfies_range?("2.41.0", ">= 2.1.0, < 2.41.0", "cargo")
      end
    end

    # packagist: craftcms/cms
    # ranges: >= 5.0.0-RC1, <= 5.8.22 || >= 4.5.0-RC1, <= 4.16.18
    context "packagist craftcms advisory with RC prerelease" do
      setup do
        @range = ">= 5.0.0-RC1, <= 5.8.22 || >= 4.5.0-RC1, <= 4.16.18"
      end

      should "match affected versions in first range" do
        assert @model.version_satisfies_range?("5.0.0-RC1", @range, "packagist")
        assert @model.version_satisfies_range?("5.8.22", @range, "packagist")
      end

      should "match affected versions in second range" do
        assert @model.version_satisfies_range?("4.5.0-RC1", @range, "packagist")
        assert @model.version_satisfies_range?("4.16.18", @range, "packagist")
      end

      should "not match versions outside ranges" do
        refute @model.version_satisfies_range?("5.8.23", @range, "packagist")
        refute @model.version_satisfies_range?("4.16.19", @range, "packagist")
      end
    end

    # hex: ash
    # range: >= 3.6.3, <= 3.7.0
    context "hex ash advisory" do
      should "match affected versions" do
        assert @model.version_satisfies_range?("3.6.3", ">= 3.6.3, <= 3.7.0", "hex")
        assert @model.version_satisfies_range?("3.7.0", ">= 3.6.3, <= 3.7.0", "hex")
      end

      should "not match fixed or prior versions" do
        refute @model.version_satisfies_range?("3.6.2", ">= 3.6.3, <= 3.7.0", "hex")
        refute @model.version_satisfies_range?("3.7.1", ">= 3.6.3, <= 3.7.0", "hex")
      end
    end
  end

  context "#vers_scheme" do
    should "map ecosystem names to vers schemes via purl type" do
      assert_equal "gem", @model.vers_scheme("rubygems")
      assert_equal "npm", @model.vers_scheme("npm")
      assert_equal "pypi", @model.vers_scheme("pypi")
      assert_equal "maven", @model.vers_scheme("maven")
      assert_equal "nuget", @model.vers_scheme("nuget")
      assert_equal "go", @model.vers_scheme("go")
      assert_equal "cargo", @model.vers_scheme("cargo")
    end

    should "fall back to lowercase ecosystem name" do
      assert_equal "hex", @model.vers_scheme("hex")
      assert_equal "packagist", @model.vers_scheme("packagist")
    end
  end
end
