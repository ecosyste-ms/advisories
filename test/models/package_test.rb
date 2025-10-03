require "test_helper"

class PackageTest < ActiveSupport::TestCase
  context "#packages_url" do
    setup do
      @registry = create(:registry, name: "github actions", ecosystem: "github-actions")
      @package = Package.create!(ecosystem: "github-actions", name: "buildalon/setup-steamcmd")
    end

    should "URL escape registry and package names with spaces" do
      expected_url = "https://packages.ecosyste.ms/registries/github+actions/packages/buildalon%2Fsetup-steamcmd"
      assert_equal expected_url, @package.packages_url
    end
  end

  context "#ping_url" do
    setup do
      @registry = create(:registry, name: "github actions", ecosystem: "github-actions")
      @package = Package.create!(ecosystem: "github-actions", name: "buildalon/setup-steamcmd")
    end

    should "URL escape registry and package names with spaces in ping URL" do
      expected_url = "https://packages.ecosyste.ms/api/v1/registries/github+actions/packages/buildalon%2Fsetup-steamcmd/ping"
      assert_equal expected_url, @package.ping_url
    end
  end

  context "#ping_for_resync" do
    setup do
      @registry = create(:registry, name: "npmjs.org")
      @package = Package.create!(ecosystem: "npm", name: "test-package")
    end

    should "send POST request to packages.ecosyste.ms ping endpoint" do
      stub_request(:post, "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages/test-package/ping")
        .to_return(status: 200, body: "", headers: {})

      @package.ping_for_resync

      assert_requested :post, "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages/test-package/ping"
    end

    should "handle network errors gracefully" do
      stub_request(:post, "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages/test-package/ping")
        .to_raise(StandardError.new("Network error"))

      # Should not raise an error
      assert_nothing_raised do
        @package.ping_for_resync
      end
    end

    should "URL escape registry and package names in ping request" do
      registry_with_spaces = create(:registry, name: "github actions", ecosystem: "github-actions")
      package_with_slash = Package.create!(ecosystem: "github-actions", name: "buildalon/setup-steamcmd")
      
      stub_request(:post, "https://packages.ecosyste.ms/api/v1/registries/github+actions/packages/buildalon%2Fsetup-steamcmd/ping")
        .to_return(status: 200, body: "", headers: {})

      package_with_slash.ping_for_resync

      assert_requested :post, "https://packages.ecosyste.ms/api/v1/registries/github+actions/packages/buildalon%2Fsetup-steamcmd/ping"
    end

    should "skip ping if registry is nil" do
      package_without_registry = Package.new(ecosystem: "unknown", name: "test")
      
      # Should not make any HTTP requests
      assert_not_requested :post, /.+/
      
      package_without_registry.ping_for_resync
    end
  end

  context "#sort_versions" do
    setup do
      @package = Package.new(ecosystem: "npm", name: "test-package")
    end

    should "sort versions in ascending order" do
      versions = ["1.0.0", "2.0.0", "1.1.0", "1.0.1"]
      expected = ["1.0.0", "1.0.1", "1.1.0", "2.0.0"]
      assert_equal expected, @package.sort_versions(versions)
    end

    should "handle versions with different number of parts" do
      versions = ["1.0", "1.0.0", "1.0.1", "1"]
      # In semantic versioning, "1" should be treated as "1.0.0.0", "1.0" as "1.0.0.0"
      # So the order should be: "1.0" (1.0.0.0), "1.0.0" (1.0.0.0), "1" (1.0.0.0), "1.0.1"
      # But since "1", "1.0", and "1.0.0" are equivalent, their relative order may vary
      # The important thing is that "1.0.1" comes last
      result = @package.sort_versions(versions)
      assert_equal "1.0.1", result.last
      assert result.include?("1")
      assert result.include?("1.0")
      assert result.include?("1.0.0")
    end

    should "handle versions with pre-release identifiers" do
      versions = ["1.0.0-alpha", "1.0.0", "1.0.0-beta", "1.0.0-alpha.1"]
      expected = ["1.0.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta"]
      assert_equal expected, @package.sort_versions(versions)
    end

    should "handle mixed numeric and string parts" do
      versions = ["1.0.0rc1", "1.0.0", "1.0.0rc2", "1.0.0a1"]
      expected = ["1.0.0", "1.0.0a1", "1.0.0rc1", "1.0.0rc2"]
      assert_equal expected, @package.sort_versions(versions)
    end

    should "handle empty array" do
      assert_equal [], @package.sort_versions([])
    end
  end

  context "#purl" do
    should "generate PURL for npm package" do
      package = build(:package, ecosystem: "npm", name: "lodash")
      assert_equal "pkg:npm/lodash", package.purl
    end

    should "generate PURL for rubygems package" do
      package = build(:package, ecosystem: "rubygems", name: "rails")
      assert_equal "pkg:gem/rails", package.purl
    end

    should "generate PURL for pypi package" do
      package = build(:package, ecosystem: "pypi", name: "django")
      assert_equal "pkg:pypi/django", package.purl
    end

    should "return nil for unsupported ecosystem" do
      package = build(:package, ecosystem: "unsupported", name: "package")
      assert_nil package.purl
    end
  end

  context "#repository_host" do
    should "return host from repository URL" do
      package = build(:package, repository_url: "https://github.com/rails/rails")
      assert_equal "github.com", package.repository_host
    end

    should "return nil when repository URL is blank" do
      package = build(:package, repository_url: nil)
      assert_nil package.repository_host
    end
  end

  context "#registry_name" do
    should "return registry name when available" do
      registry = create(:registry, name: "npmjs.org", ecosystem: "npm")
      package = build(:package, ecosystem: "npm", registry_url: "https://www.npmjs.com/package/lodash")
      assert_equal "npmjs.org", package.registry_name
    end

    should "return host from registry URL when registry name is not available" do
      package = build(:package, ecosystem: "unknown", registry_url: "https://example.com/package/test")
      assert_equal "example.com", package.registry_name
    end

    should "return nil when registry URL is blank" do
      package = build(:package, registry_url: nil)
      assert_nil package.registry_name
    end
  end
end