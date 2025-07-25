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
      expected_url = "https://packages.ecosyste.ms/registries/github+actions/packages/buildalon%2Fsetup-steamcmd/ping"
      assert_equal expected_url, @package.ping_url
    end
  end

  context "#ping_for_resync" do
    setup do
      @registry = create(:registry, name: "npmjs.org")
      @package = Package.create!(ecosystem: "npm", name: "test-package")
    end

    should "send POST request to packages.ecosyste.ms ping endpoint" do
      stub_request(:post, "https://packages.ecosyste.ms/registries/npmjs.org/packages/test-package/ping")
        .to_return(status: 200, body: "", headers: {})

      @package.ping_for_resync

      assert_requested :post, "https://packages.ecosyste.ms/registries/npmjs.org/packages/test-package/ping"
    end

    should "handle network errors gracefully" do
      stub_request(:post, "https://packages.ecosyste.ms/registries/npmjs.org/packages/test-package/ping")
        .to_raise(StandardError.new("Network error"))

      # Should not raise an error
      assert_nothing_raised do
        @package.ping_for_resync
      end
    end

    should "URL escape registry and package names in ping request" do
      registry_with_spaces = create(:registry, name: "github actions", ecosystem: "github-actions")
      package_with_slash = Package.create!(ecosystem: "github-actions", name: "buildalon/setup-steamcmd")
      
      stub_request(:post, "https://packages.ecosyste.ms/registries/github+actions/packages/buildalon%2Fsetup-steamcmd/ping")
        .to_return(status: 200, body: "", headers: {})

      package_with_slash.ping_for_resync

      assert_requested :post, "https://packages.ecosyste.ms/registries/github+actions/packages/buildalon%2Fsetup-steamcmd/ping"
    end

    should "skip ping if registry is nil" do
      package_without_registry = Package.new(ecosystem: "unknown", name: "test")
      
      # Should not make any HTTP requests
      assert_not_requested :post, /.+/
      
      package_without_registry.ping_for_resync
    end
  end
end