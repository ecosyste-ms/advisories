require "test_helper"

class PackageTest < ActiveSupport::TestCase
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

    should "skip ping if registry is nil" do
      package_without_registry = Package.new(ecosystem: "unknown", name: "test")
      
      # Should not make any HTTP requests
      assert_not_requested :post, /.+/
      
      package_without_registry.ping_for_resync
    end
  end
end