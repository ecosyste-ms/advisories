require 'test_helper'

class PackageEtagTest < ActiveSupport::TestCase
  setup do
    @package = Package.create!(
      ecosystem: 'npm',
      name: 'test-package'
    )

    # Stub registry lookup
    registry = Registry.new(name: 'npmjs.org', ecosystem: 'npm')
    Registry.stubs(:find_by_ecosystem).returns(registry)
  end

  test "stores ETags after successful sync" do
    # Mock successful API responses
    package_response = {
      status: 200,
      success: true,
      not_modified: false,
      etag: 'W/"package123"',
      body: {
        'dependent_packages_count' => 10,
        'dependent_repos_count' => 20,
        'downloads' => 1000,
        'downloads_period' => 'month',
        'latest_release_number' => '1.0.0',
        'repository_url' => 'https://github.com/test/package',
        'description' => 'Test package',
        'registry_url' => 'https://npmjs.org/package/test-package',
        'versions_count' => 5,
        'critical' => false
      }
    }

    versions_response = {
      status: 200,
      success: true,
      not_modified: false,
      etag: 'W/"versions456"',
      body: ['1.0.0', '0.9.0', '0.8.0']
    }

    EcosystemsFaradayClient.expects(:conditional_get)
      .with("/api/v1/registries/npmjs.org/packages/test-package", nil)
      .returns(package_response)

    EcosystemsFaradayClient.expects(:conditional_get)
      .with("/api/v1/registries/npmjs.org/packages/test-package/version_numbers", nil)
      .returns(versions_response)

    @package.sync
    @package.reload

    assert_equal 'W/"package123"', @package.package_etag
    assert_equal 'W/"versions456"', @package.versions_etag
    assert_equal 10, @package.dependent_packages_count
    assert_equal ['1.0.0', '0.9.0', '0.8.0'], @package.version_numbers
  end

  test "uses stored ETags for conditional requests" do
    @package.update!(
      package_etag: 'W/"existing123"',
      versions_etag: 'W/"existing456"'
    )

    # Mock 304 Not Modified responses
    package_response = {
      status: 304,
      success: true,
      not_modified: true,
      etag: 'W/"existing123"',
      body: nil
    }

    versions_response = {
      status: 304,
      success: true,
      not_modified: true,
      etag: 'W/"existing456"',
      body: nil
    }

    EcosystemsFaradayClient.expects(:conditional_get)
      .with("/api/v1/registries/npmjs.org/packages/test-package", 'W/"existing123"')
      .returns(package_response)

    EcosystemsFaradayClient.expects(:conditional_get)
      .with("/api/v1/registries/npmjs.org/packages/test-package/version_numbers", 'W/"existing456"')
      .returns(versions_response)

    @package.sync
    @package.reload

    # ETags should remain the same
    assert_equal 'W/"existing123"', @package.package_etag
    assert_equal 'W/"existing456"', @package.versions_etag

    # last_synced_at should still be updated
    assert @package.last_synced_at > 1.minute.ago
  end

  test "updates ETags when data changes" do
    @package.update!(
      package_etag: 'W/"old123"',
      versions_etag: 'W/"old456"',
      dependent_packages_count: 5
    )

    # Mock responses with new ETags
    package_response = {
      status: 200,
      success: true,
      not_modified: false,
      etag: 'W/"new123"',
      body: {
        'dependent_packages_count' => 15,
        'dependent_repos_count' => 25,
        'downloads' => 2000,
        'downloads_period' => 'month',
        'latest_release_number' => '2.0.0',
        'repository_url' => 'https://github.com/test/package',
        'description' => 'Updated test package',
        'registry_url' => 'https://npmjs.org/package/test-package',
        'versions_count' => 10,
        'critical' => true
      }
    }

    versions_response = {
      status: 200,
      success: true,
      not_modified: false,
      etag: 'W/"new456"',
      body: ['2.0.0', '1.0.0', '0.9.0']
    }

    EcosystemsFaradayClient.expects(:conditional_get)
      .with("/api/v1/registries/npmjs.org/packages/test-package", 'W/"old123"')
      .returns(package_response)

    EcosystemsFaradayClient.expects(:conditional_get)
      .with("/api/v1/registries/npmjs.org/packages/test-package/version_numbers", 'W/"old456"')
      .returns(versions_response)

    @package.sync
    @package.reload

    # ETags should be updated
    assert_equal 'W/"new123"', @package.package_etag
    assert_equal 'W/"new456"', @package.versions_etag

    # Data should be updated
    assert_equal 15, @package.dependent_packages_count
    assert_equal true, @package.critical
    assert_equal ['2.0.0', '1.0.0', '0.9.0'], @package.version_numbers
  end
end