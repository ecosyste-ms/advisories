require 'test_helper'

class PackageCasingTest < ActionDispatch::IntegrationTest
  setup do
    create(:registry, name: 'npmjs.org', ecosystem: 'npm')
    @package = create(:package, ecosystem: 'npm', name: 'openclaw', description: 'Shared package metadata',
      last_synced_at: Time.current, dependent_packages_count: 12345)
    Sidekiq::Testing.fake! do
      @advisory = create(:advisory, packages: [{
        'ecosystem' => 'npm', 'package_name' => 'OpenClaw',
        'versions' => [{ 'vulnerable_version_range' => '< 2.0.0' }]
      }])
    end
  end

  test "package pages find the same metadata and keep links on existing duplicate rows" do
    duplicate = create(:package, ecosystem: 'npm', name: 'legacy-openclaw')
    duplicate.update_columns(name: 'OpenClaw')
    related = create(:advisory)
    create(:related_package, package: duplicate, advisory: related)

    %w[openclaw OpenClaw OPENCLAW].each do |name|
      get ecosystem_package_url('npm', name)
      assert_response :success
      assert_equal @package.id, assigns(:package).id
      assert_select 'p', text: 'Shared package metadata'
      assert_includes assigns(:advisories).pluck(:id), related.id
    end
  end

  test "advisory pages display metadata for differently cased package names" do
    get advisory_url(@advisory)
    assert_response :success
    assert_select '.stat-card-title', text: '12,345'
  end

  test "legacy redirect groups case variants within one ecosystem" do
    duplicate = create(:package, ecosystem: 'npm', name: 'legacy-openclaw')
    duplicate.update_columns(name: 'OpenClaw')
    get advisories_url, params: { package_name: 'OPENCLAW' }
    assert_redirected_to ecosystem_package_url('npm', 'openclaw')
  end

  test "batscope finds metadata across casing and does not count a spelling change as a first advisory" do
    get batscope_url
    assert_response :success
    assert_includes assigns(:packages).pluck(:id), @package.id

    Sidekiq::Testing.fake! do
      create(:advisory, created_at: 2.months.ago, packages: [{
        'ecosystem' => 'npm', 'package_name' => 'openclaw', 'versions' => []
      }])
    end
    get batscope_url
    assert_response :success
    refute_includes assigns(:packages).pluck(:id), @package.id
  end

  test "batscope owner lookup finds differently cased names" do
    @package.update!(owner: 'example-owner', downloads: 12345)
    get batscope_owners_url
    assert_response :success
    assert_equal ['example-owner'], assigns(:owners).map(&:first)
  end
end
