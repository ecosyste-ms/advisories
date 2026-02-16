require "test_helper"

class EcosystemsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @source = FactoryBot.create(:source)
    @advisory = FactoryBot.create(:advisory, source: @source, packages: [
      {
        "ecosystem" => "pypi",
        "package_name" => "tensorflow",
        "versions" => [{"vulnerable_version_range" => ">= 2.0.0, < 2.5.0"}]
      }
    ])
  end

  test "should get ecosystems index" do
    get ecosystems_url
    assert_response :success
    assert_select "h2", /Browse Advisories by Ecosystems/
    assert_equal "max-age=3600, public, stale-while-revalidate=3600", response.headers["Cache-Control"]
  end

  test "should get ecosystem show page" do
    get ecosystem_url("pypi")
    assert_response :success
    assert_select "h2", /pypi/
    assert_equal "max-age=3600, public, stale-while-revalidate=3600", response.headers["Cache-Control"]
  end

  test "should get package advisories page" do
    get ecosystem_package_url("pypi", "tensorflow")
    assert_response :success
    assert_select "h2", /tensorflow/
    assert_equal "max-age=3600, public, stale-while-revalidate=3600", response.headers["Cache-Control"]
  end

  test "should get ecosystem packages page" do
    FactoryBot.create(:package, ecosystem: "pypi", name: "numpy", advisories_count: 5, latest_release_number: "1.26.0", downloads: 1000000)
    get ecosystem_packages_url("pypi")
    assert_response :success
    assert_select "h2", /pypi Packages/
    assert_equal "max-age=3600, public, stale-while-revalidate=3600", response.headers["Cache-Control"]
  end

  test "should show package data on ecosystem packages page" do
    FactoryBot.create(:package, ecosystem: "pypi", name: "numpy", advisories_count: 5, latest_release_number: "1.26.0", downloads: 1000000)
    FactoryBot.create(:package, ecosystem: "pypi", name: "requests", advisories_count: 2, latest_release_number: "2.31.0", downloads: 500000)
    get ecosystem_packages_url("pypi")
    assert_response :success
    assert_select "a.list-group-item", /numpy/
    assert_select "a.list-group-item", /requests/
  end

  test "should filter ecosystem packages to related advisories only" do
    package_with_related = FactoryBot.create(:package, ecosystem: "pypi", name: "numpy", advisories_count: 0)
    package_without_related = FactoryBot.create(:package, ecosystem: "pypi", name: "pandas", advisories_count: 0)
    FactoryBot.create(:related_package, package: package_with_related, advisory: @advisory)

    get ecosystem_packages_url("pypi"), params: { related: "true" }
    assert_response :success
    assert_select "a.list-group-item", /numpy/
    assert_select "a.list-group-item", { text: /pandas/, count: 0 }
  end

  test "should handle severity filter on ecosystem page" do
    get ecosystem_url("pypi"), params: { severity: "high" }
    assert_response :success
  end

  test "should handle severity filter on package page" do
    get ecosystem_package_url("pypi", "tensorflow"), params: { severity: "high" }
    assert_response :success
  end

  test "should handle repository_url filter on ecosystem page" do
    get ecosystem_url("pypi"), params: { repository_url: "https://github.com/tensorflow/tensorflow" }
    assert_response :success
  end

  test "should handle repository_url filter on package page" do
    get ecosystem_package_url("pypi", "tensorflow"), params: { repository_url: "https://github.com/tensorflow/tensorflow" }
    assert_response :success
  end

  test "should handle valid sort parameters on ecosystem page" do
    get ecosystem_url("pypi"), params: { sort: "published_at", order: "desc" }
    assert_response :success
  end

  test "should handle valid sort parameters on package page" do
    get ecosystem_package_url("pypi", "tensorflow"), params: { sort: "published_at", order: "desc" }
    assert_response :success
  end

  test "should sanitize invalid sort parameters on ecosystem page" do
    get ecosystem_url("pypi"), params: { sort: "invalid'; DROP TABLE advisories; --", order: "desc" }
    assert_response :success
  end

  test "should sanitize invalid sort parameters on package page" do
    get ecosystem_package_url("pypi", "tensorflow"), params: { sort: "invalid'; DROP TABLE advisories; --", order: "desc" }
    assert_response :success
  end

  test "should handle package names with dots" do
    advisory = FactoryBot.create(:advisory, source: @source, packages: [
      {
        "ecosystem" => "maven",
        "package_name" => "org.jenkins-ci.main:jenkins-core",
        "versions" => [{"vulnerable_version_range" => ">= 2.0.0, < 2.5.0"}]
      }
    ])

    get ecosystem_package_url("maven", "org.jenkins-ci.main:jenkins-core")
    assert_response :success
    assert_select "h2", /org.jenkins-ci.main:jenkins-core/
  end

  test "should handle package names with multiple slashes" do
    advisory = FactoryBot.create(:advisory, source: @source, packages: [
      {
        "ecosystem" => "npm",
        "package_name" => "@scope/package/subpath",
        "versions" => [{"vulnerable_version_range" => ">= 1.0.0, < 2.0.0"}]
      }
    ])

    get ecosystem_package_url("npm", "@scope/package/subpath")
    assert_response :success
  end

  test "should handle ecosystem without registry" do
    advisory = FactoryBot.create(:advisory, source: @source, packages: [
      {
        "ecosystem" => "unknown-ecosystem",
        "package_name" => "test-package",
        "versions" => [{"vulnerable_version_range" => ">= 1.0.0"}]
      }
    ])

    get ecosystem_url("unknown-ecosystem")
    assert_response :success
    assert_select "h2", /unknown-ecosystem/
  end

  test "should handle package without registry" do
    advisory = FactoryBot.create(:advisory, source: @source, packages: [
      {
        "ecosystem" => "unknown-ecosystem",
        "package_name" => "test-package",
        "versions" => [{"vulnerable_version_range" => ">= 1.0.0"}]
      }
    ])

    get ecosystem_package_url("unknown-ecosystem", "test-package")
    assert_response :success
    assert_select "h2", /test-package/
  end
end
