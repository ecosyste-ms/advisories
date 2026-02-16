require "test_helper"

class AdvisoriesControllerTest < ActionDispatch::IntegrationTest
  setup do
    @source = FactoryBot.create(:source)
    @advisory = FactoryBot.create(:advisory, source: @source, epss_percentage: 0.5, epss_percentile: 75.0)
  end

  test "should get index" do
    get advisories_url
    assert_response :success
    assert_equal "max-age=3600, public, stale-while-revalidate=3600", response.headers["Cache-Control"]
  end

  test "should handle valid sort parameters" do
    get advisories_url, params: { sort: "epss_percentage", order: "desc" }
    assert_response :success
  end

  test "should handle multiple valid sort parameters" do
    get advisories_url, params: { sort: "epss_percentage,severity", order: "desc,asc" }
    assert_response :success
  end

  test "should sanitize invalid sort parameters to prevent SQL injection" do
    get advisories_url, params: { sort: "epss_percentage'", order: "desc" }
    assert_response :success
  end

  test "should sanitize malicious sort parameters" do
    get advisories_url, params: { sort: "1; DROP TABLE advisories; --", order: "desc" }
    assert_response :success
  end

  test "should handle invalid column names gracefully" do
    get advisories_url, params: { sort: "invalid_column", order: "desc" }
    assert_response :success
  end

  test "should handle invalid order directions gracefully" do
    get advisories_url, params: { sort: "epss_percentage", order: "invalid" }
    assert_response :success
  end


  test "should get recent advisories data" do
    get recent_advisories_data_url
    assert_response :success
    assert_equal "max-age=3600, public, stale-while-revalidate=3600", response.headers["Cache-Control"]
  end

  test "should set cache headers on show" do
    get advisory_url(@advisory)
    assert_response :success
    assert_match /max-age=3600/, response.headers["Cache-Control"]
    assert_match /public/, response.headers["Cache-Control"]
    assert_match /stale-while-revalidate=3600/, response.headers["Cache-Control"]
    assert response.headers["ETag"].present?
  end

  test "should redirect ecosystem filter to ecosystem path" do
    get advisories_url, params: { ecosystem: "pypi" }
    assert_redirected_to ecosystem_path("pypi")
    assert_response :moved_permanently
  end

  test "should redirect ecosystem and package filters to package path" do
    get advisories_url, params: { ecosystem: "npm", package_name: "lodash" }
    assert_redirected_to ecosystem_package_path("npm", "lodash")
    assert_response :moved_permanently
  end

  test "should not redirect if only other filters are present" do
    get advisories_url, params: { severity: "high" }
    assert_response :success
  end

  test "should redirect with legacy name parameter" do
    get advisories_url, params: { ecosystem: "pypi", name: "apache-airflow" }
    assert_redirected_to ecosystem_package_path("pypi", "apache-airflow")
    assert_response :moved_permanently
  end

  test "should redirect package_name without ecosystem if only one package exists" do
    package = FactoryBot.create(:package, name: "typo3/cms", ecosystem: "packagist")
    get advisories_url, params: { package_name: "typo3/cms" }
    assert_redirected_to ecosystem_package_path("packagist", "typo3/cms")
    assert_response :moved_permanently
  end

  test "should not redirect package_name without ecosystem if multiple packages exist" do
    FactoryBot.create(:package, name: "lodash", ecosystem: "npm")
    FactoryBot.create(:package, name: "lodash", ecosystem: "jspm")
    get advisories_url, params: { package_name: "lodash" }
    assert_response :success
  end

  test "should filter by source" do
    erlef_source = FactoryBot.create(:source, kind: "erlef", url: "https://cna.erlef.org")
    FactoryBot.create(:advisory, source: erlef_source)

    get advisories_url, params: { source: "erlef" }
    assert_response :success
  end

  test "should display advisory with no packages and no repository_url" do
    erlef_source = FactoryBot.create(:source, kind: "erlef", name: "Erlef", url: "https://cna.erlef.org")
    FactoryBot.create(:advisory, source: erlef_source, packages: [], repository_url: nil)

    get advisories_url, params: { source: "erlef" }
    assert_response :success
  end

  test "should display advisory with repository_url but no packages" do
    erlef_source = FactoryBot.create(:source, kind: "erlef", name: "Erlef", url: "https://cna.erlef.org")
    Advisory.create!(
      source: erlef_source,
      uuid: "EEF-CVE-2025-TEST",
      title: "Test Advisory",
      packages: [],
      repository_url: "https://github.com/erlang/otp",
      published_at: Time.current,
      severity: "low"
    )

    get advisories_url, params: { source: "erlef" }
    assert_response :success
  end

  test "should show potentially affected packages section when present" do
    pkg = FactoryBot.create(:package, ecosystem: "conda", name: "requests")
    FactoryBot.create(:related_package, advisory: @advisory, package: pkg)

    get advisory_url(@advisory)
    assert_response :success
    assert_select "h3", text: "Potentially Affected Packages"
    assert_select "td", text: "conda"
  end

  test "should not show potentially affected packages section when empty" do
    get advisory_url(@advisory)
    assert_response :success
    assert_select "h3", text: "Potentially Affected Packages", count: 0
  end

  test "should filter by source and show correct advisories" do
    erlef_source = FactoryBot.create(:source, kind: "erlef", url: "https://cna.erlef.org")
    FactoryBot.create(:advisory, source: erlef_source, uuid: "EEF-CVE-2025-0001")

    get advisories_url, params: { source: "github" }
    assert_response :success
    assert_select "a[href*='#{@advisory.uuid}']"
  end

end