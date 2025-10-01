require "test_helper"

class AdvisoriesControllerTest < ActionDispatch::IntegrationTest
  setup do
    @source = FactoryBot.create(:source)
    @advisory = FactoryBot.create(:advisory, source: @source, epss_percentage: 0.5, epss_percentile: 75.0)
  end

  test "should get index" do
    get advisories_url
    assert_response :success
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

end