require "test_helper"

class Osv::QuerybatchControllerTest < ActionDispatch::IntegrationTest
  setup do
    @source = create(:source)
    @npm_advisory = create(:advisory,
      source: @source,
      uuid: "GHSA-npm-0001",
      title: "NPM Advisory",
      packages: [
        { "ecosystem" => "npm", "package_name" => "lodash", "versions" => [] }
      ]
    )
    @pypi_advisory = create(:advisory,
      source: @source,
      uuid: "GHSA-pypi-0001",
      title: "PyPI Advisory",
      packages: [
        { "ecosystem" => "pypi", "package_name" => "django", "versions" => [] }
      ]
    )
  end

  test "batch queries multiple packages" do
    post osv_querybatch_url,
      params: {
        queries: [
          { package: { name: "lodash", ecosystem: "npm" } },
          { package: { name: "django", ecosystem: "PyPI" } }
        ]
      },
      as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 2, json["results"].length
    assert_equal 1, json["results"][0]["vulns"].length
    assert_equal 1, json["results"][1]["vulns"].length
  end

  test "returns only id and modified in summary format" do
    post osv_querybatch_url,
      params: {
        queries: [
          { package: { name: "lodash", ecosystem: "npm" } }
        ]
      },
      as: :json
    assert_response :success

    json = JSON.parse(response.body)
    vuln = json["results"][0]["vulns"][0]

    assert_equal "GHSA-npm-0001", vuln["id"]
    assert_includes vuln.keys, "modified"
    assert_equal 2, vuln.keys.length
    refute_includes vuln.keys, "summary"
    refute_includes vuln.keys, "details"
    refute_includes vuln.keys, "affected"
  end

  test "rejects more than 1000 queries" do
    queries = 1001.times.map do |i|
      { package: { name: "pkg-#{i}", ecosystem: "npm" } }
    end

    post osv_querybatch_url, params: { queries: queries }, as: :json
    assert_response :bad_request

    json = JSON.parse(response.body)
    assert_includes json["error"], "Maximum batch size"
  end

  test "handles empty queries array" do
    post osv_querybatch_url, params: { queries: [] }, as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal [], json["results"]
  end

  test "individual query errors do not fail batch" do
    post osv_querybatch_url,
      params: {
        queries: [
          { package: { name: "lodash", ecosystem: "npm" } },
          { purl: "pkg:npm/test@1.0.0", package: { version: "2.0.0" } },
          { package: { name: "django", ecosystem: "PyPI" } }
        ]
      },
      as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 3, json["results"].length

    # First query should succeed
    assert_equal 1, json["results"][0]["vulns"].length

    # Second query should have error
    assert_equal 0, json["results"][1]["vulns"].length

    # Third query should succeed
    assert_equal 1, json["results"][2]["vulns"].length
  end

  test "handles PURL in batch queries" do
    post osv_querybatch_url,
      params: {
        queries: [
          { purl: "pkg:npm/lodash" },
          { purl: "pkg:pypi/django" }
        ]
      },
      as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 2, json["results"].length
    assert_equal 1, json["results"][0]["vulns"].length
    assert_equal 1, json["results"][1]["vulns"].length
  end

  test "handles missing queries key" do
    post osv_querybatch_url, params: {}, as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal [], json["results"]
  end

  test "returns empty vulns for unknown packages" do
    post osv_querybatch_url,
      params: {
        queries: [
          { package: { name: "nonexistent", ecosystem: "npm" } }
        ]
      },
      as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 1, json["results"].length
    assert_equal 0, json["results"][0]["vulns"].length
  end
end
