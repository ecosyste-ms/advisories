require "test_helper"

class Osv::QueryControllerTest < ActionDispatch::IntegrationTest
  setup do
    @source = create(:source)
    @npm_advisory = create(:advisory,
      source: @source,
      uuid: "GHSA-npm-0001",
      title: "NPM Advisory",
      packages: [
        {
          "ecosystem" => "npm",
          "package_name" => "lodash",
          "versions" => [
            { "vulnerable_version_range" => "< 4.17.21" }
          ]
        }
      ]
    )
    @pypi_advisory = create(:advisory,
      source: @source,
      uuid: "GHSA-pypi-0001",
      title: "PyPI Advisory",
      packages: [
        {
          "ecosystem" => "pypi",
          "package_name" => "django",
          "versions" => [
            { "vulnerable_version_range" => "< 3.2.0" }
          ]
        }
      ]
    )
  end

  test "queries by package name and ecosystem" do
    post osv_query_url, params: { package: { name: "lodash", ecosystem: "npm" } }, as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 1, json["vulns"].length
    assert_equal "GHSA-npm-0001", json["vulns"].first["id"]
  end

  test "queries by PURL" do
    post osv_query_url, params: { purl: "pkg:npm/lodash@4.17.20" }, as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 1, json["vulns"].length
    assert_equal "GHSA-npm-0001", json["vulns"].first["id"]
  end

  test "queries by PURL without version" do
    post osv_query_url, params: { purl: "pkg:npm/lodash" }, as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 1, json["vulns"].length
  end

  test "rejects version in both PURL and package parameter" do
    post osv_query_url,
      params: { purl: "pkg:npm/lodash@4.17.20", package: { version: "4.17.19" } },
      as: :json
    assert_response :bad_request

    json = JSON.parse(response.body)
    assert_includes json["error"], "version cannot be specified"
  end

  test "returns empty results for unknown package" do
    post osv_query_url, params: { package: { name: "nonexistent", ecosystem: "npm" } }, as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 0, json["vulns"].length
  end

  test "handles OSV ecosystem names (PyPI)" do
    post osv_query_url, params: { package: { name: "django", ecosystem: "PyPI" } }, as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 1, json["vulns"].length
    assert_equal "GHSA-pypi-0001", json["vulns"].first["id"]
  end

  test "handles OSV ecosystem names (RubyGems)" do
    create(:advisory,
      source: @source,
      uuid: "GHSA-ruby-0001",
      packages: [{ "ecosystem" => "rubygems", "package_name" => "rails", "versions" => [] }]
    )

    post osv_query_url, params: { package: { name: "rails", ecosystem: "RubyGems" } }, as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 1, json["vulns"].length
  end

  test "returns OSV schema fields in response" do
    post osv_query_url, params: { package: { name: "lodash", ecosystem: "npm" } }, as: :json
    assert_response :success

    json = JSON.parse(response.body)
    vuln = json["vulns"].first

    assert_includes vuln.keys, "id"
    assert_includes vuln.keys, "summary"
    assert_includes vuln.keys, "modified"
    assert_includes vuln.keys, "affected"
    assert_includes vuln.keys, "references"
  end

  test "returns pagination token for large results" do
    102.times do |i|
      create(:advisory,
        source: @source,
        uuid: "GHSA-page-#{i.to_s.rjust(4, '0')}",
        packages: [{ "ecosystem" => "npm", "package_name" => "pagination-test", "versions" => [] }]
      )
    end

    post osv_query_url, params: { package: { name: "pagination-test", ecosystem: "npm" } }, as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 100, json["vulns"].length
    assert_not_nil json["next_page_token"]

    # Test second page
    post osv_query_url, params: { package: { name: "pagination-test", ecosystem: "npm" }, page_token: json["next_page_token"] }, as: :json
    assert_response :success

    json2 = JSON.parse(response.body)
    assert_equal 2, json2["vulns"].length
    assert_nil json2["next_page_token"]
  end

  test "handles empty request body" do
    post osv_query_url, params: {}, as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 2, json["vulns"].length
  end

  test "ecosystem is case-sensitive (OSV spec)" do
    # PyPI should work, pypi should also work (normalized internally)
    post osv_query_url, params: { package: { name: "django", ecosystem: "pypi" } }, as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 1, json["vulns"].length
  end
end
