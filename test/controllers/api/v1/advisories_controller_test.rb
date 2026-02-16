require "test_helper"

class Api::V1::AdvisoriesControllerTest < ActionDispatch::IntegrationTest
  setup do
    @source = create(:source)
    @advisory = create(:advisory, 
      source: @source, 
      packages: [
        {
          "ecosystem" => "npm",
          "package_name" => "lodash",
          "versions" => [
            {"vulnerable_version_range" => "< 4.17.21"}
          ]
        }
      ]
    )
  end

  test "should get index" do
    get api_v1_advisories_url, as: :json
    assert_response :success
    assert_match /max-age=300/, response.headers["Cache-Control"]
    assert_match /public/, response.headers["Cache-Control"]
    assert_match /stale-while-revalidate=3600/, response.headers["Cache-Control"]
  end

  test "should filter by ecosystem case-insensitively" do
    create(:advisory, source: @source, packages: [{"ecosystem" => "pypi", "package_name" => "test-pypi", "versions" => []}])
    
    get api_v1_advisories_url, params: { ecosystem: "PyPI" }, as: :json
    assert_response :success
    
    json_response = JSON.parse(response.body)
    assert_equal 1, json_response.length
    assert_equal "pypi", json_response.first["packages"].first["ecosystem"]
  end

  test "should filter by package_name case-insensitively" do
    create(:advisory, source: @source, packages: [{"ecosystem" => "npm", "package_name" => "Express", "versions" => []}])
    
    get api_v1_advisories_url, params: { ecosystem: "npm", package_name: "express" }, as: :json
    assert_response :success
    
    json_response = JSON.parse(response.body)
    assert_equal 1, json_response.length
    assert_equal "Express", json_response.first["packages"].first["package_name"]
  end

  test "should handle combined ecosystem and package_name filters" do
    create(:advisory, source: @source, packages: [{"ecosystem" => "pypi", "package_name" => "apache-airflow", "versions" => []}])
    create(:advisory, source: @source, packages: [{"ecosystem" => "pypi", "package_name" => "django", "versions" => []}])
    create(:advisory, source: @source, packages: [{"ecosystem" => "npm", "package_name" => "apache-airflow", "versions" => []}])
    
    get api_v1_advisories_url, params: { ecosystem: "pypi", package_name: "apache-airflow" }, as: :json
    assert_response :success
    
    json_response = JSON.parse(response.body)
    assert_equal 1, json_response.length
    package = json_response.first["packages"].first
    assert_equal "pypi", package["ecosystem"]
    assert_equal "apache-airflow", package["package_name"]
  end

  test "should get show" do
    get api_v1_advisory_url(@advisory), as: :json
    assert_response :success
    assert_match /max-age=3600/, response.headers["Cache-Control"]
    assert_match /public/, response.headers["Cache-Control"]
    assert response.headers["ETag"].present?
  end

  test "should include related_packages_url in show response" do
    get api_v1_advisory_url(@advisory), as: :json
    assert_response :success

    json_response = JSON.parse(response.body)
    assert json_response.key?("related_packages_url")
    assert_match %r{/api/v1/advisories/#{@advisory.uuid}/related_packages}, json_response["related_packages_url"]
  end

  test "should get related_packages endpoint with confidence fields" do
    pkg = create(:package, ecosystem: "conda", name: "lodash-conda")
    create(:related_package, advisory: @advisory, package: pkg, name_match: true, fork: true, repo_package_count: 5)

    get related_packages_api_v1_advisory_url(@advisory), as: :json
    assert_response :success

    json_response = JSON.parse(response.body)
    assert_equal 1, json_response.length
    entry = json_response.first
    assert_equal "conda", entry["ecosystem"]
    assert_equal "lodash-conda", entry["name"]
    assert_equal true, entry["name_match"]
    assert_equal true, entry["fork"]
    assert_equal 5, entry["repo_package_count"]
  end

  test "should return empty array from related_packages when none exist" do
    get related_packages_api_v1_advisory_url(@advisory), as: :json
    assert_response :success

    json_response = JSON.parse(response.body)
    assert_equal 0, json_response.length
  end

  test "should filter by source" do
    erlef_source = create(:source, kind: "erlef", url: "https://cna.erlef.org")
    create(:advisory, source: erlef_source, packages: [{"ecosystem" => "hex", "package_name" => "phoenix", "versions" => []}])

    get api_v1_advisories_url, params: { source: "erlef" }, as: :json
    assert_response :success

    json_response = JSON.parse(response.body)
    assert_equal 1, json_response.length
    assert_equal "hex", json_response.first["packages"].first["ecosystem"]
  end

  test "should filter by source github" do
    erlef_source = create(:source, kind: "erlef", url: "https://cna.erlef.org")
    create(:advisory, source: erlef_source, packages: [{"ecosystem" => "hex", "package_name" => "phoenix", "versions" => []}])

    get api_v1_advisories_url, params: { source: "github" }, as: :json
    assert_response :success

    json_response = JSON.parse(response.body)
    assert_equal 1, json_response.length
    assert_equal "npm", json_response.first["packages"].first["ecosystem"]
  end

  test "should get packages" do
    get packages_api_v1_advisories_url, as: :json
    assert_response :success
    assert_match /max-age=300/, response.headers["Cache-Control"]
    assert_match /public/, response.headers["Cache-Control"]
  end

  context "lookup endpoint" do
    should "return advisories for valid npm PURL" do
      get lookup_api_v1_advisories_url, params: { purl: "pkg:npm/lodash@4.17.20" }, as: :json
      
      assert_response :success
      json_response = JSON.parse(response.body)
      
      assert_equal 1, json_response.length
      assert_equal @advisory.uuid, json_response.first["uuid"]
      
      # Check that packages include PURL field
      packages = json_response.first["packages"]
      assert_equal 1, packages.length
      assert_equal "pkg:npm/lodash", packages.first["purl"]
    end

    should "return advisories for valid npm PURL without version" do
      get lookup_api_v1_advisories_url, params: { purl: "pkg:npm/lodash" }, as: :json
      
      assert_response :success
      json_response = JSON.parse(response.body)
      
      assert_equal 1, json_response.length
    end

    should "return empty advisories for package with no advisories" do
      get lookup_api_v1_advisories_url, params: { purl: "pkg:npm/nonexistent" }, as: :json
      
      assert_response :success
      json_response = JSON.parse(response.body)
      
      assert_equal 0, json_response.length
    end

    should "return bad request for missing purl parameter" do
      get lookup_api_v1_advisories_url, as: :json
      
      assert_response :bad_request
      json_response = JSON.parse(response.body)
      
      assert_equal "PURL parameter is required", json_response["error"]
    end

    should "return bad request for blank purl parameter" do
      get lookup_api_v1_advisories_url, params: { purl: "" }, as: :json
      
      assert_response :bad_request
      json_response = JSON.parse(response.body)
      
      assert_equal "PURL parameter is required", json_response["error"]
    end

    should "return bad request for invalid purl format" do
      get lookup_api_v1_advisories_url, params: { purl: "invalid-purl" }, as: :json
      
      assert_response :bad_request
      json_response = JSON.parse(response.body)
      
      assert_equal "Invalid PURL format", json_response["error"]
    end

    should "return bad request for unsupported ecosystem" do
      get lookup_api_v1_advisories_url, params: { purl: "pkg:unsupported/package@1.0.0" }, as: :json
      
      assert_response :bad_request
      json_response = JSON.parse(response.body)
      assert_equal "Invalid PURL format", json_response["error"]
    end

    should "handle rubygems ecosystem correctly" do
      create(:advisory, 
        source: @source, 
        packages: [
          {
            "ecosystem" => "rubygems",
            "package_name" => "rails",
            "versions" => [
              {"vulnerable_version_range" => "< 7.0.0"}
            ]
          }
        ]
      )

      get lookup_api_v1_advisories_url, params: { purl: "pkg:gem/rails@6.1.0" }, as: :json
      
      assert_response :success
      json_response = JSON.parse(response.body)
      
      assert_equal 1, json_response.length
    end

    should "handle pypi ecosystem correctly" do
      create(:advisory,
        source: @source,
        packages: [
          {
            "ecosystem" => "pypi",
            "package_name" => "django",
            "versions" => [
              {"vulnerable_version_range" => "< 3.2.0"}
            ]
          }
        ]
      )

      get lookup_api_v1_advisories_url, params: { purl: "pkg:pypi/django@3.1.0" }, as: :json

      assert_response :success
      json_response = JSON.parse(response.body)

      assert_equal 1, json_response.length
    end

    should "deduplicate advisories with same CVE" do
      erlef_source = create(:source, kind: "erlef", url: "https://cna.erlef.org")

      create(:advisory, source: @source,
        packages: [{"ecosystem" => "npm", "package_name" => "test-pkg", "versions" => []}],
        identifiers: ["CVE-2025-1234", "GHSA-test-1234"])

      create(:advisory, source: erlef_source, uuid: "EEF-CVE-2025-1234",
        packages: [{"ecosystem" => "npm", "package_name" => "test-pkg", "versions" => []}],
        identifiers: ["CVE-2025-1234", "EEF-CVE-2025-1234"])

      get lookup_api_v1_advisories_url, params: { purl: "pkg:npm/test-pkg" }, as: :json
      assert_response :success

      json_response = JSON.parse(response.body)
      assert_equal 1, json_response.length
    end

    should "include related_advisories in response" do
      erlef_source = create(:source, kind: "erlef", url: "https://cna.erlef.org")

      create(:advisory, source: @source,
        packages: [{"ecosystem" => "npm", "package_name" => "test-pkg", "versions" => []}],
        identifiers: ["CVE-2025-1234", "GHSA-test-1234"])

      create(:advisory, source: erlef_source, uuid: "EEF-CVE-2025-1234",
        packages: [{"ecosystem" => "npm", "package_name" => "test-pkg", "versions" => []}],
        identifiers: ["CVE-2025-1234", "EEF-CVE-2025-1234"])

      get lookup_api_v1_advisories_url, params: { purl: "pkg:npm/test-pkg" }, as: :json
      assert_response :success

      json_response = JSON.parse(response.body)
      related = json_response.first["related_advisories"]
      assert_equal 1, related.length
    end

    should "not deduplicate advisories without CVE" do
      create(:advisory, source: @source,
        packages: [{"ecosystem" => "npm", "package_name" => "test-pkg", "versions" => []}],
        identifiers: ["GHSA-aaaa-1111"])

      create(:advisory, source: @source, uuid: "GHSA-bbbb-2222",
        packages: [{"ecosystem" => "npm", "package_name" => "test-pkg", "versions" => []}],
        identifiers: ["GHSA-bbbb-2222"])

      get lookup_api_v1_advisories_url, params: { purl: "pkg:npm/test-pkg" }, as: :json
      assert_response :success

      json_response = JSON.parse(response.body)
      assert_equal 2, json_response.length
    end
  end
end