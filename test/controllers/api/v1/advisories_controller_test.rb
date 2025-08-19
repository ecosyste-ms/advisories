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
  end

  test "should get show" do
    get api_v1_advisory_url(@advisory), as: :json
    assert_response :success
  end

  test "should get packages" do
    get packages_api_v1_advisories_url, as: :json
    assert_response :success
  end

  context "lookup endpoint" do
    should "return advisories for valid npm PURL" do
      get lookup_api_v1_advisories_url, params: { purl: "pkg:npm/lodash@4.17.20" }, as: :json
      
      assert_response :success
      json_response = JSON.parse(response.body)
      
      assert_equal 1, json_response.length
      assert_equal @advisory.uuid, json_response.first["uuid"]
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
  end
end