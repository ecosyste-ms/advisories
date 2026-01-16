require "test_helper"

class Api::V1::SourcesControllerTest < ActionDispatch::IntegrationTest
  setup do
    @github_source = create(:source, name: "GitHub Advisory Database", kind: "github", url: "https://github.com/advisories")
    @erlef_source = create(:source, name: "Erlang Ecosystem Foundation", kind: "erlef", url: "https://cna.erlef.org")
    create(:advisory, source: @github_source)
    create(:advisory, source: @github_source)
    create(:advisory, source: @erlef_source)
  end

  test "should get index" do
    get api_v1_sources_url, as: :json
    assert_response :success

    json_response = JSON.parse(response.body)
    assert_equal 2, json_response.length
  end

  test "index returns sources ordered by name" do
    get api_v1_sources_url, as: :json
    assert_response :success

    json_response = JSON.parse(response.body)
    names = json_response.map { |s| s["name"] }
    assert_equal names.sort, names
  end

  test "index includes advisories_count" do
    get api_v1_sources_url, as: :json
    assert_response :success

    json_response = JSON.parse(response.body)
    github = json_response.find { |s| s["kind"] == "github" }
    erlef = json_response.find { |s| s["kind"] == "erlef" }

    assert_equal 2, github["advisories_count"]
    assert_equal 1, erlef["advisories_count"]
  end

  test "index returns expected fields" do
    get api_v1_sources_url, as: :json
    assert_response :success

    json_response = JSON.parse(response.body)
    source = json_response.first

    assert source.key?("id")
    assert source.key?("name")
    assert source.key?("kind")
    assert source.key?("url")
    assert source.key?("advisories_count")
    assert source.key?("created_at")
    assert source.key?("updated_at")
  end

  test "should get show by kind" do
    get api_v1_source_url("github"), as: :json
    assert_response :success

    json_response = JSON.parse(response.body)
    assert_equal "GitHub Advisory Database", json_response["name"]
    assert_equal "github", json_response["kind"]
  end

  test "should get show for erlef" do
    get api_v1_source_url("erlef"), as: :json
    assert_response :success

    json_response = JSON.parse(response.body)
    assert_equal "Erlang Ecosystem Foundation", json_response["name"]
    assert_equal "erlef", json_response["kind"]
  end

  test "show returns 404 for unknown source" do
    get api_v1_source_url("unknown"), as: :json
    assert_response :not_found
  end
end
