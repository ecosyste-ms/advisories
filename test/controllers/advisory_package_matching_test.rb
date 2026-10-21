require "test_helper"

class AdvisoryPackageMatchingTest < ActionDispatch::IntegrationTest
  setup do
    source = create(:source)
    @advisory = create(:advisory, source: source, packages: [
      { "ecosystem" => "npm", "package_name" => "jquery", "versions" => [] },
      { "ecosystem" => "rubygems", "package_name" => "jquery-rails", "versions" => [] }
    ])
  end

  test "API requires ecosystem and name on the same package before pagination" do
    get api_v1_advisories_url, params: { ecosystem: "rubygems", package_name: "jquery", per_page: 1 }, as: :json
    assert_response :success
    assert_empty response.parsed_body
    assert_equal "0", response.headers["total-count"]

    get api_v1_advisories_url, params: { ecosystem: "RubyGems", package_name: "JQUERY-RAILS" }, as: :json
    assert_response :success
    assert_equal [@advisory.uuid], response.parsed_body.pluck("uuid")
  end

  test "API preserves ecosystem-only and name-only filters" do
    [{ ecosystem: "rubygems" }, { package_name: "JQUERY" }].each do |filters|
      get api_v1_advisories_url, params: filters, as: :json
      assert_response :success
      assert_equal [@advisory.uuid], response.parsed_body.pluck("uuid")
    end
  end

  test "PURL lookup requires ecosystem and name on the same package" do
    get lookup_api_v1_advisories_url, params: { purl: "pkg:gem/jquery" }, as: :json
    assert_response :success
    assert_empty response.parsed_body

    get lookup_api_v1_advisories_url, params: { purl: "pkg:gem/jquery-rails" }, as: :json
    assert_response :success
    assert_equal [@advisory.uuid], response.parsed_body.pluck("uuid")
  end

  test "OSV package and PURL queries require ecosystem and name on the same package" do
    [{ package: { ecosystem: "RubyGems", name: "jquery" } }, { purl: "pkg:gem/jquery" }].each do |query|
      post osv_query_url, params: query, as: :json
      assert_response :success
      assert_empty response.parsed_body.fetch("vulns")
    end

    [{ package: { ecosystem: "RubyGems", name: "JQUERY-RAILS" } }, { purl: "pkg:gem/jquery-rails" }].each do |query|
      post osv_query_url, params: query, as: :json
      assert_response :success
      assert_equal [@advisory.uuid], response.parsed_body.fetch("vulns").pluck("id")
    end
  end

  test "OSV batch queries match each package within its ecosystem" do
    post osv_querybatch_url, params: { queries: [{ package: { ecosystem: "RubyGems", name: "jquery" } }, { purl: "pkg:gem/jquery-rails" }] }, as: :json
    assert_response :success
    results = response.parsed_body.fetch("results")
    assert_empty results.first.fetch("vulns")
    assert_equal [@advisory.uuid], results.last.fetch("vulns").pluck("id")
  end

  test "package page and ecosystem filters exclude cross-package matches" do
    get ecosystem_package_url("rubygems", "jquery")
    assert_response :success
    assert_empty assigns(:advisories)

    get ecosystem_url("rubygems"), params: { package_name: "jquery" }
    assert_response :success
    assert_empty assigns(:advisories)

    get ecosystem_package_url("rubygems", "jquery-rails")
    assert_response :success
    assert_equal [@advisory.id], assigns(:advisories).map(&:id)
  end

  test "package advisory counts exclude matches from another ecosystem" do
    package = create(:package, ecosystem: "rubygems", name: "jquery")
    package.update_advisories_count
    assert_equal 0, package.reload.advisories_count
  end
end
