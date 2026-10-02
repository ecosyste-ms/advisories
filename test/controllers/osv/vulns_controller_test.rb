require "test_helper"

class Osv::VulnsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @source = create(:source)
    @advisory = create(:advisory,
      source: @source,
      uuid: "GHSA-xxxx-yyyy-zzzz",
      title: "Test Vulnerability",
      description: "A test vulnerability description",
      identifiers: ["GHSA-xxxx-yyyy-zzzz", "CVE-2023-12345"],
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      cvss_score: 9.8,
      severity: "critical",
      references: ["https://github.com/example/advisory"],
      packages: [
        {
          "ecosystem" => "npm",
          "package_name" => "lodash",
          "versions" => [
            { "vulnerable_version_range" => ">= 1.0.0, < 4.17.21", "first_patched_version" => "4.17.21" }
          ]
        }
      ],
      published_at: Time.zone.parse("2023-01-15 10:00:00 UTC")
    )
  end

  test "gets vulnerability by uuid" do
    get osv_vuln_url("GHSA-xxxx-yyyy-zzzz"), as: :json
    assert_response :success
    assert_match /max-age=3600/, response.headers["Cache-Control"]
    assert_match /public/, response.headers["Cache-Control"]

    json = JSON.parse(response.body)
    assert_equal "GHSA-xxxx-yyyy-zzzz", json["id"]
    assert_equal "Test Vulnerability", json["summary"]
    assert_equal "A test vulnerability description", json["details"]
  end

  test "gets vulnerability by CVE identifier" do
    get osv_vuln_url("CVE-2023-12345"), as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal "GHSA-xxxx-yyyy-zzzz", json["id"]
  end

  test "returns 404 for unknown ID" do
    get osv_vuln_url("GHSA-nonexistent"), as: :json
    assert_response :not_found

    json = JSON.parse(response.body)
    assert_equal({}, json)
  end

  test "returns full OSV format response" do
    get osv_vuln_url("GHSA-xxxx-yyyy-zzzz"), as: :json
    assert_response :success

    json = JSON.parse(response.body)

    # Required OSV fields
    assert_includes json.keys, "id"
    assert_includes json.keys, "modified"
    assert_includes json.keys, "published"
    assert_includes json.keys, "summary"
    assert_includes json.keys, "details"
    assert_includes json.keys, "aliases"
    assert_includes json.keys, "references"
    assert_includes json.keys, "affected"
    assert_includes json.keys, "severity"
    assert_includes json.keys, "database_specific"
  end

  test "returns correct affected structure" do
    get osv_vuln_url("GHSA-xxxx-yyyy-zzzz"), as: :json
    assert_response :success

    json = JSON.parse(response.body)
    affected = json["affected"]

    assert_equal 1, affected.length
    assert_equal "lodash", affected.first["package"]["name"]
    assert_equal "npm", affected.first["package"]["ecosystem"]
    assert_not_empty affected.first["ranges"]
  end

  test "returns correct range events structure" do
    get osv_vuln_url("GHSA-xxxx-yyyy-zzzz"), as: :json
    assert_response :success

    json = JSON.parse(response.body)
    ranges = json["affected"].first["ranges"]

    assert_equal 1, ranges.length
    assert_equal "ECOSYSTEM", ranges.first["type"]

    events = ranges.first["events"]
    introduced_event = events.find { |e| e.key?("introduced") }
    fixed_event = events.find { |e| e.key?("fixed") }

    assert_not_nil introduced_event
    assert_equal "1.0.0", introduced_event["introduced"]
    assert_not_nil fixed_event
    assert_equal "4.17.21", fixed_event["fixed"]
  end

  test "returns CVE in aliases" do
    get osv_vuln_url("GHSA-xxxx-yyyy-zzzz"), as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_includes json["aliases"], "CVE-2023-12345"
    refute_includes json["aliases"], "GHSA-xxxx-yyyy-zzzz"
  end

  test "returns severity with CVSS vector" do
    get osv_vuln_url("GHSA-xxxx-yyyy-zzzz"), as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal 1, json["severity"].length
    assert_equal "CVSS_V3", json["severity"].first["type"]
    assert_equal @advisory.cvss_vector, json["severity"].first["score"]
  end

  test "handles ID with special characters" do
    @advisory.update!(uuid: "MAL-2023-1234")
    @advisory.update!(identifiers: ["MAL-2023-1234"])

    get osv_vuln_url("MAL-2023-1234"), as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_equal "MAL-2023-1234", json["id"]
  end

  test "handles timestamps in ISO 8601 format" do
    get osv_vuln_url("GHSA-xxxx-yyyy-zzzz"), as: :json
    assert_response :success

    json = JSON.parse(response.body)
    assert_match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, json["published"])
    assert_match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, json["modified"])
  end
end
