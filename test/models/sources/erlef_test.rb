require "test_helper"
require "webmock/minitest"

class ErlefSourceTest < ActiveSupport::TestCase
  def setup
    WebMock.disable_net_connect!
    @source = Source.create!(name: "Erlang Ecosystem Foundation", kind: "erlef", url: "https://cna.erlef.org")
    @erlef = Sources::Erlef.new(@source)
  end

  def teardown
    WebMock.allow_net_connect!
  end

  test "fetch_advisories retrieves all advisories from index" do
    index_response = [
      { "id" => "EEF-CVE-2025-0001", "modified" => "2025-01-01T00:00:00Z" },
      { "id" => "EEF-CVE-2025-0002", "modified" => "2025-01-02T00:00:00Z" }
    ]

    advisory1 = sample_osv_advisory("EEF-CVE-2025-0001")
    advisory2 = sample_osv_advisory("EEF-CVE-2025-0002")

    stub_request(:get, "https://cna.erlef.org/osv/all.json")
      .to_return(status: 200, body: index_response.to_json)

    stub_request(:get, "https://cna.erlef.org/osv/EEF-CVE-2025-0001.json")
      .to_return(status: 200, body: advisory1.to_json)

    stub_request(:get, "https://cna.erlef.org/osv/EEF-CVE-2025-0002.json")
      .to_return(status: 200, body: advisory2.to_json)

    advisories = @erlef.fetch_advisories

    assert_equal 2, advisories.length
    assert_equal "EEF-CVE-2025-0001", advisories[0][:id]
    assert_equal "EEF-CVE-2025-0002", advisories[1][:id]
  end

  test "map_osv_advisory extracts correct fields" do
    osv = sample_osv_advisory("EEF-CVE-2025-48042")
    mapped = @erlef.map_osv_advisory(osv)

    assert_equal "EEF-CVE-2025-48042", mapped[:uuid]
    assert_equal "Test vulnerability summary", mapped[:title]
    assert_equal "Detailed description of the vulnerability.", mapped[:description]
    assert_equal "ERLEF", mapped[:origin]
    assert_equal "erlef", mapped[:source_kind]
    assert_includes mapped[:identifiers], "EEF-CVE-2025-48042"
    assert_includes mapped[:identifiers], "CVE-2025-48042"
    assert_includes mapped[:identifiers], "GHSA-test-test"
    assert_equal ["https://github.com/example/repo/security/advisories/GHSA-test-test"], mapped[:references]
    assert_equal "2025-01-15T00:00:00Z", mapped[:published_at]
    assert_equal "2025-01-16T00:00:00Z", mapped[:updated_at]
  end

  test "map_osv_advisory extracts packages correctly" do
    osv = sample_osv_advisory("EEF-CVE-2025-48042")
    mapped = @erlef.map_osv_advisory(osv)

    assert_equal 1, mapped[:packages].length
    package = mapped[:packages].first
    assert_equal "hex", package[:ecosystem]
    assert_equal "test_package", package[:package_name]
    assert_equal 1, package[:versions].length
    assert_equal "< 1.0.0", package[:versions].first[:vulnerable_version_range]
    assert_equal "1.0.0", package[:versions].first[:first_patched_version]
  end

  test "build_version_range handles various cases" do
    assert_equal "< 1.0.0", @erlef.build_version_range("0", "1.0.0")
    assert_equal ">= 0.5.0, < 1.0.0", @erlef.build_version_range("0.5.0", "1.0.0")
    assert_equal ">= 0.5.0", @erlef.build_version_range("0.5.0", nil)
    assert_nil @erlef.build_version_range("0", nil)
    assert_nil @erlef.build_version_range(nil, nil)
  end

  test "correct_ecosystem normalizes Hex to hex" do
    assert_equal "hex", @erlef.correct_ecosystem("Hex")
    assert_equal "hex", @erlef.correct_ecosystem("HEX")
    assert_equal "npm", @erlef.correct_ecosystem("npm")
  end

  test "severity_from_score returns correct severity levels" do
    assert_equal "CRITICAL", @erlef.severity_from_score(9.5)
    assert_equal "CRITICAL", @erlef.severity_from_score(10.0)
    assert_equal "HIGH", @erlef.severity_from_score(8.0)
    assert_equal "HIGH", @erlef.severity_from_score(7.0)
    assert_equal "MEDIUM", @erlef.severity_from_score(5.0)
    assert_equal "MEDIUM", @erlef.severity_from_score(4.0)
    assert_equal "LOW", @erlef.severity_from_score(3.0)
    assert_equal "LOW", @erlef.severity_from_score(0.1)
    assert_nil @erlef.severity_from_score(nil)
  end

  test "parse_cvss_score extracts score from CVSS 4.0 vector" do
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    score = @erlef.parse_cvss_score(vector)
    assert score > 0
    assert score <= 10
  end

  test "parse_cvss_score returns nil for invalid vector" do
    assert_nil @erlef.parse_cvss_score(nil)
    assert_nil @erlef.parse_cvss_score("invalid")
  end

  test "sync_advisories creates advisories in database" do
    Sidekiq::Testing.fake! do
      index_response = [{ "id" => "EEF-CVE-2025-0001", "modified" => "2025-01-01T00:00:00Z" }]
      advisory = sample_osv_advisory("EEF-CVE-2025-0001")

      stub_request(:get, "https://cna.erlef.org/osv/all.json")
        .to_return(status: 200, body: index_response.to_json)

      stub_request(:get, "https://cna.erlef.org/osv/EEF-CVE-2025-0001.json")
        .to_return(status: 200, body: advisory.to_json)

      assert_difference "Advisory.count", 1 do
        @source.sync_advisories
      end

      created = Advisory.find_by(uuid: "EEF-CVE-2025-0001")
      assert_not_nil created
      assert_equal "Test vulnerability summary", created.title
      assert_equal @source, created.source
    end
  end

  test "map_osv_advisory skips advisories without semver packages" do
    osv = {
      id: "EEF-CVE-2025-GIT-ONLY",
      summary: "Test",
      details: "Details",
      published: "2025-01-15T00:00:00Z",
      modified: "2025-01-16T00:00:00Z",
      affected: [
        {
          ranges: [
            {
              type: "GIT",
              repo: "https://github.com/example/repo",
              events: [{ introduced: "abc123" }, { fixed: "def456" }]
            }
          ]
        }
      ],
      references: [],
      aliases: []
    }

    mapped = @erlef.map_osv_advisory(osv)
    assert_nil mapped
  end

  def sample_osv_advisory(id)
    {
      id: id,
      summary: "Test vulnerability summary",
      details: "Detailed description of the vulnerability.",
      published: "2025-01-15T00:00:00Z",
      modified: "2025-01-16T00:00:00Z",
      aliases: ["CVE-2025-48042", "GHSA-test-test"],
      affected: [
        {
          package: {
            ecosystem: "Hex",
            name: "test_package",
            purl: "pkg:hex/test_package"
          },
          ranges: [
            {
              type: "SEMVER",
              events: [
                { introduced: "0" },
                { fixed: "1.0.0" }
              ]
            }
          ]
        }
      ],
      references: [
        { type: "ADVISORY", url: "https://github.com/example/repo/security/advisories/GHSA-test-test" }
      ],
      severity: [
        { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N" }
      ],
      database_specific: {
        cwe_ids: ["CWE-22"]
      }
    }
  end
end
