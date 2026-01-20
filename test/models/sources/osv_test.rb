require "test_helper"
require "webmock/minitest"

class OsvSourceTest < ActiveSupport::TestCase
  def setup
    WebMock.disable_net_connect!
    @source = Source.create!(name: "OSV.dev", kind: "osv", url: "https://osv.dev")
    @osv = Sources::Osv.new(@source)
  end

  def teardown
    WebMock.allow_net_connect!
  end

  test "fetch_ecosystems retrieves list from GCS bucket" do
    ecosystems_content = "PyPI\nnpm\nGo\n"

    stub_request(:get, "https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt")
      .to_return(status: 200, body: ecosystems_content)

    ecosystems = @osv.fetch_ecosystems

    assert_equal ["PyPI", "npm", "Go"], ecosystems
  end

  test "ecosystem_zip_url encodes ecosystem names with spaces" do
    assert_equal "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip",
                 @osv.ecosystem_zip_url("PyPI")
    assert_equal "https://storage.googleapis.com/osv-vulnerabilities/GitHub%20Actions/all.zip",
                 @osv.ecosystem_zip_url("GitHub Actions")
  end

  test "map_osv_advisory extracts correct fields" do
    osv = sample_osv_advisory("GHSA-test-1234")
    mapped = @osv.map_osv_advisory(osv)

    assert_equal "GHSA-test-1234", mapped[:uuid]
    assert_equal "Test vulnerability summary", mapped[:title]
    assert_equal "Detailed description of the vulnerability.", mapped[:description]
    assert_equal "OSV", mapped[:origin]
    assert_equal "osv", mapped[:source_kind]
    assert_includes mapped[:identifiers], "GHSA-test-1234"
    assert_includes mapped[:identifiers], "CVE-2025-12345"
    assert_equal ["https://github.com/example/repo/security/advisories/GHSA-test-1234"], mapped[:references]
    assert_equal "2025-01-15T00:00:00Z", mapped[:published_at]
    assert_equal "2025-01-16T00:00:00Z", mapped[:updated_at]
  end

  test "map_osv_advisory extracts url from ADVISORY reference" do
    osv = sample_osv_advisory("GHSA-test-1234")
    mapped = @osv.map_osv_advisory(osv)

    assert_equal "https://github.com/example/repo/security/advisories/GHSA-test-1234", mapped[:url]
  end

  test "map_osv_advisory falls back to osv.dev url when no ADVISORY reference" do
    osv = sample_osv_advisory("GHSA-test-1234")
    osv[:references] = [{ type: "WEB", url: "https://example.com" }]
    mapped = @osv.map_osv_advisory(osv)

    assert_equal "https://osv.dev/vulnerability/GHSA-test-1234", mapped[:url]
  end

  test "map_osv_advisory extracts packages correctly" do
    osv = sample_osv_advisory("GHSA-test-1234")
    mapped = @osv.map_osv_advisory(osv)

    assert_equal 1, mapped[:packages].length
    package = mapped[:packages].first
    assert_equal "pypi", package[:ecosystem]
    assert_equal "test-package", package[:package_name]
    assert_equal 1, package[:versions].length
    assert_equal "< 1.0.0", package[:versions].first[:vulnerable_version_range]
    assert_equal "1.0.0", package[:versions].first[:first_patched_version]
  end

  test "correct_ecosystem maps known ecosystems" do
    assert_equal "pypi", @osv.correct_ecosystem("PyPI")
    assert_equal "npm", @osv.correct_ecosystem("npm")
    assert_equal "cargo", @osv.correct_ecosystem("crates.io")
    assert_equal "rubygems", @osv.correct_ecosystem("RubyGems")
    assert_equal "maven", @osv.correct_ecosystem("Maven")
    assert_equal "go", @osv.correct_ecosystem("Go")
    assert_equal "actions", @osv.correct_ecosystem("GitHub Actions")
  end

  test "correct_ecosystem excludes distro ecosystems" do
    assert_nil @osv.correct_ecosystem("Debian")
    assert_nil @osv.correct_ecosystem("Alpine")
    assert_nil @osv.correct_ecosystem("Ubuntu")
    assert_nil @osv.correct_ecosystem("Debian:12")
    assert_nil @osv.correct_ecosystem("Alpine:v3.17")
  end

  test "correct_ecosystem strips URL suffixes" do
    assert_equal "packagist", @osv.correct_ecosystem("Packagist:https://packages.drupal.org/8")
    assert_equal "vscode", @osv.correct_ecosystem("VSCode:https://open-vsx.org")
  end

  test "correct_ecosystem handles unknown ecosystems" do
    assert_equal "unknown", @osv.correct_ecosystem("Unknown")
    assert_equal "my-ecosystem", @osv.correct_ecosystem("My Ecosystem")
    assert_nil @osv.correct_ecosystem(nil)
  end

  test "build_version_range handles various cases" do
    assert_equal "< 1.0.0", @osv.build_version_range("0", "1.0.0")
    assert_equal ">= 0.5.0, < 1.0.0", @osv.build_version_range("0.5.0", "1.0.0")
    assert_equal ">= 0.5.0", @osv.build_version_range("0.5.0", nil)
    assert_equal ">= 0", @osv.build_version_range("0", nil)
    assert_nil @osv.build_version_range(nil, nil)
  end

  test "extract_version_ranges handles SEMVER type" do
    ranges = [
      {
        type: "SEMVER",
        events: [{ introduced: "0" }, { fixed: "1.0.0" }]
      }
    ]

    result = @osv.extract_version_ranges(ranges)

    assert_equal 1, result.length
    assert_equal "< 1.0.0", result.first[:vulnerable_version_range]
    assert_equal "1.0.0", result.first[:first_patched_version]
  end

  test "extract_version_ranges handles ECOSYSTEM type" do
    ranges = [
      {
        type: "ECOSYSTEM",
        events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }]
      }
    ]

    result = @osv.extract_version_ranges(ranges)

    assert_equal 1, result.length
    assert_equal ">= 1.0.0, < 2.0.0", result.first[:vulnerable_version_range]
  end

  test "extract_version_ranges ignores GIT type" do
    ranges = [
      {
        type: "GIT",
        repo: "https://github.com/example/repo",
        events: [{ introduced: "abc123" }, { fixed: "def456" }]
      }
    ]

    result = @osv.extract_version_ranges(ranges)

    assert_empty result
  end

  test "extract_cvss_vector prefers CVSS_V4" do
    severity = [
      { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
      { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }
    ]

    result = @osv.extract_cvss_vector(severity)

    assert_equal "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", result
  end

  test "extract_cvss_vector falls back to CVSS_V3" do
    severity = [
      { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }
    ]

    result = @osv.extract_cvss_vector(severity)

    assert_equal "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", result
  end

  test "extract_cvss_vector returns nil for empty severity" do
    assert_nil @osv.extract_cvss_vector(nil)
    assert_nil @osv.extract_cvss_vector([])
  end

  test "severity_from_score returns correct severity levels" do
    assert_equal "CRITICAL", @osv.severity_from_score(9.5)
    assert_equal "CRITICAL", @osv.severity_from_score(10.0)
    assert_equal "HIGH", @osv.severity_from_score(8.0)
    assert_equal "HIGH", @osv.severity_from_score(7.0)
    assert_equal "MEDIUM", @osv.severity_from_score(5.0)
    assert_equal "MEDIUM", @osv.severity_from_score(4.0)
    assert_equal "LOW", @osv.severity_from_score(3.0)
    assert_equal "LOW", @osv.severity_from_score(0.1)
    assert_nil @osv.severity_from_score(nil)
  end

  test "parse_cvss_score calculates correct CVSS 4.0 score" do
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    score = @osv.parse_cvss_score(vector)
    assert_equal 9.3, score
  end

  test "parse_cvss_score calculates correct CVSS 3.1 score" do
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = @osv.parse_cvss_score(vector)
    assert_equal 9.8, score
  end

  test "parse_cvss_score returns nil for invalid vector" do
    assert_nil @osv.parse_cvss_score(nil)
    assert_nil @osv.parse_cvss_score("invalid")
  end

  test "extract_identifiers includes id and aliases" do
    osv = { id: "GHSA-test-1234", aliases: ["CVE-2025-12345", "PYSEC-2025-1"] }
    identifiers = @osv.extract_identifiers(osv)

    assert_includes identifiers, "GHSA-test-1234"
    assert_includes identifiers, "CVE-2025-12345"
    assert_includes identifiers, "PYSEC-2025-1"
    assert_equal 3, identifiers.length
  end

  test "extract_identifiers handles missing aliases" do
    osv = { id: "GHSA-test-1234" }
    identifiers = @osv.extract_identifiers(osv)

    assert_equal ["GHSA-test-1234"], identifiers
  end

  test "extract_classification returns MALWARE for MAL- prefix" do
    assert_equal "MALWARE", @osv.extract_classification("MAL-2024-1234")
    assert_equal "MALWARE", @osv.extract_classification("MAL-123")
  end

  test "extract_classification returns nil for other prefixes" do
    assert_nil @osv.extract_classification("GHSA-1234-5678")
    assert_nil @osv.extract_classification("CVE-2024-1234")
    assert_nil @osv.extract_classification("PYSEC-2024-1")
    assert_nil @osv.extract_classification(nil)
  end

  test "map_osv_advisory handles advisory without packages" do
    osv = {
      id: "OSV-2025-GIT-ONLY",
      summary: "Git-only advisory",
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
      references: [{ type: "WEB", url: "https://example.com" }]
    }

    mapped = @osv.map_osv_advisory(osv)

    assert_not_nil mapped
    assert_equal "OSV-2025-GIT-ONLY", mapped[:uuid]
    assert_equal [], mapped[:packages]
  end

  test "fetch_ecosystem_advisories parses zip file" do
    Sidekiq::Testing.fake! do
      zip_content = create_test_zip([
        { name: "GHSA-test-1.json", content: sample_osv_advisory("GHSA-test-1").to_json },
        { name: "GHSA-test-2.json", content: sample_osv_advisory("GHSA-test-2").to_json }
      ])

      stub_request(:get, "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip")
        .to_return(status: 200, body: zip_content)

      advisories = @osv.fetch_ecosystem_advisories("PyPI")

      assert_equal 2, advisories.length
      assert_equal "GHSA-test-1", advisories[0][:id]
      assert_equal "GHSA-test-2", advisories[1][:id]
    end
  end

  test "sync_ecosystem creates advisories in database" do
    Sidekiq::Testing.fake! do
      zip_content = create_test_zip([
        { name: "GHSA-test-1.json", content: sample_osv_advisory("GHSA-test-1").to_json }
      ])

      stub_request(:get, "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip")
        .to_return(status: 200, body: zip_content)

      packages_to_sync = Set.new

      assert_difference "Advisory.count", 1 do
        @osv.sync_ecosystem("PyPI", packages_to_sync)
      end

      created = Advisory.find_by(uuid: "GHSA-test-1")
      assert_not_nil created
      assert_equal "Test vulnerability summary", created.title
      assert_equal @source, created.source

      assert_includes packages_to_sync, ["pypi", "test-package"]
    end
  end

  test "sync_ecosystem updates existing advisories" do
    Sidekiq::Testing.fake! do
      existing = Advisory.create!(
        uuid: "GHSA-test-1",
        title: "Old title",
        source: @source,
        packages: []
      )

      updated_advisory = sample_osv_advisory("GHSA-test-1")
      updated_advisory[:summary] = "Updated title"

      zip_content = create_test_zip([
        { name: "GHSA-test-1.json", content: updated_advisory.to_json }
      ])

      stub_request(:get, "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip")
        .to_return(status: 200, body: zip_content)

      packages_to_sync = Set.new

      assert_no_difference "Advisory.count" do
        @osv.sync_ecosystem("PyPI", packages_to_sync)
      end

      existing.reload
      assert_equal "Updated title", existing.title
    end
  end

  test "fetch_ecosystem_advisories returns empty array on HTTP failure" do
    stub_request(:get, "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip")
      .to_return(status: 404)

    advisories = @osv.fetch_ecosystem_advisories("PyPI")

    assert_equal [], advisories
  end

  test "fetch_ecosystem_advisories returns empty array on invalid zip" do
    stub_request(:get, "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip")
      .to_return(status: 200, body: "not a zip file")

    advisories = @osv.fetch_ecosystem_advisories("PyPI")

    assert_equal [], advisories
  end

  test "map_osv_advisory handles multiple packages" do
    osv = {
      id: "MULTI-PKG-001",
      summary: "Multi-package vulnerability",
      details: "Affects multiple packages",
      published: "2025-01-15T00:00:00Z",
      modified: "2025-01-16T00:00:00Z",
      affected: [
        {
          package: { ecosystem: "PyPI", name: "package-a" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }]
        },
        {
          package: { ecosystem: "PyPI", name: "package-b" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }]
        }
      ],
      references: []
    }

    mapped = @osv.map_osv_advisory(osv)

    assert_equal 2, mapped[:packages].length
    assert_equal "package-a", mapped[:packages][0][:package_name]
    assert_equal "package-b", mapped[:packages][1][:package_name]
  end

  test "extract_version_ranges handles multiple ranges" do
    ranges = [
      { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] },
      { type: "SEMVER", events: [{ introduced: "2.0.0" }, { fixed: "2.1.0" }] }
    ]

    result = @osv.extract_version_ranges(ranges)

    assert_equal 2, result.length
    assert_equal "< 1.0.0", result[0][:vulnerable_version_range]
    assert_equal ">= 2.0.0, < 2.1.0", result[1][:vulnerable_version_range]
  end

  test "extract_version_ranges handles last_affected without fixed" do
    ranges = [
      {
        type: "ECOSYSTEM",
        events: [{ introduced: "1.0.0" }, { last_affected: "1.5.0" }]
      }
    ]

    result = @osv.extract_version_ranges(ranges)

    assert_equal 1, result.length
    assert_equal ">= 1.0.0", result.first[:vulnerable_version_range]
    assert_nil result.first[:first_patched_version]
  end

  test "sync_ecosystem skips unchanged advisories" do
    Sidekiq::Testing.fake! do
      existing = Advisory.create!(
        uuid: "GHSA-unchanged",
        url: "https://github.com/example/repo/security/advisories/GHSA-test-1234",
        title: "Test vulnerability summary",
        description: "Detailed description of the vulnerability.",
        origin: "OSV",
        source_kind: "osv",
        severity: "CRITICAL",
        cvss_score: 9.8,
        cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        published_at: "2025-01-15T00:00:00Z",
        source: @source,
        packages: [{ "ecosystem" => "pypi", "package_name" => "test-package", "versions" => [{ "vulnerable_version_range" => "< 1.0.0", "first_patched_version" => "1.0.0" }] }],
        references: ["https://github.com/example/repo/security/advisories/GHSA-test-1234"],
        identifiers: ["GHSA-unchanged", "CVE-2025-12345"]
      )
      original_updated_at = existing.updated_at

      zip_content = create_test_zip([
        { name: "GHSA-unchanged.json", content: sample_osv_advisory("GHSA-unchanged").to_json }
      ])

      stub_request(:get, "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip")
        .to_return(status: 200, body: zip_content)

      packages_to_sync = Set.new
      @osv.sync_ecosystem("PyPI", packages_to_sync)

      existing.reload
      assert_equal original_updated_at, existing.updated_at
      assert_empty packages_to_sync
    end
  end

  test "advisory_changed? detects changes" do
    existing = Advisory.create!(
      uuid: "TEST-001",
      title: "Old title",
      source: @source,
      packages: []
    )

    new_attrs = { title: "New title", packages: [] }
    assert @osv.advisory_changed?(existing, new_attrs)

    same_attrs = { title: "Old title", packages: [] }
    refute @osv.advisory_changed?(existing, same_attrs)
  end

  def sample_osv_advisory(id)
    {
      id: id,
      summary: "Test vulnerability summary",
      details: "Detailed description of the vulnerability.",
      published: "2025-01-15T00:00:00Z",
      modified: "2025-01-16T00:00:00Z",
      aliases: ["CVE-2025-12345"],
      affected: [
        {
          package: {
            ecosystem: "PyPI",
            name: "test-package"
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
        { type: "ADVISORY", url: "https://github.com/example/repo/security/advisories/GHSA-test-1234" }
      ],
      severity: [
        { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }
      ]
    }
  end

  def create_test_zip(files)
    tempfile = Tempfile.new(['test', '.zip'])
    Zip::File.open(tempfile.path, create: true) do |zip|
      files.each do |file|
        zip.get_output_stream(file[:name]) { |f| f.write(file[:content]) }
      end
    end
    File.read(tempfile.path, mode: 'rb')
  end
end
