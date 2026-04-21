require "test_helper"
require "webmock/minitest"

class CpansaSourceTest < ActiveSupport::TestCase
  def setup
    WebMock.disable_net_connect!
    @source = Source.create!(name: "CPAN Security Advisory Database", kind: "cpansa", url: "https://github.com/briandfoy/cpan-security-advisory")
    @cpansa = Sources::Cpansa.new(@source)
  end

  def teardown
    WebMock.allow_net_connect!
  end

  test "fetch_advisories flattens dists into advisory list" do
    stub_request(:get, Sources::Cpansa::DATA_URL)
      .to_return(status: 200, body: sample_payload.to_json)

    advisories = @cpansa.fetch_advisories

    assert_equal 3, advisories.length
    assert_equal "CPANSA-HTTP-Body-2013-4407", advisories[0]["id"]
    assert_equal "HTTP-Body", advisories[0]["distribution"]
    assert_equal "Catalyst-Controller-Combine", advisories[2]["distribution"]
  end

  test "fetch_advisories returns empty array on http failure" do
    stub_request(:get, Sources::Cpansa::DATA_URL).to_return(status: 500)

    assert_equal [], @cpansa.fetch_advisories
  end

  test "map_advisory extracts core fields" do
    mapped = @cpansa.map_advisory(http_body_advisory)

    assert_equal "CPANSA-HTTP-Body-2013-4407", mapped[:uuid]
    assert_equal "https://www.openwall.com/lists/oss-security/2024/04/07/1", mapped[:url]
    assert_equal "CPANSA", mapped[:origin]
    assert_equal "cpansa", mapped[:source_kind]
    assert_equal "MODERATE", mapped[:severity]
    assert_equal "2013-09-02", mapped[:published_at]
    assert_nil mapped[:withdrawn_at]
    assert_nil mapped[:cvss_score]
    assert_equal http_body_advisory["references"], mapped[:references]
    assert_equal "HTTP::Body::Multipart in the HTTP-Body 1.08, 1.22, and earlier module for Perl is vulnerable.", mapped[:description]
    assert_equal "HTTP::Body::Multipart in the HTTP-Body 1.08, 1.22, and earlier module for Perl is vulnerable.", mapped[:title]
  end

  test "map_advisory builds identifiers from id and cves" do
    mapped = @cpansa.map_advisory(http_body_advisory)

    assert_equal ["CPANSA-HTTP-Body-2013-4407", "CVE-2013-4407"], mapped[:identifiers]
  end

  test "map_advisory handles advisory without cves or references" do
    mapped = @cpansa.map_advisory(catalyst_advisory)

    assert_equal ["CPANSA-Catalyst-Controller-Combine-2010-01"], mapped[:identifiers]
    assert_equal Sources::Cpansa::REPO_URL, mapped[:url]
    assert_nil mapped[:severity]
  end

  test "map_advisory extracts package with normalized version ranges" do
    mapped = @cpansa.map_advisory(http_body_advisory)

    assert_equal 1, mapped[:packages].length
    package = mapped[:packages].first
    assert_equal "cpan", package[:ecosystem]
    assert_equal "HTTP-Body", package[:package_name]
    assert_equal 1, package[:versions].length
    assert_equal ">= 1.08, < 1.23", package[:versions].first[:vulnerable_version_range]
    assert_equal "1.23", package[:versions].first[:first_patched_version]
  end

  test "map_advisory pairs multiple affected ranges with fixed versions" do
    advisory = {
      "id" => "CPANSA-Multi-2020-01",
      "distribution" => "Multi-Dist",
      "description" => "Multiple ranges",
      "affected_versions" => ["==1.08", "==2.07"],
      "fixed_versions" => [">=2.08"],
      "cves" => [],
      "reported" => "2020-01-01"
    }

    mapped = @cpansa.map_advisory(advisory)
    versions = mapped[:packages].first[:versions]

    assert_equal 2, versions.length
    assert_equal "= 1.08", versions[0][:vulnerable_version_range]
    assert_equal "2.08", versions[0][:first_patched_version]
    assert_equal "= 2.07", versions[1][:vulnerable_version_range]
    assert_equal "2.08", versions[1][:first_patched_version]
  end

  test "map_advisory derives range from fixed_versions when affected is empty" do
    advisory = {
      "id" => "CPANSA-FixedOnly-2020-01",
      "distribution" => "Fixed-Only",
      "description" => "Only fixed version known",
      "affected_versions" => [],
      "fixed_versions" => [">=1.5.0"],
      "cves" => [],
      "reported" => "2020-01-01"
    }

    mapped = @cpansa.map_advisory(advisory)
    versions = mapped[:packages].first[:versions]

    assert_equal 1, versions.length
    assert_equal "< 1.5.0", versions[0][:vulnerable_version_range]
    assert_equal "1.5.0", versions[0][:first_patched_version]
  end

  test "map_advisory returns no packages when no version info" do
    advisory = {
      "id" => "CPANSA-Empty-2020-01",
      "distribution" => "Empty-Dist",
      "description" => "No version info",
      "affected_versions" => [],
      "fixed_versions" => [],
      "cves" => [],
      "reported" => "2020-01-01"
    }

    mapped = @cpansa.map_advisory(advisory)

    assert_equal [], mapped[:packages]
  end

  test "normalize_range handles operator and bare version formats" do
    assert_equal "< 0.12", @cpansa.normalize_range("<0.12")
    assert_equal ">= 1.08, < 1.23", @cpansa.normalize_range(">=1.08,<1.23")
    assert_equal "= 1.08", @cpansa.normalize_range("==1.08")
    assert_equal "= 1.9.1", @cpansa.normalize_range("1.9.1")
    assert_equal "<= 5.2.1.2", @cpansa.normalize_range("<=5.2.1.2")
    assert_equal "> 7.83, < 7.92", @cpansa.normalize_range(">7.83,<7.92")
    assert_nil @cpansa.normalize_range(nil)
    assert_nil @cpansa.normalize_range("")
  end

  test "extract_patched_version strips leading operator" do
    assert_equal "1.23", @cpansa.extract_patched_version(">=1.23")
    assert_equal "1.23", @cpansa.extract_patched_version(">= 1.23")
    assert_equal "1.23", @cpansa.extract_patched_version(">1.23")
    assert_equal "1.23", @cpansa.extract_patched_version("1.23")
    assert_nil @cpansa.extract_patched_version(nil)
    assert_nil @cpansa.extract_patched_version("")
  end

  test "normalize_severity maps cpansa values to standard set" do
    assert_equal "CRITICAL", @cpansa.normalize_severity("critical")
    assert_equal "HIGH", @cpansa.normalize_severity("high")
    assert_equal "MODERATE", @cpansa.normalize_severity("moderate")
    assert_equal "MODERATE", @cpansa.normalize_severity("medium")
    assert_equal "LOW", @cpansa.normalize_severity("low")
    assert_equal "LOW", @cpansa.normalize_severity("minor")
    assert_nil @cpansa.normalize_severity(nil)
    assert_nil @cpansa.normalize_severity("unknown")
  end

  test "derive_title falls back to id when description blank" do
    advisory = { "id" => "CPANSA-Test-2020-01", "description" => "" }
    assert_equal "CPANSA-Test-2020-01", @cpansa.derive_title(advisory)
  end

  test "derive_title uses first line of description" do
    advisory = { "id" => "CPANSA-Test-2020-01", "description" => "First line.\nSecond line." }
    assert_equal "First line.", @cpansa.derive_title(advisory)
  end

  test "sync_advisories creates advisories in database" do
    Sidekiq::Testing.fake! do
      stub_request(:get, Sources::Cpansa::DATA_URL)
        .to_return(status: 200, body: sample_payload.to_json)

      assert_difference "Advisory.count", 3 do
        @source.sync_advisories
      end

      created = Advisory.find_by(uuid: "CPANSA-HTTP-Body-2013-4407")
      assert_not_nil created
      assert_equal @source, created.source
      assert_equal "MODERATE", created.severity
      assert_includes created.identifiers, "CVE-2013-4407"
      assert_equal "cpan", created.packages.first["ecosystem"]
      assert_equal "HTTP-Body", created.packages.first["package_name"]
    end
  end

  def sample_payload
    {
      "meta" => { "date" => "Sun Apr 19 16:34:00 2026" },
      "dists" => {
        "HTTP-Body" => {
          "advisories" => [http_body_advisory, http_body_second_advisory],
          "main_module" => "HTTP::Body"
        },
        "Catalyst-Controller-Combine" => {
          "advisories" => [catalyst_advisory],
          "main_module" => "Catalyst::Controller::Combine"
        }
      }
    }
  end

  def http_body_advisory
    {
      "id" => "CPANSA-HTTP-Body-2013-4407",
      "distribution" => "HTTP-Body",
      "severity" => "moderate",
      "fixed_versions" => [">=1.23"],
      "reported" => "2013-09-02",
      "affected_versions" => [">=1.08,<1.23"],
      "cves" => ["CVE-2013-4407"],
      "description" => "HTTP::Body::Multipart in the HTTP-Body 1.08, 1.22, and earlier module for Perl is vulnerable.\n",
      "references" => [
        "https://www.openwall.com/lists/oss-security/2024/04/07/1",
        "https://security-tracker.debian.org/tracker/CVE-2013-4407"
      ]
    }
  end

  def http_body_second_advisory
    {
      "id" => "CPANSA-HTTP-Body-2020-01",
      "distribution" => "HTTP-Body",
      "severity" => "high",
      "fixed_versions" => [],
      "reported" => "2020-01-01",
      "affected_versions" => ["<1.30"],
      "cves" => [],
      "description" => "Another issue.\n",
      "references" => ["https://metacpan.org/changes/distribution/HTTP-Body"]
    }
  end

  def catalyst_advisory
    {
      "id" => "CPANSA-Catalyst-Controller-Combine-2010-01",
      "distribution" => "Catalyst-Controller-Combine",
      "fixed_versions" => [">=0.12"],
      "reported" => "2010-05-21",
      "affected_versions" => ["<0.12"],
      "cves" => [],
      "description" => "Allows reading files outside the intended directory.\n"
    }
  end
end
