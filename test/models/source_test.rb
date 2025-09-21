require "test_helper"
require "mocha/minitest"
require "webmock/minitest"

class SourceTest < ActiveSupport::TestCase
  def setup
    # Disable all HTTP requests
    WebMock.disable_net_connect!

    @source = Source.create!(name: "Test GitHub", kind: "github", url: "https://github.com/advisories")
  end

  def teardown
    WebMock.allow_net_connect!
  end

  test "sync_advisories processes pages without loading all into memory" do
    # Mock the GraphQL responses for pagination
    page1_response = {
      data: {
        securityVulnerabilities: {
          edges: [
            {
              node: {
                advisory: {
                  id: "GHSA-1111",
                  permalink: "https://github.com/advisories/GHSA-1111",
                  summary: "Test Advisory 1",
                  description: "Description 1",
                  origin: "GITHUB",
                  severity: "HIGH",
                  publishedAt: "2024-01-01T00:00:00Z",
                  updatedAt: "2024-01-02T00:00:00Z",
                  withdrawnAt: nil,
                  classification: "GENERAL",
                  cvssSeverities: { cvssV4: { score: 7.5, vectorString: "CVSS:4.0/..." } },
                  references: [{ url: "https://example.com/1" }],
                  identifiers: [{ value: "CVE-2024-1111" }],
                  epss: { percentage: 0.1, percentile: 0.5 }
                },
                package: { name: "test-package-1", ecosystem: "npm" },
                vulnerableVersionRange: "< 1.0.0",
                firstPatchedVersion: { identifier: "1.0.0" }
              }
            }
          ],
          pageInfo: { hasNextPage: true, endCursor: "cursor1" }
        }
      }
    }

    page2_response = {
      data: {
        securityVulnerabilities: {
          edges: [
            {
              node: {
                advisory: {
                  id: "GHSA-2222",
                  permalink: "https://github.com/advisories/GHSA-2222",
                  summary: "Test Advisory 2",
                  description: "Description 2",
                  origin: "GITHUB",
                  severity: "MEDIUM",
                  publishedAt: "2024-01-01T00:00:00Z",
                  updatedAt: "2024-01-02T00:00:00Z",
                  withdrawnAt: nil,
                  classification: "GENERAL",
                  cvssSeverities: { cvssV4: { score: 5.0, vectorString: "CVSS:4.0/..." } },
                  references: [{ url: "https://example.com/2" }],
                  identifiers: [{ value: "CVE-2024-2222" }],
                  epss: { percentage: 0.2, percentile: 0.6 }
                },
                package: { name: "test-package-2", ecosystem: "pypi" },
                vulnerableVersionRange: "< 2.0.0",
                firstPatchedVersion: { identifier: "2.0.0" }
              }
            }
          ],
          pageInfo: { hasNextPage: false, endCursor: "cursor2" }
        }
      }
    }

    # Stub GitHub GraphQL API calls
    stub_request(:post, "https://api.github.com/graphql")
      .to_return(
        { status: 200, body: page1_response.to_json, headers: { 'Content-Type' => 'application/json' } },
        { status: 200, body: page2_response.to_json, headers: { 'Content-Type' => 'application/json' } }
      )

    # Track advisory processing
    processed_advisories = []

    # Override the update! method to track what's being processed
    Advisory.any_instance.stubs(:update!).with do |data|
      processed_advisories << data[:uuid]
      true
    end

    # Run the sync
    @source.sync_advisories

    # Verify both pages were processed
    assert_equal 2, processed_advisories.size
    assert_includes processed_advisories, "GHSA-1111"
    assert_includes processed_advisories, "GHSA-2222"

    # Verify exactly 2 API calls were made (one per page)
    assert_requested :post, "https://api.github.com/graphql", times: 2
  end

  test "base source sync_advisories uses list_advisories for non-paginated sources" do
    # This test should not make any HTTP calls
    mock_source = Sources::Base.new(@source)

    test_advisories = [
      { uuid: "TEST-001", title: "Advisory 1" },
      { uuid: "TEST-002", title: "Advisory 2" }
    ]

    mock_source.stubs(:list_advisories).returns(test_advisories)

    # Track calls
    processed_advisories = []

    Advisory.any_instance.stubs(:update!).with do |data|
      processed_advisories << data[:uuid]
      true
    end

    mock_source.sync_advisories

    assert_equal 2, processed_advisories.size
    assert_includes processed_advisories, "TEST-001"
    assert_includes processed_advisories, "TEST-002"

    # Verify no HTTP calls were made
    assert_not_requested :any, /.*/
  end
end