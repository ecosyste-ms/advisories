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
    # Create registries for ecosystems
    create(:registry, name: "npmjs.org", ecosystem: "npm")
    create(:registry, name: "pypi.org", ecosystem: "pypi")

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
                  cvssSeverities: { cvssV4: { score: 7.5, vectorString: "CVSS:4.0/..." }, cvssV3: { score: nil, vectorString: nil } },
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
                  cvssSeverities: { cvssV4: { score: 5.0, vectorString: "CVSS:4.0/..." }, cvssV3: { score: nil, vectorString: nil } },
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

    # Stub package sync API calls (from after_create callback)
    stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+})
      .to_return(status: 200, body: {}.to_json, headers: {'Content-Type' => 'application/json'})
    stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/version_numbers})
      .to_return(status: 200, body: [].to_json, headers: {'Content-Type' => 'application/json'})
    stub_request(:post, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/ping})
      .to_return(status: 200, body: "", headers: {})

    # Reset request tracking
    WebMock::RequestRegistry.instance.reset!

    # Run the sync
    assert_difference 'Advisory.count', 2 do
      @source.sync_advisories
    end

    # Verify both advisories were created
    assert_not_nil Advisory.find_by(uuid: "GHSA-1111")
    assert_not_nil Advisory.find_by(uuid: "GHSA-2222")

    # Verify exactly 2 GraphQL API calls were made (one per page)
    assert_requested :post, "https://api.github.com/graphql", times: 2
  end

  test "base source sync_advisories uses list_advisories for non-paginated sources" do
    # Reset WebMock to ensure no stubs from previous tests
    WebMock.reset!

    # This test should not make any HTTP calls
    mock_source = Sources::Base.new(@source)

    test_advisories = [
      { uuid: "TEST-001", title: "Advisory 1" },
      { uuid: "TEST-002", title: "Advisory 2" }
    ]

    mock_source.stubs(:list_advisories).returns(test_advisories)

    # Run the sync
    assert_difference 'Advisory.count', 2 do
      mock_source.sync_advisories
    end

    # Verify both advisories were created
    assert_not_nil Advisory.find_by(uuid: "TEST-001")
    assert_not_nil Advisory.find_by(uuid: "TEST-002")

    # Verify no HTTP calls were made
    assert_not_requested :any, /.*/
  end

  test "sync_advisories updates existing advisory when data changed" do
    Sidekiq::Testing.fake! do
      # Create an existing advisory
      create(:advisory,
        source: @source,
        uuid: "GHSA-2222",
        title: "Old Title",
        description: "Old Description",
        severity: "MEDIUM",
        cvss_score: 5.0
      )

      # Mock GraphQL response with CHANGED data (different title)
      response = {
        data: {
          securityVulnerabilities: {
            edges: [
              {
                node: {
                  advisory: {
                    id: "GHSA-2222",
                    permalink: "https://github.com/advisories/GHSA-2222",
                    summary: "New Title",  # Changed!
                    description: "Old Description",
                    origin: "GITHUB",
                    severity: "MEDIUM",
                    publishedAt: "2024-01-01T00:00:00Z",
                    updatedAt: "2024-01-02T00:00:00Z",
                    withdrawnAt: nil,
                    classification: "GENERAL",
                    cvssSeverities: { cvssV4: { score: 5.0, vectorString: nil }, cvssV3: { score: nil, vectorString: nil } },
                    references: [{ url: "https://example.com" }],
                    identifiers: [],
                    epss: { percentage: nil, percentile: nil }
                  },
                  package: { name: "test-package", ecosystem: "NPM" },
                  vulnerableVersionRange: "< 1.0.0",
                  firstPatchedVersion: nil
                }
              }
            ],
            pageInfo: { hasNextPage: false, endCursor: "cursor1" }
          }
        }
      }

      stub_request(:post, "https://api.github.com/graphql")
        .to_return(status: 200, body: response.to_json, headers: { 'Content-Type' => 'application/json' })

      # Should enqueue PackageSyncWorker for changed advisory
      assert_difference 'PackageSyncWorker.jobs.size', 1 do
        @source.sync_advisories
      end

      # Verify the advisory was updated
      advisory = Advisory.find_by(uuid: "GHSA-2222")
      assert_equal "New Title", advisory.title
      assert_equal "Old Description", advisory.description
    end
  end

  test "sync_advisories creates new advisory when it doesn't exist" do
    Sidekiq::Testing.fake! do
      # Mock GraphQL response with new advisory
      response = {
        data: {
          securityVulnerabilities: {
            edges: [
              {
                node: {
                  advisory: {
                    id: "GHSA-3333",
                    permalink: "https://github.com/advisories/GHSA-3333",
                    summary: "Brand New Advisory",
                    description: "New Description",
                    origin: "GITHUB",
                    severity: "HIGH",
                    publishedAt: "2024-01-01T00:00:00Z",
                    updatedAt: "2024-01-02T00:00:00Z",
                    withdrawnAt: nil,
                    classification: "GENERAL",
                    cvssSeverities: { cvssV4: { score: 8.0, vectorString: nil }, cvssV3: { score: nil, vectorString: nil } },
                    references: [{ url: "https://example.com" }],
                    identifiers: [{ value: "CVE-2024-1234" }],
                    epss: { percentage: 0.5, percentile: 0.9 }
                  },
                  package: { name: "new-package", ecosystem: "NPM" },
                  vulnerableVersionRange: "< 2.0.0",
                  firstPatchedVersion: { identifier: "2.0.0" }
                }
              }
            ],
            pageInfo: { hasNextPage: false, endCursor: "cursor1" }
          }
        }
      }

      stub_request(:post, "https://api.github.com/graphql")
        .to_return(status: 200, body: response.to_json, headers: { 'Content-Type' => 'application/json' })

      assert_difference ['Advisory.count', 'PackageSyncWorker.jobs.size'], 1 do
        @source.sync_advisories
      end

      # Verify the new advisory was created correctly
      advisory = Advisory.find_by(uuid: "GHSA-3333")
      assert_not_nil advisory
      assert_equal "Brand New Advisory", advisory.title
      assert_equal "New Description", advisory.description
      assert_equal "HIGH", advisory.severity
      assert_equal 8.0, advisory.cvss_score
    end
  end

  test "sync_advisories does not enqueue jobs when advisory unchanged" do
    Sidekiq::Testing.fake! do
      # Create an existing advisory with ALL fields matching what GitHub will send
      create(:advisory,
        source: @source,
        uuid: "GHSA-4444",
        url: "https://github.com/advisories/GHSA-4444",
        title: "Same Title",
        description: "Same Description",
        origin: "GITHUB",
        severity: "MEDIUM",
        published_at: "2024-01-01T00:00:00Z",
        withdrawn_at: nil,
        classification: "GENERAL",
        cvss_score: 5.0,
        cvss_vector: nil,
        references: ["https://example.com"],
        source_kind: "github",
        identifiers: [],
        epss_percentage: nil,
        epss_percentile: nil,
        packages: [{ "ecosystem" => "npm", "package_name" => "test-package", "versions" => [{ "vulnerable_version_range" => "< 1.0.0", "first_patched_version" => nil }] }]
      )

      # Mock GraphQL response with IDENTICAL data
      response = {
        data: {
          securityVulnerabilities: {
            edges: [
              {
                node: {
                  advisory: {
                    id: "GHSA-4444",
                    permalink: "https://github.com/advisories/GHSA-4444",
                    summary: "Same Title",
                    description: "Same Description",
                    origin: "GITHUB",
                    severity: "MEDIUM",
                    publishedAt: "2024-01-01T00:00:00Z",
                    updatedAt: "2024-01-02T00:00:00Z",
                    withdrawnAt: nil,
                    classification: "GENERAL",
                    cvssSeverities: { cvssV4: { score: 5.0, vectorString: nil }, cvssV3: { score: nil, vectorString: nil } },
                    references: [{ url: "https://example.com" }],
                    identifiers: [],
                    epss: { percentage: nil, percentile: nil }
                  },
                  package: { name: "test-package", ecosystem: "NPM" },
                  vulnerableVersionRange: "< 1.0.0",
                  firstPatchedVersion: nil
                }
              }
            ],
            pageInfo: { hasNextPage: false, endCursor: "cursor1" }
          }
        }
      }

      stub_request(:post, "https://api.github.com/graphql")
        .to_return(status: 200, body: response.to_json, headers: { 'Content-Type' => 'application/json' })

      # Should NOT enqueue jobs since nothing changed
      assert_no_difference 'PackageSyncWorker.jobs.size' do
        @source.sync_advisories
      end

      # Advisory should still exist with same data
      advisory = Advisory.find_by(uuid: "GHSA-4444")
      assert_equal "Same Title", advisory.title
    end
  end

  test "sync_advisories falls back to cvssV3 when cvssV4 is not available" do
    Sidekiq::Testing.fake! do
      # Mock GraphQL response with cvssV4 null but cvssV3 present
      response = {
        data: {
          securityVulnerabilities: {
            edges: [
              {
                node: {
                  advisory: {
                    id: "GHSA-v3-fallback",
                    permalink: "https://github.com/advisories/GHSA-v3-fallback",
                    summary: "Advisory with CVSS V3 only",
                    description: "This advisory only has CVSS V3 score",
                    origin: "GITHUB",
                    severity: "MEDIUM",
                    publishedAt: "2024-01-01T00:00:00Z",
                    updatedAt: "2024-01-02T00:00:00Z",
                    withdrawnAt: nil,
                    classification: "GENERAL",
                    cvssSeverities: {
                      cvssV4: { score: nil, vectorString: nil },
                      cvssV3: { score: 5.3, vectorString: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N" }
                    },
                    references: [{ url: "https://example.com" }],
                    identifiers: [{ value: "CVE-2025-50181" }],
                    epss: { percentage: nil, percentile: nil }
                  },
                  package: { name: "urllib3", ecosystem: "PIP" },
                  vulnerableVersionRange: "< 2.0.0",
                  firstPatchedVersion: { identifier: "2.0.0" }
                }
              }
            ],
            pageInfo: { hasNextPage: false, endCursor: "cursor1" }
          }
        }
      }

      stub_request(:post, "https://api.github.com/graphql")
        .to_return(status: 200, body: response.to_json, headers: { 'Content-Type' => 'application/json' })

      assert_difference 'Advisory.count', 1 do
        @source.sync_advisories
      end

      # Verify the advisory was created with CVSS V3 data
      advisory = Advisory.find_by(uuid: "GHSA-v3-fallback")
      assert_not_nil advisory
      assert_equal 5.3, advisory.cvss_score
      assert_equal "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", advisory.cvss_vector
    end
  end

  test "sync_advisories prefers cvssV4 over cvssV3 when both are available" do
    Sidekiq::Testing.fake! do
      # Mock GraphQL response with both cvssV4 and cvssV3 present
      response = {
        data: {
          securityVulnerabilities: {
            edges: [
              {
                node: {
                  advisory: {
                    id: "GHSA-v4-preferred",
                    permalink: "https://github.com/advisories/GHSA-v4-preferred",
                    summary: "Advisory with both CVSS V4 and V3",
                    description: "This advisory has both CVSS versions",
                    origin: "GITHUB",
                    severity: "HIGH",
                    publishedAt: "2024-01-01T00:00:00Z",
                    updatedAt: "2024-01-02T00:00:00Z",
                    withdrawnAt: nil,
                    classification: "GENERAL",
                    cvssSeverities: {
                      cvssV4: { score: 8.5, vectorString: "CVSS:4.0/AV:N/AC:L/..." },
                      cvssV3: { score: 7.5, vectorString: "CVSS:3.1/AV:N/AC:L/..." }
                    },
                    references: [{ url: "https://example.com" }],
                    identifiers: [{ value: "CVE-2024-9999" }],
                    epss: { percentage: nil, percentile: nil }
                  },
                  package: { name: "test-pkg", ecosystem: "NPM" },
                  vulnerableVersionRange: "< 1.0.0",
                  firstPatchedVersion: { identifier: "1.0.0" }
                }
              }
            ],
            pageInfo: { hasNextPage: false, endCursor: "cursor1" }
          }
        }
      }

      stub_request(:post, "https://api.github.com/graphql")
        .to_return(status: 200, body: response.to_json, headers: { 'Content-Type' => 'application/json' })

      assert_difference 'Advisory.count', 1 do
        @source.sync_advisories
      end

      # Verify the advisory was created with CVSS V4 data (preferred)
      advisory = Advisory.find_by(uuid: "GHSA-v4-preferred")
      assert_not_nil advisory
      assert_equal 8.5, advisory.cvss_score
      assert_equal "CVSS:4.0/AV:N/AC:L/...", advisory.cvss_vector
    end
  end

  test "sync_advisories batches package sync jobs for multiple advisories" do
    Sidekiq::Testing.fake! do
      # Mock GraphQL response with multiple advisories affecting same package
      response = {
        data: {
          securityVulnerabilities: {
            edges: [
              {
                node: {
                  advisory: {
                    id: "GHSA-5555",
                    permalink: "https://github.com/advisories/GHSA-5555",
                    summary: "Advisory 1",
                    description: "Description 1",
                    origin: "GITHUB",
                    severity: "HIGH",
                    publishedAt: "2024-01-01T00:00:00Z",
                    updatedAt: "2024-01-02T00:00:00Z",
                    withdrawnAt: nil,
                    classification: "GENERAL",
                    cvssSeverities: { cvssV4: { score: 7.0, vectorString: nil }, cvssV3: { score: nil, vectorString: nil } },
                    references: [{ url: "https://example.com" }],
                    identifiers: [],
                    epss: { percentage: nil, percentile: nil }
                  },
                  package: { name: "shared-package", ecosystem: "NPM" },
                  vulnerableVersionRange: "< 1.0.0",
                  firstPatchedVersion: nil
                }
              },
              {
                node: {
                  advisory: {
                    id: "GHSA-6666",
                    permalink: "https://github.com/advisories/GHSA-6666",
                    summary: "Advisory 2",
                    description: "Description 2",
                    origin: "GITHUB",
                    severity: "MEDIUM",
                    publishedAt: "2024-01-01T00:00:00Z",
                    updatedAt: "2024-01-02T00:00:00Z",
                    withdrawnAt: nil,
                    classification: "GENERAL",
                    cvssSeverities: { cvssV4: { score: 5.0, vectorString: nil }, cvssV3: { score: nil, vectorString: nil } },
                    references: [{ url: "https://example.com" }],
                    identifiers: [],
                    epss: { percentage: nil, percentile: nil }
                  },
                  package: { name: "shared-package", ecosystem: "NPM" },
                  vulnerableVersionRange: "< 2.0.0",
                  firstPatchedVersion: nil
                }
              }
            ],
            pageInfo: { hasNextPage: false, endCursor: "cursor1" }
          }
        }
      }

      stub_request(:post, "https://api.github.com/graphql")
        .to_return(status: 200, body: response.to_json, headers: { 'Content-Type' => 'application/json' })

      # Should only enqueue 1 job for the shared package, not 2
      assert_difference 'PackageSyncWorker.jobs.size', 1 do
        assert_difference 'Advisory.count', 2 do
          @source.sync_advisories
        end
      end
    end
  end
end