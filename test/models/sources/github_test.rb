require "test_helper"

class SourcesGithubTest < ActiveSupport::TestCase
  setup do
    @source = create(:source, kind: "github")
    @uuid = "GSA_kwCzR0hTQS01djh2LTY2djgtbXdtN84AAl70"
    @brotli = vulnerability("brotli", "PIP", ">= 0, < 1.0.8", "1.0.8")
    @dotnet = vulnerability("Microsoft.NETCore.App.Runtime.linux-arm", "NUGET", ">= 3.0.0, < 3.1.23", "3.1.23")
    @dotnet_later = vulnerability("Microsoft.NETCore.App.Runtime.linux-arm", "NUGET", ">= 6.0.0, < 6.0.3", "6.0.3")
    @cargo = vulnerability("compu-brotli-sys", "RUST", "< 1.0.9", "1.0.9")
  end

  test "sync retains packages and ranges across nonadjacent pages" do
    unrelated = vulnerability("another-package", "NPM", "< 2.0.0", "2.0.0")
    unrelated[:node][:advisory][:id] = "another-advisory"
    stub_pages([@brotli, @dotnet], [unrelated], [@dotnet_later, @cargo, @dotnet])

    Sidekiq::Testing.fake! do
      assert_difference "Advisory.count", 2 do
        @source.sync_advisories
      end
    end

    advisory = @source.advisories.find_by!(uuid: @uuid)
    assert_equal %w[brotli Microsoft.NETCore.App.Runtime.linux-arm compu-brotli-sys], advisory.packages.pluck("package_name")
    assert_equal [">= 0, < 1.0.8"], ranges_for(advisory, "brotli")
    assert_equal [">= 3.0.0, < 3.1.23", ">= 6.0.0, < 6.0.3"], ranges_for(advisory, "Microsoft.NETCore.App.Runtime.linux-arm")
    assert_equal ["< 1.0.9"], ranges_for(advisory, "compu-brotli-sys")
    assert_equal ["another-package"], @source.advisories.find_by!(uuid: "another-advisory").packages.pluck("package_name")
    assert_requested :post, "https://api.github.com/graphql", times: 3
  end

  test "a later sync replaces removed packages and version ranges" do
    Sidekiq::Testing.fake! do
      stub_pages([@brotli, @dotnet], [@dotnet_later, @cargo])
      @source.sync_advisories

      stub_pages([@brotli], [@dotnet_later])
      assert_no_difference "Advisory.count" do
        @source.sync_advisories
      end
    end

    advisory = @source.advisories.find_by!(uuid: @uuid)
    assert_equal %w[brotli Microsoft.NETCore.App.Runtime.linux-arm], advisory.packages.pluck("package_name")
    assert_equal [">= 0, < 1.0.8"], ranges_for(advisory, "brotli")
    assert_equal [">= 6.0.0, < 6.0.3"], ranges_for(advisory, "Microsoft.NETCore.App.Runtime.linux-arm")
  end

  test "sync merges later pages when the first page matches the stored advisory" do
    Sidekiq::Testing.fake! do
      stub_pages([@brotli])
      @source.sync_advisories
      advisory = @source.advisories.find_by!(uuid: @uuid)
      advisory.update_column(:packages, advisory.packages.map { |package| package.slice("ecosystem", "package_name", "versions") })

      stub_pages([@brotli], [@cargo])
      @source.sync_advisories

      assert_equal %w[brotli compu-brotli-sys], advisory.reload.packages.pluck("package_name")
    end
  end

  [
    ['NPM', 'npm', '>= 1.0.0, < 2.0.0', %w[0.9.0 1.0.0 1.5.0 2.0.0], %w[1.0.0 1.5.0], %w[0.9.0 2.0.0]],
    ['RUST', 'cargo', '>= 2.1.0, < 2.41.0', %w[2.0.0 2.1.0 2.40.0 2.41.0], %w[2.1.0 2.40.0], %w[2.0.0 2.41.0]],
    ['NPM', 'npm', '< 3.0.0', %w[1.7.0-alpha.2 1.7.0 3.0.0 3.1.0-alpha.1], %w[1.7.0-alpha.2 1.7.0], %w[3.0.0]],
    ['RUST', 'cargo', '< 3.0.0', %w[1.7.0-alpha.2 1.7.0 3.0.0 3.1.0-alpha.1], %w[1.7.0-alpha.2 1.7.0], %w[3.0.0]]
  ].each_with_index do |(github_ecosystem, ecosystem, range, numbers, affected, unaffected), index|
    test "sync caches affected and unaffected versions for #{ecosystem} range #{index}" do
      name = 'range-test-package'
      Sidekiq::Testing.fake! do
        create(:package, name: name, ecosystem: ecosystem, version_numbers: numbers)
        stub_pages([vulnerability(name, github_ecosystem, range, unaffected.last)])

        @source.sync_advisories
      end

      advisory = @source.advisories.find_by!(uuid: @uuid).reload
      package = advisory.packages.sole
      assert_equal ecosystem, package.fetch('ecosystem')
      assert_equal [range], package.fetch('versions').pluck('vulnerable_version_range')
      assert_equal affected.sort, package.fetch('affected_versions').sort
      assert_equal unaffected.sort, package.fetch('unaffected_versions').sort
      assert_requested :post, 'https://api.github.com/graphql'
    end
  end

  def vulnerability(name, ecosystem, range, patched_version)
    {
      node: {
        advisory: {
          id: @uuid,
          permalink: "https://github.com/advisories/GHSA-5v8v-66v8-mwm7",
          summary: "Integer overflow in the bundled Brotli C library",
          description: "A buffer overflow exists in Brotli versions prior to 1.0.8.",
          origin: "UNSPECIFIED",
          severity: "HIGH",
          publishedAt: "2022-05-24T17:28:21Z",
          updatedAt: "2024-09-16T14:29:05Z",
          withdrawnAt: nil,
          classification: "GENERAL",
          cvssSeverities: { cvssV3: { score: 7.5, vectorString: nil }, cvssV4: nil },
          references: [],
          identifiers: [{ value: "GHSA-5v8v-66v8-mwm7" }, { value: "CVE-2020-8927" }],
          epss: { percentage: nil, percentile: nil }
        },
        package: { name: name, ecosystem: ecosystem },
        vulnerableVersionRange: range,
        firstPatchedVersion: { identifier: patched_version }
      }
    }
  end

  def stub_pages(*pages)
    pages.each_with_index do |edges, index|
      cursor = index.zero? ? "null" : "\"cursor-#{index}\""
      response = {
        data: {
          securityVulnerabilities: {
            edges: edges,
            pageInfo: { hasNextPage: index < pages.length - 1, endCursor: "cursor-#{index + 1}" }
          }
        }
      }
      stub_request(:post, "https://api.github.com/graphql")
        .with { |request| JSON.parse(request.body).fetch("query").include?("after: #{cursor})") }
        .to_return(status: 200, body: response.to_json, headers: { "Content-Type" => "application/json" })
    end
  end

  def ranges_for(advisory, name)
    advisory.packages.find { |package| package["package_name"] == name }.fetch("versions").pluck("vulnerable_version_range")
  end
end
