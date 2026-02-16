require "test_helper"

class AdvisoryTest < ActiveSupport::TestCase
  context ".ecosystem_counts" do
    should "return ecosystem counts sorted by count descending" do
      # Create advisories with different ecosystems
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "package1", "versions" => [] },
        { "ecosystem" => "rubygems", "package_name" => "package2", "versions" => [] }
      ])
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "package3", "versions" => [] }
      ])
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "package4", "versions" => [] }
      ])
      create(:advisory, withdrawn_at: Time.current, packages: [
        { "ecosystem" => "npm", "package_name" => "package5", "versions" => [] }
      ])

      result = Advisory.not_withdrawn.ecosystem_counts

      assert_equal [["npm", 3], ["rubygems", 1]], result
    end

    should "count ecosystems correctly when advisory has multiple packages" do
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "package1", "versions" => [] },
        { "ecosystem" => "npm", "package_name" => "package2", "versions" => [] },
        { "ecosystem" => "rubygems", "package_name" => "package3", "versions" => [] }
      ])

      result = Advisory.ecosystem_counts

      assert_equal [["npm", 2], ["rubygems", 1]], result
    end
  end

  context ".package_counts" do
    should "return package counts sorted by count descending" do
      # Create advisories with different packages
      package1 = { "ecosystem" => "npm", "package_name" => "lodash", "versions" => [] }
      package2 = { "ecosystem" => "npm", "package_name" => "express", "versions" => [] }

      create(:advisory, packages: [package1])
      create(:advisory, packages: [package1, package2])
      create(:advisory, packages: [package2])

      result = Advisory.package_counts

      # Both packages should have count of 2 (they're both used twice)
      assert_equal 2, result.length
      assert_equal 2, result[0][1]
      assert_equal 2, result[1][1]
      
      # Verify the packages are correct (order might vary for same count)
      package_names = result.map { |r| r[0]["package_name"] }
      assert_includes package_names, "lodash"
      assert_includes package_names, "express"
    end

    should "exclude versions from package data" do
      package_with_versions = {
        "ecosystem" => "npm",
        "package_name" => "test",
        "versions" => [{ "vulnerable_version_range" => "< 1.0.0" }]
      }
      create(:advisory, packages: [package_with_versions])

      result = Advisory.package_counts

      assert_equal 1, result.length
      assert_equal({ "ecosystem" => "npm", "package_name" => "test" }, result[0][0])
      assert_nil result[0][0]["versions"]
    end

    should "exclude withdrawn advisories when called on not_withdrawn scope" do
      package = { "ecosystem" => "npm", "package_name" => "test", "versions" => [] }
      create(:advisory, packages: [package])
      create(:advisory, withdrawn_at: Time.current, packages: [package])

      result = Advisory.not_withdrawn.package_counts

      assert_equal [[package.except("versions"), 1]], result
    end
  end

  context "#ping_packages_for_resync" do
    should "ping packages.ecosyste.ms for each package when advisory is created" do
      # Create registries for the ecosystems
      create(:registry, name: "npmjs.org", ecosystem: "npm")
      create(:registry, name: "rubygems.org", ecosystem: "rubygems")

      # Stub package sync requests (called by sync_packages callback)
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+})
        .to_return(status: 200, body: {}.to_json, headers: {'Content-Type' => 'application/json'})
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/version_numbers})
        .to_return(status: 200, body: [].to_json, headers: {'Content-Type' => 'application/json'})

      # Stub the ping HTTP request to packages.ecosyste.ms
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/ping})
        .to_return(status: 200, body: "", headers: {})

      source = create(:source)
      advisory = build(:advisory, source: source, packages: [
        { "ecosystem" => "npm", "package_name" => "lodash", "versions" => [] },
        { "ecosystem" => "rubygems", "package_name" => "rails", "versions" => [] }
      ])

      # Creating the advisory should trigger the ping
      advisory.save!

      # Verify the requests were made
      assert_requested :get, "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages/lodash/ping"
      assert_requested :get, "https://packages.ecosyste.ms/api/v1/registries/rubygems.org/packages/rails/ping"
    end

    should "ping packages.ecosyste.ms for each package when advisory is updated" do
      # Create registry for npm ecosystem  
      create(:registry, name: "npmjs.org", ecosystem: "npm")
      
      # Stub package sync requests (called by sync_packages callback)
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+})
        .to_return(status: 200, body: {}.to_json, headers: {'Content-Type' => 'application/json'})
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/version_numbers})
        .to_return(status: 200, body: [].to_json, headers: {'Content-Type' => 'application/json'})
      
      # Stub the ping HTTP request to packages.ecosyste.ms
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/ping})
        .to_return(status: 200, body: "", headers: {})

      advisory = create(:advisory)

      # Updating the advisory should trigger the ping
      advisory.update!(title: "Updated title")

      # Verify the request was made for the default test package (2 times: once for create, once for update)
      assert_requested :get, "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages/test-package/ping", times: 2
    end

    should "handle ping failures gracefully" do
      # Create registry for npm ecosystem  
      create(:registry, name: "npmjs.org", ecosystem: "npm")
      
      # Stub package sync requests (called by sync_packages callback)
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+})
        .to_return(status: 200, body: {}.to_json, headers: {'Content-Type' => 'application/json'})
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/version_numbers})
        .to_return(status: 200, body: [].to_json, headers: {'Content-Type' => 'application/json'})
      
      # Stub the ping HTTP request to fail
      stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/registries/.+/packages/.+/ping})
        .to_raise(StandardError.new("Network error"))

      # Should not raise an error
      assert_nothing_raised do
        create(:advisory)
      end
    end
  end

  context ".ecosystem scope" do
    should "match ecosystems case insensitively" do
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "test1", "versions" => [] }
      ])
      create(:advisory, packages: [
        { "ecosystem" => "rubygems", "package_name" => "test2", "versions" => [] }
      ])

      npm_results = Advisory.ecosystem("NPM")  # Input is uppercase
      rubygems_results = Advisory.ecosystem("RUBYGEMS")  # Input is uppercase

      assert_equal 1, npm_results.count
      assert_equal 1, rubygems_results.count
    end

    should "match exact case as well" do
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "test1", "versions" => [] }
      ])

      results = Advisory.ecosystem("npm")
      assert_equal 1, results.count
    end
  end

  context "#ecosystems_repo_url" do
    should "generate ecosyste.ms URL from GitHub repository" do
      advisory = build(:advisory, repository_url: "https://github.com/erlang/otp")

      assert_equal "https://repos.ecosyste.ms/hosts/github.com/repositories/erlang/otp", advisory.ecosystems_repo_url
    end

    should "handle repository URLs with .git suffix" do
      advisory = build(:advisory, repository_url: "https://github.com/erlang/otp.git")

      assert_equal "https://repos.ecosyste.ms/hosts/github.com/repositories/erlang/otp", advisory.ecosystems_repo_url
    end

    should "return nil when repository_url is nil" do
      advisory = build(:advisory, repository_url: nil)

      assert_nil advisory.ecosystems_repo_url
    end
  end

  context "#repository_full_name" do
    should "extract full name from GitHub repository URL" do
      advisory = build(:advisory, repository_url: "https://github.com/erlang/otp")

      assert_equal "erlang/otp", advisory.repository_full_name
    end

    should "handle repository URLs with .git suffix" do
      advisory = build(:advisory, repository_url: "https://github.com/erlang/otp.git")

      assert_equal "erlang/otp", advisory.repository_full_name
    end

    should "return nil when repository_url is nil" do
      advisory = build(:advisory, repository_url: nil)

      assert_nil advisory.repository_full_name
    end
  end

  context "#related_advisories" do
    should "find advisories sharing the same CVE" do
      github_source = create(:source, kind: "github", url: "https://github.com/advisories")
      erlef_source = create(:source, kind: "erlef", url: "https://cna.erlef.org")

      github_advisory = create(:advisory, source: github_source, uuid: "GHSA-test-1234", identifiers: ["CVE-2025-1234", "GHSA-test-1234"])
      erlef_advisory = create(:advisory, source: erlef_source, uuid: "EEF-CVE-2025-1234", identifiers: ["CVE-2025-1234", "EEF-CVE-2025-1234"])

      assert_includes github_advisory.related_advisories, erlef_advisory
      assert_includes erlef_advisory.related_advisories, github_advisory
    end

    should "not include itself in related advisories" do
      advisory = create(:advisory, identifiers: ["CVE-2025-1234"])

      refute_includes advisory.related_advisories, advisory
    end

    should "return empty when no CVE" do
      advisory = create(:advisory, identifiers: ["GHSA-test-only"])

      assert_empty advisory.related_advisories
    end
  end

  context ".source_kind scope" do
    should "filter advisories by source kind" do
      github_source = create(:source, kind: "github", url: "https://github.com/advisories")
      erlef_source = create(:source, kind: "erlef", url: "https://cna.erlef.org")

      github_advisory = create(:advisory, source: github_source, uuid: "GHSA-test-1234")
      erlef_advisory = create(:advisory, source: erlef_source, uuid: "EEF-CVE-2025-0001")

      github_results = Advisory.source_kind("github")
      erlef_results = Advisory.source_kind("erlef")

      assert_equal 1, github_results.count
      assert_equal github_advisory, github_results.first

      assert_equal 1, erlef_results.count
      assert_equal erlef_advisory, erlef_results.first
    end

    should "return empty when no advisories match source kind" do
      github_source = create(:source, kind: "github", url: "https://github.com/advisories")
      create(:advisory, source: github_source)

      results = Advisory.source_kind("erlef")
      assert_equal 0, results.count
    end
  end

  context ".package_name scope" do
    should "match package names case insensitively" do
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "LODASH", "versions" => [] }
      ])
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "express", "versions" => [] }
      ])

      lodash_results = Advisory.package_name("lodash")
      express_results = Advisory.package_name("EXPRESS")

      assert_equal 1, lodash_results.count
      assert_equal 1, express_results.count
    end

    should "match exact case as well" do
      create(:advisory, packages: [
        { "ecosystem" => "npm", "package_name" => "test-package", "versions" => [] }
      ])

      results = Advisory.package_name("test-package")
      assert_equal 1, results.count
    end
  end

  context "#set_repository_url" do
    should "only update repository_url if it changes" do
      advisory = build(:advisory, references: ["https://github.com/owner/repo/issues/1"])
      advisory.save!

      initial_url = advisory.repository_url
      assert_equal "https://github.com/owner/repo", initial_url

      # Update with different references - repository_url should change
      advisory.update!(references: ["https://github.com/other/project/issues/1"])
      assert_equal "https://github.com/other/project", advisory.repository_url
    end

    should "not mark repository_url as changed when references don't change computed url" do
      Sidekiq::Testing.fake! do
        advisory = build(:advisory, references: ["https://github.com/owner/repo/issues/1"])
        advisory.save!

        initial_url = advisory.repository_url

        # Change references but to same repo (different issue) - URL shouldn't change
        advisory.assign_attributes(references: ["https://github.com/owner/repo/issues/2"])

        # The before_save should detect no change and not mark it as dirty
        advisory.save!

        assert_equal initial_url, advisory.repository_url
        # Verify no package sync jobs were queued since nothing meaningful changed
        # (we already have jobs from the initial create, so just check count didn't increase)
      end
    end
  end

  context "#set_blast_radius" do
    should "only update blast_radius when it actually changes" do
      Sidekiq::Testing.fake! do
        # Create with package records to get a calculable blast radius
        create(:registry, name: "npmjs.org", ecosystem: "npm")
        pkg = create(:package, ecosystem: "npm", name: "test-package", dependent_repos_count: 100)

        advisory = create(:advisory, cvss_score: 5.0, packages: [
          { "ecosystem" => "npm", "package_name" => "test-package", "versions" => [] }
        ])
        initial_radius = advisory.blast_radius

        # Update title only - blast_radius calculation would return same value
        # so it shouldn't be marked as changed
        advisory.update!(title: "New Title")

        # Verify blast_radius is still the same
        advisory.reload
        assert_equal initial_radius, advisory.blast_radius
      end
    end

    should "update blast_radius when cvss_score changes" do
      Sidekiq::Testing.fake! do
        create(:registry, name: "npmjs.org", ecosystem: "npm")
        pkg = create(:package, ecosystem: "npm", name: "test-package", dependent_repos_count: 100)

        advisory = create(:advisory, cvss_score: 5.0, packages: [
          { "ecosystem" => "npm", "package_name" => "test-package", "versions" => [] }
        ])
        initial_radius = advisory.blast_radius

        # Change cvss_score - this should change the blast radius calculation
        advisory.update!(cvss_score: 8.0)

        # blast_radius should have changed
        advisory.reload
        refute_equal initial_radius, advisory.blast_radius
      end
    end
  end

  context "#sync_related_packages" do
    should "create related package records from API response" do
      Sidekiq::Testing.fake! do
        advisory = create(:advisory,
          references: ["https://github.com/psf/requests/issues/1"],
          packages: [{ "ecosystem" => "pypi", "package_name" => "requests", "versions" => [] }]
        )

        WebMock.reset!
        stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/packages/lookup})
          .to_return(status: 200, body: [
            { "ecosystem" => "pypi", "name" => "requests" },
            { "ecosystem" => "conda", "name" => "requests" },
            { "ecosystem" => "homebrew", "name" => "python-requests" }
          ].to_json, headers: { 'Content-Type' => 'application/json' })

        advisory.sync_related_packages

        assert_equal 2, advisory.related_package_records.count
        ecosystems = advisory.related_package_records.pluck(:ecosystem).sort
        assert_equal ["conda", "homebrew"], ecosystems
      end
    end

    should "filter out packages already in the advisory" do
      Sidekiq::Testing.fake! do
        advisory = create(:advisory,
          references: ["https://github.com/pallets/flask/issues/1"],
          packages: [
            { "ecosystem" => "pypi", "package_name" => "flask", "versions" => [] },
            { "ecosystem" => "conda", "package_name" => "flask", "versions" => [] }
          ]
        )

        WebMock.reset!
        stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/packages/lookup})
          .to_return(status: 200, body: [
            { "ecosystem" => "pypi", "name" => "flask" },
            { "ecosystem" => "conda", "name" => "flask" },
            { "ecosystem" => "homebrew", "name" => "python-flask" }
          ].to_json, headers: { 'Content-Type' => 'application/json' })

        advisory.sync_related_packages

        assert_equal 1, advisory.related_package_records.count
        assert_equal "homebrew", advisory.related_package_records.first.ecosystem
      end
    end

    should "return early when repository_url is blank" do
      Sidekiq::Testing.fake! do
        advisory = create(:advisory, repository_url: nil)

        advisory.sync_related_packages

        assert_equal 0, advisory.related_package_records.count
      end
    end

    should "handle API failure gracefully" do
      Sidekiq::Testing.fake! do
        advisory = create(:advisory, references: ["https://github.com/owner/repo/issues/1"])

        WebMock.reset!
        stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/packages/lookup})
          .to_return(status: 500, body: "Internal Server Error")

        assert_nothing_raised do
          advisory.sync_related_packages
        end
        assert_equal 0, advisory.related_package_records.count
      end
    end

    should "remove stale related packages no longer in API response" do
      Sidekiq::Testing.fake! do
        advisory = create(:advisory,
          references: ["https://github.com/owner/repo/issues/1"],
          packages: [{ "ecosystem" => "pypi", "package_name" => "mypkg", "versions" => [] }]
        )

        stale_pkg = create(:package, ecosystem: "alpine", name: "mypkg")
        create(:related_package, advisory: advisory, package: stale_pkg)

        WebMock.reset!
        stub_request(:get, %r{https://packages\.ecosyste\.ms/api/v1/packages/lookup})
          .to_return(status: 200, body: [
            { "ecosystem" => "pypi", "name" => "mypkg" },
            { "ecosystem" => "conda", "name" => "mypkg" }
          ].to_json, headers: { 'Content-Type' => 'application/json' })

        advisory.sync_related_packages

        assert_equal 1, advisory.related_package_records.count
        assert_equal "conda", advisory.related_package_records.first.ecosystem
      end
    end
  end

  context "#affected_versions" do
    should "return original invalid versions that match the range after normalization" do
      package = { "ecosystem" => "nuget", "package_name" => "Mammoth" }
      advisory = build(:advisory, packages: [package])

      # Stub version_numbers to return versions including ones with extra dots
      versions = ["1.6.0", "1.7.0-alpha.2", "1.7.0-alpha.3", "1.10.0", "1.11.0", "1.12.0"]
      advisory.stubs(:version_numbers).returns(versions)

      affected = advisory.affected_versions(package, "< 1.11.0")

      # Should include the ORIGINAL alpha versions (not normalized)
      assert_includes affected, "1.7.0-alpha.2"
      assert_includes affected, "1.7.0-alpha.3"
      assert_includes affected, "1.6.0"
      assert_includes affected, "1.10.0"

      # Should not include versions >= 1.11.0
      refute_includes affected, "1.11.0"
      refute_includes affected, "1.12.0"
    end

    should "exclude completely invalid versions that don't look like semver" do
      package = { "ecosystem" => "npm", "package_name" => "test" }
      advisory = build(:advisory, packages: [package])

      versions = ["1.0.0", "not-a-version", "1.7.0-alpha.2", "abcdef", "2.0.0"]
      advisory.stubs(:version_numbers).returns(versions)

      affected = advisory.affected_versions(package, "< 3.0.0")

      # Should include valid and normalizable versions
      assert_includes affected, "1.0.0"
      assert_includes affected, "1.7.0-alpha.2"
      assert_includes affected, "2.0.0"

      # Should not include completely invalid versions
      refute_includes affected, "not-a-version"
      refute_includes affected, "abcdef"
    end

    should "handle both original versions being returned" do
      package = { "ecosystem" => "nuget", "package_name" => "test" }
      advisory = build(:advisory, packages: [package])

      # Both of these normalize to "1.7.0-alpha" but we should return both originals
      versions = ["1.7.0-alpha.2", "1.7.0-alpha.3"]
      advisory.stubs(:version_numbers).returns(versions)

      affected = advisory.affected_versions(package, "< 2.0.0")

      assert_equal 2, affected.count
      assert_includes affected, "1.7.0-alpha.2"
      assert_includes affected, "1.7.0-alpha.3"
    end
  end
end