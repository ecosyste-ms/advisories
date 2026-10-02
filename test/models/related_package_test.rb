require "test_helper"

class RelatedPackageTest < ActiveSupport::TestCase
  context "associations" do
    should belong_to(:advisory)
    should belong_to(:package)
  end

  context "validations" do
    should "enforce uniqueness of package_id scoped to advisory_id" do
      advisory = create(:advisory)
      package = create(:package)
      create(:related_package, advisory: advisory, package: package)

      duplicate = build(:related_package, advisory: advisory, package: package)
      refute duplicate.valid?
      assert_includes duplicate.errors[:package_id], "has already been taken"
    end

    should "allow the same package for different advisories" do
      package = create(:package)
      advisory1 = create(:advisory)
      advisory2 = create(:advisory)

      create(:related_package, advisory: advisory1, package: package)
      second = build(:related_package, advisory: advisory2, package: package)

      assert second.valid?
    end
  end

  context ".normalize_name" do
    should "strip python prefix" do
      assert_equal "requests", RelatedPackage.normalize_name("python3-requests")
      assert_equal "requests", RelatedPackage.normalize_name("python-requests")
      assert_equal "django", RelatedPackage.normalize_name("py3-django")
    end

    should "strip nix package set prefix" do
      assert_equal "requests", RelatedPackage.normalize_name("python312Packages.requests")
      assert_equal "rails", RelatedPackage.normalize_name("rubyPackages.rails")
      assert_equal "lodash", RelatedPackage.normalize_name("nodePackages.lodash")
    end

    should "strip nix _latest variant prefix" do
      assert_equal "flood", RelatedPackage.normalize_name("nodePackages_latest.flood")
      assert_equal "joplin", RelatedPackage.normalize_name("python312Packages_latest.joplin")
    end

    should "strip distro suffixes" do
      assert_equal "admesh", RelatedPackage.normalize_name("admesh-dev")
      assert_equal "admesh", RelatedPackage.normalize_name("admesh-doc")
      assert_equal "alertmanager", RelatedPackage.normalize_name("alertmanager-openrc")
    end

    should "strip conda subpackage suffixes" do
      assert_equal "numpy", RelatedPackage.normalize_name("numpy-base")
      assert_equal "nbconvert", RelatedPackage.normalize_name("nbconvert-core")
      assert_equal "nbconvert", RelatedPackage.normalize_name("nbconvert-all")
    end

    should "strip rb prefix" do
      assert_equal "octokit", RelatedPackage.normalize_name("rb-octokit")
      assert_equal "tzinfo", RelatedPackage.normalize_name("rb-tzinfo")
    end

    should "strip lib prefix" do
      assert_equal "xml2", RelatedPackage.normalize_name("libxml2")
    end

    should "strip apache prefix" do
      assert_equal "airflow", RelatedPackage.normalize_name("apache-airflow")
    end

    should "leave names without prefix unchanged" do
      assert_equal "requests", RelatedPackage.normalize_name("requests")
    end

    should "downcase the result" do
      assert_equal "flask", RelatedPackage.normalize_name("Python3-Flask")
    end
  end

  context ".normalize_advisory_name" do
    should "extract last segment from Go module path" do
      assert_equal "cosign", RelatedPackage.normalize_advisory_name("github.com/sigstore/cosign")
    end

    should "skip version segments in Go module paths" do
      assert_equal "cosign", RelatedPackage.normalize_advisory_name("github.com/sigstore/cosign/v2")
    end

    should "strip apache prefix from advisory names" do
      assert_equal "airflow", RelatedPackage.normalize_advisory_name("apache-airflow")
    end

    should "leave simple names unchanged" do
      assert_equal "requests", RelatedPackage.normalize_advisory_name("requests")
    end
  end

  context ".compute_name_match" do
    should "return true when stripped name matches an advisory package" do
      assert RelatedPackage.compute_name_match("python3-requests", ["requests"])
    end

    should "return true for nix package set match" do
      assert RelatedPackage.compute_name_match("python312Packages.django", ["Django"])
    end

    should "return true when advisory name is a Go module path" do
      assert RelatedPackage.compute_name_match("cosign", ["github.com/sigstore/cosign/v2"])
    end

    should "return true when both sides need prefix stripping" do
      assert RelatedPackage.compute_name_match("airflow", ["apache-airflow"])
    end

    should "return false when name does not match" do
      refute RelatedPackage.compute_name_match("python3-flask", ["requests", "django"])
    end

    should "match case insensitively" do
      assert RelatedPackage.compute_name_match("Ruby-Rails", ["rails"])
    end

    should "match debian Go package by suffix" do
      assert RelatedPackage.compute_name_match(
        "golang-github-go-viper-mapstructure",
        ["github.com/go-viper/mapstructure/v2"],
        package_ecosystem: "debian"
      )
    end

    should "match debian Go package with multi-segment name by suffix" do
      assert RelatedPackage.compute_name_match(
        "golang-github-aws-aws-sdk-go",
        ["github.com/aws/aws-sdk-go"],
        package_ecosystem: "debian"
      )
    end

    should "not suffix match when name does not end with advisory name" do
      refute RelatedPackage.compute_name_match(
        "golang-github-foo-bar",
        ["github.com/baz/qux"],
        package_ecosystem: "debian"
      )
    end

    should "not suffix match for non-distro ecosystems" do
      refute RelatedPackage.compute_name_match(
        "@redwoodjs/auth-netlify-api",
        ["@redwoodjs/api"],
        package_ecosystem: "npm"
      )
    end
  end

  context ".compute_match_kind" do
    should "return likely_fork when repo_fork and name_match in same ecosystem" do
      assert_equal "likely_fork", RelatedPackage.compute_match_kind(
        name_match: true, repo_fork: true, package_ecosystem: "go", advisory_ecosystems: ["go"]
      )
    end

    should "return repackage when repo_fork and name_match in different ecosystem" do
      assert_equal "repackage", RelatedPackage.compute_match_kind(
        name_match: true, repo_fork: true, package_ecosystem: "debian", advisory_ecosystems: ["go"]
      )
    end

    should "return repo_fork when repo_fork without name match" do
      assert_equal "repo_fork", RelatedPackage.compute_match_kind(
        name_match: false, repo_fork: true, package_ecosystem: "go", advisory_ecosystems: ["go"]
      )
    end

    should "return likely_fork for same-ecosystem name match" do
      assert_equal "likely_fork", RelatedPackage.compute_match_kind(
        name_match: true, repo_fork: false, package_ecosystem: "npm", advisory_ecosystems: ["npm"]
      )
    end

    should "return repackage for cross-ecosystem name match" do
      assert_equal "repackage", RelatedPackage.compute_match_kind(
        name_match: true, repo_fork: false, package_ecosystem: "conda", advisory_ecosystems: ["pypi"]
      )
    end

    should "return unknown when no name match and not a fork" do
      assert_equal "unknown", RelatedPackage.compute_match_kind(
        name_match: false, repo_fork: false, package_ecosystem: "alpine", advisory_ecosystems: ["pypi"]
      )
    end

    should "match ecosystems case insensitively" do
      assert_equal "likely_fork", RelatedPackage.compute_match_kind(
        name_match: true, repo_fork: false, package_ecosystem: "npm", advisory_ecosystems: ["NPM"]
      )
    end
  end

  context ".compute_ecosystem_signal" do
    should "return fork_farm for large same-ecosystem repos" do
      result = RelatedPackage.compute_ecosystem_signal(
        ecosystem_counts: { "npm" => 150, "go" => 2 },
        package_ecosystem: "npm",
        advisory_ecosystems: ["npm"]
      )
      assert_equal "fork_farm", result[:signal]
      assert_equal 152, result[:total]
    end

    should "return repackaging when many ecosystems include known repackagers" do
      result = RelatedPackage.compute_ecosystem_signal(
        ecosystem_counts: { "pypi" => 1, "conda" => 1, "homebrew" => 1, "nixpkgs" => 1 },
        package_ecosystem: "conda",
        advisory_ecosystems: ["pypi"]
      )
      assert_equal "repackaging", result[:signal]
      assert_includes result[:repackager_ecosystems], "conda"
    end

    should "return same_ecosystem for small same-ecosystem repos" do
      result = RelatedPackage.compute_ecosystem_signal(
        ecosystem_counts: { "npm" => 8, "go" => 1 },
        package_ecosystem: "npm",
        advisory_ecosystems: ["npm"]
      )
      assert_equal "same_ecosystem", result[:signal]
    end

    should "return mixed for diverse repos without repackagers" do
      result = RelatedPackage.compute_ecosystem_signal(
        ecosystem_counts: { "npm" => 3, "go" => 3, "pypi" => 3, "cargo" => 3 },
        package_ecosystem: "npm",
        advisory_ecosystems: ["npm"]
      )
      assert_equal "mixed", result[:signal]
    end

    should "return too_few for repos with fewer than 2 packages" do
      result = RelatedPackage.compute_ecosystem_signal(
        ecosystem_counts: { "npm" => 1 },
        package_ecosystem: "npm",
        advisory_ecosystems: ["npm"]
      )
      assert_equal "too_few", result[:signal]
    end

    should "not return fork_farm for cross-ecosystem packages" do
      result = RelatedPackage.compute_ecosystem_signal(
        ecosystem_counts: { "npm" => 150 },
        package_ecosystem: "conda",
        advisory_ecosystems: ["npm"]
      )
      refute_equal "fork_farm", result[:signal]
    end
  end

  context ".compute_version_overlap" do
    should "compute overlap between matching version sets" do
      result = RelatedPackage.compute_version_overlap(
        ["2.28.0", "2.29.0", "2.31.0"],
        ["2.28.0", "2.28.1", "2.29.0", "2.31.0", "2.32.0"]
      )
      assert result[:sufficient_data]
      assert_equal 3, result[:overlap_count]
      assert_in_delta 1.0, result[:overlap_ratio], 0.01
    end

    should "compute partial overlap" do
      result = RelatedPackage.compute_version_overlap(
        ["1.0.0", "2.0.0", "3.0.0", "4.0.0"],
        ["1.0.0", "2.0.0", "5.0.0"]
      )
      assert result[:sufficient_data]
      assert_equal 2, result[:overlap_count]
      assert_in_delta 0.5, result[:overlap_ratio], 0.01
    end

    should "return zero for no overlap" do
      result = RelatedPackage.compute_version_overlap(
        ["1.0.0", "2.0.0", "3.0.0"],
        ["4.0.0", "5.0.0", "6.0.0"]
      )
      assert result[:sufficient_data]
      assert_equal 0, result[:overlap_count]
      assert_in_delta 0.0, result[:overlap_ratio], 0.01
    end

    should "return insufficient data for empty arrays" do
      result = RelatedPackage.compute_version_overlap([], ["1.0.0"])
      refute result[:sufficient_data]
      assert_equal 0, result[:overlap_count]
    end

    should "return insufficient data when below min_versions threshold" do
      result = RelatedPackage.compute_version_overlap(
        ["1.0.0", "2.0.0"],
        ["1.0.0", "2.0.0", "3.0.0"]
      )
      refute result[:sufficient_data]

      result = RelatedPackage.compute_version_overlap(
        ["1.0.0", "2.0.0", "3.0.0"],
        ["1.0.0", "2.0.0"]
      )
      refute result[:sufficient_data]
    end

    should "allow custom min_versions threshold" do
      result = RelatedPackage.compute_version_overlap(
        ["1.0.0", "2.0.0"],
        ["1.0.0", "2.0.0"],
        min_versions: 2
      )
      assert result[:sufficient_data]
      assert_equal 2, result[:overlap_count]
    end

    should "normalize versions before comparing" do
      result = RelatedPackage.compute_version_overlap(
        ["v1.0.0", "2.0.0", "3.0.0"],
        ["1.0.0", "v2.0.0", "v3.0.0"]
      )
      assert result[:sufficient_data]
      assert_equal 3, result[:overlap_count]
      assert_in_delta 1.0, result[:overlap_ratio], 0.01
    end

    should "skip non-semver versions" do
      result = RelatedPackage.compute_version_overlap(
        ["1.0.0", "not-a-version", "2.0.0", "3.0.0"],
        ["1.0.0", "2.0.0", "3.0.0", "also-bad"]
      )
      assert result[:sufficient_data]
      assert_equal 3, result[:overlap_count]
      assert_in_delta 1.0, result[:overlap_ratio], 0.01
    end
  end

  context "scopes" do
    should "filter by name_matched" do
      advisory = create(:advisory)
      matched = create(:related_package, advisory: advisory, name_match: true)
      unmatched = create(:related_package, advisory: advisory, name_match: false)

      results = RelatedPackage.name_matched
      assert_includes results, matched
      refute_includes results, unmatched
    end

    should "filter by forked" do
      advisory = create(:advisory)
      forked = create(:related_package, advisory: advisory, repo_fork: true)
      not_forked = create(:related_package, advisory: advisory, repo_fork: false)

      results = RelatedPackage.forked
      assert_includes results, forked
      refute_includes results, not_forked
    end

    should "filter by not_monorepo" do
      advisory = create(:advisory)
      small_repo = create(:related_package, advisory: advisory, repo_package_count: 5)
      monorepo = create(:related_package, advisory: advisory, repo_package_count: 50)

      results = RelatedPackage.not_monorepo
      assert_includes results, small_repo
      refute_includes results, monorepo
    end

    should "filter by match_kind" do
      advisory = create(:advisory)
      fork_pkg = create(:related_package, advisory: advisory, match_kind: "repo_fork")
      repackage_pkg = create(:related_package, advisory: advisory, match_kind: "repackage")

      results = RelatedPackage.match_kind("repo_fork")
      assert_includes results, fork_pkg
      refute_includes results, repackage_pkg
    end
  end
end
