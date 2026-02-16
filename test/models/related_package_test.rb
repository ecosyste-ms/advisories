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

    should "filter by not_monorepo" do
      advisory = create(:advisory)
      small_repo = create(:related_package, advisory: advisory, repo_package_count: 5)
      monorepo = create(:related_package, advisory: advisory, repo_package_count: 50)

      results = RelatedPackage.not_monorepo
      assert_includes results, small_repo
      refute_includes results, monorepo
    end
  end
end
