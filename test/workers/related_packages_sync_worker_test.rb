require "test_helper"

class RelatedPackagesSyncWorkerTest < ActiveSupport::TestCase
  context "#perform" do
    should "call sync_related_packages on the advisory" do
      advisory = create(:advisory, repository_url: "https://github.com/owner/repo")
      advisory.expects(:sync_related_packages).once

      Advisory.stubs(:find_by).with(id: advisory.id).returns(advisory)

      RelatedPackagesSyncWorker.new.perform(advisory.id)
    end

    should "handle missing advisory gracefully" do
      assert_nothing_raised do
        RelatedPackagesSyncWorker.new.perform(-1)
      end
    end

    should "sync duplicate lookup results and update existing relationships on retry" do
      Sidekiq::Testing.fake! do
        advisory = create(:advisory,
          references: ["https://github.com/psf/requests/issues/1"],
          packages: [{ "ecosystem" => "pypi", "package_name" => "requests", "versions" => [] }]
        )
        existing_package = create(:package, ecosystem: "conda", name: "requests")
        existing_related = create(:related_package,
          advisory: advisory, package: existing_package,
          name_match: false, match_kind: "unknown", repo_package_count: 1
        )
        stale_related = create(:related_package, advisory: advisory)
        response = [
          { "ecosystem" => "pypi", "name" => "requests" },
          { "ecosystem" => "conda", "name" => "requests" },
          { "ecosystem" => "conda", "name" => "requests" },
          { "ecosystem" => "Homebrew", "name" => "python-requests", "repo_metadata" => { "fork" => true } },
          { "ecosystem" => "homebrew", "name" => "python-requests", "repo_metadata" => { "fork" => true } }
        ]
        stub_request(:get, "https://packages.ecosyste.ms/api/v1/packages/lookup")
          .with(query: { repository_url: advisory.repository_url })
          .to_return(status: 200, body: response.to_json, headers: { "Content-Type" => "application/json" })

        assert_difference "Package.count", 1 do
          RelatedPackagesSyncWorker.new.perform(advisory.id)
        end

        assert_equal [["conda", "requests"], ["homebrew", "python-requests"]],
          advisory.related_package_records.order(:ecosystem).pluck(:ecosystem, :name)
        assert existing_related.reload.name_match
        assert_equal "repackage", existing_related.match_kind
        assert_equal response.size, existing_related.repo_package_count
        refute RelatedPackage.exists?(stale_related.id)
        homebrew_related = advisory.related_packages.find_by!(package: Package.find_by!(ecosystem: "homebrew", name: "python-requests"))
        assert homebrew_related.repo_fork

        response.each { |package| package["repo_metadata"] = { "fork" => false } }
        stub_request(:get, "https://packages.ecosyste.ms/api/v1/packages/lookup")
          .with(query: { repository_url: advisory.repository_url })
          .to_return(status: 200, body: response.to_json, headers: { "Content-Type" => "application/json" })

        assert_no_difference ["Package.count", "RelatedPackage.count"] do
          RelatedPackagesSyncWorker.new.perform(advisory.id)
        end
        refute homebrew_related.reload.repo_fork
      end
    end
  end
end
