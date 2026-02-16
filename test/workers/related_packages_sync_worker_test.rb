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
  end
end
