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
end
