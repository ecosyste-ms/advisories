class RelatedPackage < ApplicationRecord
  belongs_to :advisory
  belongs_to :package

  validates :package_id, uniqueness: { scope: :advisory_id }
end
