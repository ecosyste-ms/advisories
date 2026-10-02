class AddMatchKindToRelatedPackages < ActiveRecord::Migration[8.1]
  def change
    add_column :related_packages, :match_kind, :string
  end
end
