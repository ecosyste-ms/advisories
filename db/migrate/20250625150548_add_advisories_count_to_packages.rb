class AddAdvisoriesCountToPackages < ActiveRecord::Migration[8.0]
  def change
    add_column :packages, :advisories_count, :integer, default: 0
    add_index :packages, :advisories_count
  end
end
