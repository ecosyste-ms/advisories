class AddIndexToPackagesEcosystemName < ActiveRecord::Migration[8.0]
  def change
    add_index :packages, [:ecosystem, :name], unique: true
  end
end
