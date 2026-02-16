class CreateRelatedPackages < ActiveRecord::Migration[8.1]
  def change
    create_table :related_packages do |t|
      t.references :advisory, null: false, foreign_key: true
      t.references :package, null: false, foreign_key: true
      t.timestamps
    end
    add_index :related_packages, [:advisory_id, :package_id], unique: true
  end
end
