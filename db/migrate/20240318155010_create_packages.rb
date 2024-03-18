class CreatePackages < ActiveRecord::Migration[7.1]
  def change
    create_table :packages do |t|
      t.string :ecosystem
      t.string :name
      t.string :description
      t.string :registry_url
      t.datetime :last_synced_at
      t.integer :dependent_packages_count
      t.integer :dependent_repos_count
      t.bigint :downloads
      t.string :downloads_period
      t.string :latest_release_number
      t.string :repository_url
      t.integer :versions_count
      t.string :version_numbers, array: true, default: []

      t.timestamps
    end
  end
end
