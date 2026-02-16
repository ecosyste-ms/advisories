class AddRepoMetadataToPackages < ActiveRecord::Migration[8.1]
  def change
    add_column :packages, :repo_metadata, :jsonb
  end
end
