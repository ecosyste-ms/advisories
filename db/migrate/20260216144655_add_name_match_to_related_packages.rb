class AddNameMatchToRelatedPackages < ActiveRecord::Migration[8.1]
  def change
    add_column :related_packages, :name_match, :boolean, default: false
    add_column :related_packages, :repo_package_count, :integer
  end
end
