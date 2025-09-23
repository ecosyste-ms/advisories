class AddEtagFieldsToPackages < ActiveRecord::Migration[8.0]
  def change
    add_column :packages, :package_etag, :string
    add_column :packages, :versions_etag, :string
  end
end
