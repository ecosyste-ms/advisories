class AddOwnerToPackages < ActiveRecord::Migration[8.0]
  def change
    add_column :packages, :owner, :string
    add_index :packages, :owner
  end
end
