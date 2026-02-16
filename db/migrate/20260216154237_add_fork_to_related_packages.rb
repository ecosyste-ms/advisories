class AddForkToRelatedPackages < ActiveRecord::Migration[8.1]
  def change
    add_column :related_packages, :fork, :boolean
  end
end
