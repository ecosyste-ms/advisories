class AddIconUrlToRegistries < ActiveRecord::Migration[8.0]
  def change
    add_column :registries, :icon_url, :string
  end
end
