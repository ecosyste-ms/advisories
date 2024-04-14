class AddPurlTypeToRegistries < ActiveRecord::Migration[7.1]
  def change
    add_column :registries, :purl_type, :string
  end
end
