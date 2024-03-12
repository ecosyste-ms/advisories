class AddRepositoryUrlToAdvisories < ActiveRecord::Migration[7.1]
  def change
    add_column :advisories, :repository_url, :string
  end
end
