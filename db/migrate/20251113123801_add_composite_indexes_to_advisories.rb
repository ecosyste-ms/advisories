class AddCompositeIndexesToAdvisories < ActiveRecord::Migration[8.1]
  def change
    add_index :advisories, [:severity, :published_at]
    add_index :advisories, [:repository_url, :published_at]
  end
end
