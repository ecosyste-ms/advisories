class AddCachedRelatedAdvisoriesToAdvisories < ActiveRecord::Migration[8.1]
  def change
    add_column :advisories, :cached_related_advisories, :jsonb, default: []
  end
end
