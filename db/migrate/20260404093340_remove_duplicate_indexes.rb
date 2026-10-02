class RemoveDuplicateIndexes < ActiveRecord::Migration[8.1]
  def change
    remove_index :advisories, name: "index_advisories_on_repository_url"
    remove_index :advisories, name: "index_advisories_on_severity"
    remove_index :related_packages, name: "index_related_packages_on_advisory_id"
  end
end
