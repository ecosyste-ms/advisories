class CreateSources < ActiveRecord::Migration[7.0]
  def change
    create_table :sources do |t|
      t.string :name
      t.string :kind
      t.string :url
      t.integer :advisories_count, default: 0
      t.json :metadata, default: {}

      t.timestamps
    end
  end
end
