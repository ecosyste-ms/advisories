class CreateAdvisories < ActiveRecord::Migration[7.0]
  def change
    create_table :advisories do |t|
      t.references :source, null: false, foreign_key: true
      t.string :uuid
      t.string :url
      t.string :title
      t.text :description
      t.string :origin
      t.string :severity
      t.datetime :published_at
      t.datetime :withdrawn_at
      t.string :classification
      t.float :cvss_score
      t.string :cvss_vector
      t.string :references, array: true, default: []
      t.string :source_kind
      t.string :identifiers, array: true, default: []

      t.jsonb :packages, default: []
      t.timestamps
    end
  end
end
