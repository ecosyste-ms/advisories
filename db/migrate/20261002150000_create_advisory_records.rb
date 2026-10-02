class CreateAdvisoryRecords < ActiveRecord::Migration[8.1]
  def change
    create_table :advisory_records do |t|
      t.references :source, null: false, foreign_key: true
      t.references :advisory, foreign_key: true
      t.string :external_id, null: false
      t.text :identifiers, array: true, default: [], null: false
      t.jsonb :payload, default: {}, null: false
      t.jsonb :raw
      t.jsonb :pending_payload
      t.jsonb :pending_raw
      t.string :pending_sync_token
      t.timestamps
    end

    add_index :advisory_records, 'source_id, lower(external_id)', unique: true, name: 'index_advisory_records_on_source_and_external_id'
    add_index :advisory_records, :identifiers, using: :gin
    add_index :advisory_records, :pending_sync_token, where: 'pending_sync_token IS NOT NULL'
  end
end
