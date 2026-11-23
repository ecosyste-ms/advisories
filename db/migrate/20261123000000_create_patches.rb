class CreatePatches < ActiveRecord::Migration[8.1]
  def change
    create_table :patches do |t|
      t.string :sha256, null: false, index: { unique: true }
      t.integer :byte_size, null: false
      t.jsonb :headers, null: false, default: {}
      t.timestamps
    end

    create_table :patch_bodies, id: :string, primary_key: :sha256 do |t|
      t.binary :contents, null: false
      t.check_constraint "encode(sha256(contents), 'hex') = sha256", name: 'patch_body_matches_digest'
    end
    add_foreign_key :patch_bodies, :patches, column: :sha256, primary_key: :sha256, on_delete: :cascade

    create_table :patch_releases do |t|
      t.string :distribution, null: false
      t.string :package_name, null: false
      t.string :version, null: false
      t.string :upstream_version
      t.string :repository_url, index: true
      t.string :source_url, null: false
      t.string :sync_sha256
      t.string :last_error
      t.jsonb :metadata, null: false, default: {}
      t.datetime :imported_at
      t.index [:distribution, :package_name, :version], unique: true
    end

    create_table :patch_occurrences do |t|
      t.references :patch, null: false, foreign_key: true
      t.references :patch_release, null: false, foreign_key: true, index: false
      t.string :name, null: false
      t.integer :position, null: false
      t.string :source_url, null: false
      t.string :advisory_ids, array: true, default: [], null: false
      t.jsonb :declaration, null: false, default: {}
      t.index [:patch_release_id, :name], unique: true
      t.index :advisory_ids, using: :gin
    end
  end
end
