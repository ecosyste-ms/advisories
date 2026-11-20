class CreatePatchIndex < ActiveRecord::Migration[8.1]
  def change
    create_table :patches do |t|
      t.string :sha256, null: false, index: { unique: true }
      t.jsonb :headers, null: false, default: {}
      t.timestamps
    end

    create_table :patch_releases do |t|
      t.string :distribution, null: false
      t.string :package_name, null: false
      t.string :version, null: false
      t.string :revision, null: false
      t.string :source_url, null: false
      t.jsonb :metadata, null: false
      t.jsonb :component, null: false
      t.datetime :imported_at, null: false
      t.index [:distribution, :package_name, :version, :revision], unique: true
    end

    create_table :patch_occurrences do |t|
      t.references :patch, null: false, foreign_key: true
      t.references :patch_release, null: false, foreign_key: true
      t.string :name, null: false
      t.string :source_url, null: false
      t.jsonb :declaration, null: false
      t.jsonb :scope_evidence, null: false
      t.string :advisory_ids, array: true, default: [], null: false
      t.string :project_purl, index: true
      t.string :purl, index: true
      t.jsonb :mapping, null: false
      t.index [:patch_release_id, :name], unique: true
    end
  end
end
