class CreatePatchBodies < ActiveRecord::Migration[8.1]
  def change
    create_table :patch_bodies, id: :string, primary_key: :sha256 do |t|
      t.binary :contents, null: false
      t.check_constraint "encode(sha256(contents), 'hex') = sha256", name: 'patch_body_matches_digest'
    end
    add_foreign_key :patch_bodies, :patches, column: :sha256, primary_key: :sha256, on_delete: :cascade
  end
end
