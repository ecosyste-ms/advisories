# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2025_11_13_123801) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"
  enable_extension "pg_stat_statements"
  enable_extension "pg_trgm"

  create_table "advisories", force: :cascade do |t|
    t.float "blast_radius", default: 0.0
    t.string "classification"
    t.datetime "created_at", null: false
    t.float "cvss_score"
    t.string "cvss_vector"
    t.text "description"
    t.float "epss_percentage"
    t.float "epss_percentile"
    t.string "identifiers", default: [], array: true
    t.string "origin"
    t.jsonb "packages", default: []
    t.datetime "published_at"
    t.string "references", default: [], array: true
    t.string "repository_url"
    t.string "severity"
    t.bigint "source_id", null: false
    t.string "source_kind"
    t.string "title"
    t.datetime "updated_at", null: false
    t.string "url"
    t.string "uuid"
    t.datetime "withdrawn_at"
    t.index ["created_at"], name: "index_advisories_on_created_at"
    t.index ["packages"], name: "index_advisories_on_packages", using: :gin
    t.index ["published_at"], name: "index_advisories_on_published_at"
    t.index ["repository_url", "published_at"], name: "index_advisories_on_repository_url_and_published_at"
    t.index ["repository_url"], name: "index_advisories_on_repository_url"
    t.index ["severity", "published_at"], name: "index_advisories_on_severity_and_published_at"
    t.index ["severity"], name: "index_advisories_on_severity"
    t.index ["source_id"], name: "index_advisories_on_source_id"
    t.index ["updated_at"], name: "index_advisories_on_updated_at"
  end

  create_table "exports", force: :cascade do |t|
    t.integer "advisories_count"
    t.string "bucket_name"
    t.datetime "created_at", null: false
    t.string "date"
    t.datetime "updated_at", null: false
  end

  create_table "packages", force: :cascade do |t|
    t.integer "advisories_count", default: 0
    t.datetime "created_at", null: false
    t.boolean "critical", default: false
    t.integer "dependent_packages_count"
    t.integer "dependent_repos_count"
    t.string "description"
    t.bigint "downloads"
    t.string "downloads_period"
    t.string "ecosystem"
    t.datetime "last_synced_at"
    t.string "latest_release_number"
    t.string "name"
    t.string "owner"
    t.string "package_etag"
    t.string "registry_url"
    t.string "repository_url"
    t.datetime "updated_at", null: false
    t.string "version_numbers", default: [], array: true
    t.integer "versions_count"
    t.string "versions_etag"
    t.index ["advisories_count"], name: "index_packages_on_advisories_count"
    t.index ["ecosystem", "name"], name: "index_packages_on_ecosystem_and_name", unique: true
    t.index ["owner"], name: "index_packages_on_owner"
  end

  create_table "registries", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.boolean "default", default: false
    t.string "ecosystem"
    t.string "github"
    t.string "icon_url"
    t.json "metadata", default: {}
    t.string "name"
    t.integer "packages_count", default: 0
    t.string "purl_type"
    t.datetime "updated_at", null: false
    t.string "url"
  end

  create_table "sources", force: :cascade do |t|
    t.integer "advisories_count", default: 0
    t.datetime "created_at", null: false
    t.string "kind"
    t.json "metadata", default: {}
    t.string "name"
    t.datetime "updated_at", null: false
    t.string "url"
  end

  add_foreign_key "advisories", "sources"
end
