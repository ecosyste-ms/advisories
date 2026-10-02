class IndexAdvisoryIdentity < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_index :advisories, :uuid, algorithm: :concurrently
    add_index :advisories, :identifiers, using: :gin, algorithm: :concurrently
  end
end
