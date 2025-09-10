class AddPerformanceIndexesToAdvisories < ActiveRecord::Migration[8.0]
  def up
    # Enable pg_trgm extension if not already enabled
    enable_extension 'pg_trgm'
    
    # Add GIN index on packages JSONB column for fast containment queries
    add_index :advisories, :packages, using: :gin
    
    # Add regular indexes on commonly filtered columns
    add_index :advisories, :published_at
    add_index :advisories, :created_at
    add_index :advisories, :updated_at
    add_index :advisories, :severity
    add_index :advisories, :repository_url
  end
  
  def down
    remove_index :advisories, :repository_url
    remove_index :advisories, :severity
    remove_index :advisories, :updated_at
    remove_index :advisories, :created_at
    remove_index :advisories, :published_at
    remove_index :advisories, :packages
    
    disable_extension 'pg_trgm'
  end
end
