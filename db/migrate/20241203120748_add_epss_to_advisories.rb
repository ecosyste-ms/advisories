class AddEpssToAdvisories < ActiveRecord::Migration[8.0]
  def change
    add_column :advisories, :epss_percentage, :float
    add_column :advisories, :epss_percentile, :float
  end
end
