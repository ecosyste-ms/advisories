class RenameForkToRepoForkOnRelatedPackages < ActiveRecord::Migration[8.1]
  def change
    rename_column :related_packages, :fork, :repo_fork
  end
end
