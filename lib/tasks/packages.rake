namespace :packages do
  desc 'sync registries'
  task sync_registries: :environment do
    Registry.sync_all
  end

  desc 'sync packages'
  task sync_packages: :environment do
    Advisory.all.find_each(&:sync_packages)
  end

  desc 'clean up sidekiq unique jobs'
  task clean_up_sidekiq_unique_jobs: :environment do
    SidekiqUniqueJobs::Digests.new.delete_by_pattern("*")
  end
end