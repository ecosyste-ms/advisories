namespace :packages do
  desc 'sync registries'
  task sync_registries: :environment do
    Registry.sync_all
  end

  desc 'sync packages'
  task sync_packages: :environment do
    Advisory.all.find_each(&:sync_packages)
  end

  desc 'sync related packages for all advisories with a repository_url'
  task sync_related_packages: :environment do
    Advisory.where.not(repository_url: [nil, '']).find_each do |advisory|
      RelatedPackagesSyncWorker.perform_async(advisory.id)
    end
  end

  desc 'clean up sidekiq unique jobs'
  task clean_up_sidekiq_unique_jobs: :environment do
    SidekiqUniqueJobs::Digests.new.delete_by_pattern("*")
  end
end