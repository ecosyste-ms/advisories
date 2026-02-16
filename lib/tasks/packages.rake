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

  desc 'backfill name_match and repo_package_count on existing related_packages'
  task backfill_related_package_confidence: :environment do
    Advisory.joins(:related_packages).distinct.find_each do |advisory|
      advisory_package_names = advisory.packages.map { |p| p['package_name'] }
      advisory_ecosystems = advisory.packages.map { |p| p['ecosystem'] }
      repo_package_count = advisory.related_packages.count + advisory.packages.size

      advisory.related_packages.includes(:package).each do |related|
        name_match = RelatedPackage.compute_name_match(related.package.name, advisory_package_names)
        is_fork = related.package.repo_metadata&.dig('fork') == true
        match_kind = RelatedPackage.compute_match_kind(
          name_match: name_match, repo_fork: is_fork,
          package_ecosystem: related.package.ecosystem, advisory_ecosystems: advisory_ecosystems
        )
        related.update_columns(name_match: name_match, repo_package_count: repo_package_count, repo_fork: is_fork, match_kind: match_kind)
      end
    end
  end

  desc 'clean up sidekiq unique jobs'
  task clean_up_sidekiq_unique_jobs: :environment do
    SidekiqUniqueJobs::Digests.new.delete_by_pattern("*")
  end
end