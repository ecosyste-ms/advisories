namespace :packages do
  desc 'sync registries'
  task sync_registries: :environment do
    Registry.sync_all
  end

  desc 'sync packages'
  task sync_packages: :environment do
    Advisory.all.find_each(&:sync_packages)
  end
end