namespace :advisories do
  desc 'Update advisories from GitHub'
  task :sync => :environment do
    Source.all.each(&:sync_advisories)
  end
end