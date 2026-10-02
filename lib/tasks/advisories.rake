namespace :advisories do
  desc 'Create source records for existing GitHub and OSV advisories'
  task :backfill_records => :environment do
    AdvisoryRecord.backfill
  end

  desc 'Update advisories from all sources'
  task :sync => :environment do
    Source.all.each(&:sync_advisories)
  end

  desc 'Update advisories from GitHub'
  task :sync_github => :environment do
    source = Source.find_by(kind: 'github')
    if source
      source.sync_advisories
    else
      puts "GitHub source not found. Run `rails db:seed` to create it."
    end
  end

  desc 'Update advisories from Erlang Ecosystem Foundation'
  task :sync_erlef => :environment do
    source = Source.find_by(kind: 'erlef')
    if source
      source.sync_advisories
    else
      puts "Erlef source not found. Run `rails db:seed` to create it."
    end
  end

  desc 'Update advisories from OSV.dev'
  task :sync_osv => :environment do
    source = Source.find_by(kind: 'osv')
    if source
      source.sync_advisories
    else
      puts "OSV source not found. Run `rails db:seed` to create it."
    end
  end

  desc 'Update advisories from CPAN Security Advisory Database'
  task :sync_cpansa => :environment do
    source = Source.find_by(kind: 'cpansa')
    if source
      source.sync_advisories
    else
      puts "CPANSA source not found. Run `rails db:seed` to create it."
    end
  end
end
