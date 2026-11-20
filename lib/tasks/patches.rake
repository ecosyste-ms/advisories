namespace :patches do
  namespace :sync do
    %w[debian homebrew ubuntu].each do |source|
      desc "Sync current #{source} patch declarations (PATCH_SYNC_LIMIT, PATCH_SYNC_PACKAGE)"
      task source => :environment do
        stats = PatchIndex::DailySync.new(source).run(limit: Integer(ENV.fetch('PATCH_SYNC_LIMIT', '200')),
          package: ENV['PATCH_SYNC_PACKAGE'].presence)
        puts stats.merge(source: source).to_json
        abort "#{source} patch sync had failures" if stats.fetch(:failed).positive?
      end
    end
  end

  desc 'Import a published conda build from a supplied JSON record'
  task :conda, [:build_file] => :environment do |_, args|
    abort 'Supply a build JSON file' if args[:build_file].blank?
    PatchIndex::Conda.new.import(JSON.parse(File.read(args[:build_file])))
  end

  desc 'Store missing patch bodies from local SHA-256 caches'
  task backfill_bodies: :environment do
    require Rails.root.join('script/patch_index/indexed_bodies')
    audit = IndexedBodies.new(catalog: Rails.root.join('tmp/trixie-catalog/patches'), cache: Rails.root.join('tmp/patch-similarity/blobs'))
    result = audit.verify(store: true)
    puts JSON.generate(result)
    abort 'Some patch files are missing from the local caches' if result.fetch(:missing).positive?
  end

  desc 'Import a Debian source package at the given version'
  task :debian, [:package, :version] => :environment do |_, args|
    abort 'Supply a Debian package and version' if args[:package].blank? || args[:version].blank?
    PatchIndex::Debian.new.import(args[:package], args[:version])
  end

  desc 'Import the default patch declarations for a Homebrew formula'
  task :homebrew, [:formula] => :environment do |_, args|
    abort 'Supply a Homebrew formula name' if args[:formula].blank?
    PatchIndex::Homebrew.new.import(args[:formula])
  end

  desc 'Import Fedora and Ubuntu release declarations from a manifest with adjacent blobs/'
  task :import_releases, [:manifest] => :environment do |_, args|
    abort 'Supply a release manifest' if args[:manifest].blank?
    manifest = Pathname(args[:manifest])
    importer = PatchIndex::DistributionRelease.new(manifest.dirname)
    JSON.parse(manifest.read).each { |row| importer.import(row) if %w[Fedora Ubuntu].include?(row.fetch('source')) }
  end

  desc 'Index source repositories from imported Homebrew formulae (optional DEBIAN_PACKAGE from the trixie catalog)'
  task repositories: :environment do
    load Rails.root.join('script/patch_index/import_repositories.rb')
  end

  desc 'Recompute patch mappings from previously imported source evidence'
  task resolve: :environment do
    PatchRelease.find_each do |release|
      release.with_lock { release.patch_occurrences.each(&:resolve!) }
    end
  end

  desc 'Count examined releases, declarations and PURL mappings'
  task stats: :environment do
    PatchRelease.distinct.pluck(:distribution).sort.each do |distribution|
      releases = PatchRelease.where(distribution: distribution)
      occurrences = PatchOccurrence.where(patch_release: releases)
      puts({ distribution: distribution, packages: releases.distinct.count(:package_name), releases: releases.count,
        patched_packages: releases.where(id: occurrences.select(:patch_release_id)).distinct.count(:package_name),
        patched_releases: occurrences.distinct.count(:patch_release_id), patches: occurrences.distinct.count(:patch_id),
        occurrences: occurrences.count, by_status: occurrences.group("mapping->>'status'").count,
        by_purl_type: occurrences.group("split_part(split_part(purl, '/', 1), ':', 2)").count }.to_json)
    end
    occurrences = PatchOccurrence.all
    referenced = occurrences.where('cardinality(advisory_ids) > 0')
    shared = occurrences.joins(:patch, :patch_release).where.not(patches: { sha256: Patch::EMPTY_SHA256 })
      .group(:patch_id).having('count(DISTINCT patch_releases.distribution) > 1').count
    puts({ distinct_patches: occurrences.distinct.count(:patch_id), occurrences: occurrences.count,
      mapped_patches: occurrences.where.not(purl: nil).distinct.count(:patch_id),
      versioned: occurrences.where("purl LIKE '%@%'").count, advisory_occurrences: referenced.count,
      advisory_patches: referenced.distinct.count(:patch_id), cross_distribution_patches: shared.size }.to_json)
  end

end

namespace :patches do
  desc 'Import evaluated Nix builds whose exact output occurs in the published channel manifest'
  task nix_builds: :environment do
    require 'open3'
    published, status = Open3.capture2('xz', '-dc', ENV.fetch('STORE_PATHS'))
    abort 'Invalid published store manifest' unless status.success?
    root = Pathname(ENV.fetch('NIX_RELEASE'))
    revision = root.join('.git-revision').read.strip
    release_url = ENV.fetch('RELEASE_URL').delete_suffix('/')
    http = PatchIndex::Http.new
    raise 'Unexpected published revision' unless http.get("#{release_url}/git-revision").strip == revision
    http.verified("#{release_url}/store-paths.xz", Digest::SHA256.file(ENV.fetch('STORE_PATHS')).hexdigest)
    importer = PatchIndex::NixBuild.new(root: root, published: published.lines(chomp: true).to_set,
      release_url: release_url, http: http)
    files = Dir[File.join(ENV.fetch('NIX_BUILDS'), revision, '*', '*.json')]
    abort 'No evaluated build batches' if files.empty?
    failures = imported = 0
    files.each do |file|
      batch = JSON.parse(File.read(file))
      raise 'Mismatched evaluation revision' unless batch.fetch('revision') == revision
      batch.fetch('builds').each do |row|
        begin
          importer.import(row)
          imported += 1
        rescue IOError, KeyError, Errno::ENOENT => e
          warn "#{row['attr']} #{row['system']}: #{e.message}"
          failures += 1
        end
      end
    end
    puts "Imported #{imported} Nix build records, #{failures} failed"
    abort 'Some patch inputs could not be imported' if failures.positive?
  end
end

namespace :patches do
  desc 'Import published conda builds from a JSON Lines catalog using archive byte ranges'
  task conda_builds: :environment do
    catalog = ENV.fetch('BUILD_CATALOG')
    checkpoint = ENV['CHECKPOINT']
    File.open("#{checkpoint || catalog}.lock", 'a') do |lock|
      abort 'This catalog is already being imported' unless lock.flock(File::LOCK_EX | File::LOCK_NB)
      stats = PatchIndex::CondaBackfill.new.run(catalog, budget: ENV['MAX_TOTAL_BYTES']&.then { |n| Integer(n) },
        build_limit: Integer(ENV.fetch('MAX_BUILD_BYTES', 8.megabytes)), checkpoint: checkpoint)
      puts JSON.generate(stats)
      abort 'Some builds could not be imported' if stats[:failed].positive?
    end
  end
end
