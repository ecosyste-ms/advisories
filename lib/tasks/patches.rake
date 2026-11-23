namespace :patches do
  namespace :sync do
    %w[debian homebrew ubuntu].each do |source|
      desc "Sync #{source} patch declarations (PATCH_SYNC_LIMIT, PATCH_SYNC_PACKAGE, PATCH_SYNC_RETRY_FAILED)"
      task source => :environment do
        stats = PatchIndex::DailySync.new(source).run(limit: Integer(ENV.fetch('PATCH_SYNC_LIMIT', '200')),
          package: ENV['PATCH_SYNC_PACKAGE'].presence, retry_failed: ENV['PATCH_SYNC_RETRY_FAILED'].present?)
        puts stats.merge(source: source).to_json
      end
    end
  end
end
