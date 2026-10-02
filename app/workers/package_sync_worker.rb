class PackageSyncWorker
  include Sidekiq::Worker
  sidekiq_options queue: :packages, retry: 3, lock: :until_executed, lock_expiration: 2.hours.to_i

  def perform(ecosystem, package_name)
    pkg = Package.find_or_create_by(ecosystem: ecosystem, name: package_name)

    # Sync package data if needed
    version_numbers_before = pkg.version_numbers
    pkg.sync if pkg.last_synced_at.nil? || pkg.last_synced_at < 1.day.ago

    # Recompute cached affected versions if version_numbers changed
    if pkg.version_numbers != version_numbers_before
      Advisory.ecosystem(ecosystem).package_name(package_name).find_each do |advisory|
        advisory.cache_affected_versions!
      end
    end

    # Update advisory count
    pkg.update_advisories_count

    # Ping for resync
    pkg.ping_for_resync
  end
end
