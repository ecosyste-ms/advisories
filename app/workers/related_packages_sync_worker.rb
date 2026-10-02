class RelatedPackagesSyncWorker
  include Sidekiq::Worker
  sidekiq_options queue: :packages, retry: 3, lock: :until_executed, lock_expiration: 2.hours.to_i

  def perform(advisory_id)
    advisory = Advisory.find_by(id: advisory_id)
    return unless advisory

    advisory.sync_related_packages
  end
end
