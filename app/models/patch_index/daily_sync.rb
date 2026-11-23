module PatchIndex
  class DailySync
    SOURCES = %w[debian homebrew ubuntu].freeze
    # Worth retrying on the next run without remembering the digest.
    TRANSIENT = [Http::Error, SystemCallError, ActiveRecord::TransactionRollbackError, ActiveRecord::ConnectionNotEstablished,
      ActiveRecord::QueryAborted, ActiveRecord::LockWaitTimeout].freeze

    def initialize(source, http: Http.new)
      raise ArgumentError, "unknown distribution #{source}" unless SOURCES.include?(source)
      @source = source
      @catalog = source == 'homebrew' ? Homebrew.new(http) : Apt.new(source, http)
    end

    def run(limit: 200, package: nil, retry_failed: false)
      raise ArgumentError, 'limit must be positive' unless limit.positive?
      PatchRelease.connection_pool.with_connection do |db|
        lock = db.quote("patches:sync:#{@source}")
        # A cached answer would report a lock that was never taken.
        locked = db.uncached { db.select_value("SELECT pg_try_advisory_lock(hashtext(#{lock}))") }
        raise IOError, "#{@source} sync already running" unless locked
        begin
          sync_catalog(limit, package, retry_failed)
        ensure
          db.uncached { db.select_value("SELECT pg_advisory_unlock(hashtext(#{lock}))") }
        end
      end
    end

    def sync_catalog(limit, package, retry_failed)
      scope = PatchRelease.where(distribution: @source)
      scope = scope.where(package_name: package) if package
      tracked = scope.where(id: PatchOccurrence.select(:patch_release_id)).distinct.pluck(:package_name).to_set
      scope = scope.where(last_error: nil) if retry_failed
      synced = scope.pluck(:package_name, :version, :sync_sha256).to_h { |name, version, sha| [[name, version], sha] }
      stats = { imported: 0, unchanged: 0, deferred: 0, failed: 0 }
      seen = {}
      @catalog.each_release(package: package, tracked: tracked) do |key, digest, row|
        next if seen[key] == digest
        raise IOError, "conflicting catalog checksums for #{key.join(' ')}" if seen.key?(key)
        seen[key] = digest
        if synced[key] == digest
          stats[:unchanged] += 1
        elsif stats[:imported] + stats[:failed] >= limit
          stats[:deferred] += 1
        else
          stats[attempt(key, digest, row)] += 1
        end
      end
      stats
    end

    def attempt(key, digest, row)
      @catalog.import(key, digest, row)
      :imported
    rescue *TRANSIENT => error
      warn "#{@source} #{key.join(' ')}: #{error.class}: #{error.message}"
      :failed
    rescue StandardError => error
      warn "#{@source} #{key.join(' ')}: #{error.class}: #{error.message}"
      record_failure(key, digest, row, error)
      :failed
    end

    # The same bytes would fail the same way, so wait for the catalog to change.
    def record_failure(key, digest, row, error)
      PatchRelease.record_failure!({ distribution: @source, package_name: key.first, version: key.last },
        source_url: @catalog.source_url(row), sync_sha256: digest, last_error: "#{error.class}: #{error.message}".first(250))
    rescue StandardError => failure
      warn "#{@source} #{key.join(' ')}: failure not recorded: #{failure.class}: #{failure.message}"
    end
  end
end
