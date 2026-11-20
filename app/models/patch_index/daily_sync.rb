module PatchIndex
  class DailySync
    SOURCES = %w[debian homebrew ubuntu].freeze

    def initialize(source, http: Http.new(cache: ActiveSupport::Cache::NullStore.new))
      raise ArgumentError, "unknown distribution #{source}" unless SOURCES.include?(source)
      @source = source
      @catalog = source == 'homebrew' ? Homebrew.new(http) : AptCatalog.new(source, http)
    end

    def run(limit: 200, package: nil)
      raise ArgumentError, 'limit must be positive' unless limit.positive?
      PatchRelease.connection_pool.with_connection do |db|
        lock = db.quote("patches:sync:#{@source}")
        raise IOError, "#{@source} sync already running" unless db.select_value("SELECT pg_try_advisory_lock(hashtext(#{lock}))")
        begin
          sync_catalog(limit, package)
        ensure
          db.select_value("SELECT pg_advisory_unlock(hashtext(#{lock}))")
        end
      end
    end

    def sync_catalog(limit, package)
      scope = PatchRelease.where(distribution: @source)
      scope = scope.where(package_name: package) if package
      fingerprints = scope.pluck(:package_name, :version, :revision,
        Arel.sql("metadata->>'sync_sha256'")).to_h { |name, version, rev, sha| [[name, version, rev], sha] }
      tracked = fingerprints.keys.map(&:first).to_set
      stats = { imported: 0, unchanged: 0, deferred: 0, failed: 0 }
      seen = {}
      @catalog.each_release(package: package) do |key, digest, row|
        next if seen[key] == digest
        if seen.key?(key)
          raise IOError, "conflicting catalog checksums for #{key.join(' ')}"
        end
        seen[key] = digest
        if @source == 'homebrew' && row.fetch('patches').empty? && !tracked.include?(key.first) &&
            row.fetch('variations').values.none? { |v| v['patches'].present? }
          next
        end
        if fingerprints[key] == digest
          stats[:unchanged] += 1
        elsif stats[:imported] + stats[:failed] >= limit
          stats[:deferred] += 1
        else
          begin
            if @source == 'homebrew'
              @catalog.import(key.first, formula: row, sync_sha256: digest)
            else
              @catalog.import(key, digest, row)
            end
            stats[:imported] += 1
          rescue StandardError => error
            stats[:failed] += 1
            warn "#{@source} #{key.join(' ')}: #{error.class}: #{error.message}"
          end
        end
      end
      stats
    end
  end
end
