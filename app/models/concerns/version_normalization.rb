module VersionNormalization
  extend ActiveSupport::Concern

  # Vers cache lookups can race with eviction in another thread.
  RANGE_MUTEX = Mutex.new

  def build_version_map(versions)
    versions.filter_map do |original|
      cleaned = Vers.clean(original)
      [original, cleaned] if cleaned
    end.to_h
  end

  def version_satisfies_range?(version, range, ecosystem)
    scheme = PurlParser.reverse_map_ecosystem(ecosystem) || ecosystem&.downcase
    return false unless scheme
    RANGE_MUTEX.synchronize { Vers.satisfies?(version, range, scheme) }
  rescue ArgumentError
    false
  end
end
