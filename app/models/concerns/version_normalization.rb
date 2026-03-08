module VersionNormalization
  extend ActiveSupport::Concern

  def build_version_map(versions)
    versions.filter_map do |original|
      cleaned = Vers.clean(original)
      [original, cleaned] if cleaned
    end.to_h
  end

  def version_satisfies_range?(version, range, ecosystem)
    scheme = PurlParser.reverse_map_ecosystem(ecosystem) || ecosystem&.downcase
    return false unless scheme
    Vers.satisfies?(version, range, scheme)
  rescue ArgumentError
    false
  end
end
