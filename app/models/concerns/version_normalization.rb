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
    range = range.tr(',', ' ') if scheme == 'npm'
    Vers.satisfies?(version, range, scheme, include_prerelease: true)
  rescue ArgumentError
    false
  end
end
