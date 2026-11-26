module VersionNormalization
  extend ActiveSupport::Concern

  # Ubuntu versions follow Debian ordering, and opam orders versions with the same algorithm.
  SCHEMES = { 'debian' => 'deb', 'ubuntu' => 'deb', 'opam' => 'deb' }.freeze

  def version_scheme(ecosystem)
    SCHEMES[ecosystem&.downcase] || PurlParser.reverse_map_ecosystem(ecosystem) || ecosystem&.downcase
  end

  def build_version_map(versions, ecosystem = nil)
    scheme = SCHEMES[ecosystem&.downcase]
    versions.filter_map do |original|
      cleaned = scheme ? Vers.clean(original, scheme) : Vers.clean(original)
      [original, cleaned] if cleaned
    end.to_h
  end

  def version_satisfies_range?(version, range, ecosystem)
    scheme = version_scheme(ecosystem)
    return false unless scheme
    range = range.tr(',', ' ') if scheme == 'npm'
    Vers.satisfies?(version, range, scheme, include_prerelease: true)
  rescue ArgumentError
    false
  end
end
