module VersionNormalization
  extend ActiveSupport::Concern

  def clean_version(version)
    return nil unless version.match?(/\Av?\d+\.\d+\.\d+/)
    version.sub(/\Av/, '')
  end

  def build_version_map(versions)
    versions.filter_map do |original|
      cleaned = clean_version(original)
      [original, cleaned] if cleaned
    end.to_h
  end

  def version_satisfies_range?(version, range, ecosystem)
    scheme = vers_scheme(ecosystem)
    sub_ranges = range.split('||').map(&:strip).reject(&:empty?)
    sub_ranges.any? do |sub_range|
      normalized = normalize_range_for_vers(sub_range, scheme)
      Vers.satisfies?(version, normalized, scheme)
    rescue ArgumentError
      false
    end
  end

  def vers_scheme(ecosystem)
    PurlParser.reverse_map_ecosystem(ecosystem) || ecosystem&.downcase
  end

  def normalize_range_for_vers(range, scheme)
    case scheme
    when "gem", "pypi"
      range
    when "npm"
      range.gsub(/\s*,\s*/, ' ').gsub(/(>=|<=|!=|[<>=])\s+/, '\1')
    else
      range.gsub(/\s*,\s*/, '|')
    end
  end
end
