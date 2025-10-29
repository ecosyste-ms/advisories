module VersionNormalization
  extend ActiveSupport::Concern

  def clean_version(version)
    # Only attempt normalization if version looks roughly like semver (has at least x.x.x pattern)
    # Handle optional "v" prefix for Go packages
    return nil unless version.match?(/^v?\d+\.\d+\.\d+/)

    # Check if we need to normalize the prerelease part
    # Example: "1.7.0-alpha.2" -> "1.7.0-alpha"
    if version.include?('-')
      parts = version.split('-', 2)
      base = parts[0]
      prerelease = parts[1]

      # If prerelease has dots, keep only the first part
      if prerelease && prerelease.include?('.')
        first_prerelease = prerelease.split('.').first
        normalized = "#{base}-#{first_prerelease}"

        # Try cleaning the normalized version
        cleaned = SemanticRange.clean(normalized, loose: true)
        return cleaned if cleaned.present?
      end
    end

    # Otherwise try standard cleaning
    SemanticRange.clean(version, loose: true)
  end

  def build_version_map(versions)
    versions.map do |original|
      cleaned = clean_version(original)
      [original, cleaned] if cleaned.present?
    end.compact.to_h
  end

  def version_satisfies_range?(cleaned_version, range, platform)
    # First try the standard check
    if SemanticRange.satisfies?(cleaned_version, range, platform: platform, loose: true)
      true
    elsif cleaned_version.include?('-')
      # For prerelease versions, also check if the base version would satisfy the range
      # This handles cases where "1.7.0-alpha" should match "< 1.11.0"
      base_version = cleaned_version.split('-').first
      SemanticRange.satisfies?(base_version, range, platform: platform, loose: true)
    else
      false
    end
  end
end
