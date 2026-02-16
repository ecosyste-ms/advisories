class Package < ApplicationRecord
  include VersionNormalization

  has_many :related_packages, dependent: :delete_all
  has_many :related_advisories, through: :related_packages, source: :advisory

  validates :ecosystem, presence: true
  validates :name, presence: true, uniqueness: { scope: :ecosystem }

  scope :ecosystem, ->(ecosystem) { where(ecosystem: ecosystem) }
  scope :critical, -> { where(critical: true) }

  def registry
    @registry = Registry.find_by_ecosystem(ecosystem)
  end

  def packages_url
    "https://packages.ecosyste.ms#{escaped_registry_package_path}"
  end

  def packages_api_url
    "https://packages.ecosyste.ms/api/v1#{escaped_registry_package_path}"
  end

  def ping_url
    "#{packages_api_url}/ping"
  end

  def sync_async
    PackageSyncWorker.perform_async(ecosystem, name)
  end

  def ping_for_resync
    return if registry.nil?
    conn = EcosystemsFaradayClient.build
    conn.get(ping_url)
  rescue => e
    Rails.logger.warn "Failed to ping #{ping_url}: #{e.message}"
  end

  def sync
    if registry.nil?
      Rails.logger.warn "[PackageSync] No registry for #{ecosystem}/#{name}"
      return
    end

    # Fetch package data with conditional request using ETag
    package_response = EcosystemsFaradayClient.conditional_get(
      "/api/v1#{escaped_registry_package_path}",
      package_etag
    )

    # Only update if data has changed (not a 304 response)
    if package_response[:success] && !package_response[:not_modified]
      json = package_response[:body]

      self.last_synced_at = Time.now
      self.dependent_packages_count = json['dependent_packages_count']
      self.dependent_repos_count = json['dependent_repos_count']
      self.downloads = json['downloads']
      self.downloads_period = json['downloads_period']
      self.latest_release_number = json['latest_release_number']
      self.repository_url = json['repository_url']
      self.description = json['description']
      self.registry_url = json['registry_url']
      self.versions_count = json['versions_count']
      self.critical = json['critical'] || false
      self.repo_metadata = json['repo_metadata']
      self.owner = extract_owner
      self.package_etag = package_response[:etag]
      save
    elsif package_response[:not_modified]
      # Data hasn't changed, just update last_synced_at
      update_column(:last_synced_at, Time.now)
    else
      Rails.logger.warn "[PackageSync] Failed to fetch #{ecosystem}/#{name}: HTTP #{package_response[:status]}"
    end

    return nil unless package_response[:success]

    # Fetch version numbers with conditional request using ETag
    versions_response = EcosystemsFaradayClient.conditional_get(
      "/api/v1#{escaped_registry_package_path}/version_numbers",
      versions_etag
    )

    if versions_response[:success] && !versions_response[:not_modified]
      self.version_numbers = versions_response[:body]
      self.versions_etag = versions_response[:etag]
      save
    end

    # update advisory count
    update_advisories_count
  end

  def advisories
    Advisory.ecosystem(ecosystem).package_name(name)
  end

  def affected_versions(range)
    # Map original versions to cleaned versions
    version_map = build_version_map(version_numbers)
    platform = ecosystem.humanize

    # Filter using cleaned versions, return originals
    original_affected = version_map.select do |original, cleaned|
      version_satisfies_range?(cleaned, range, platform)
    end.keys

    # Sort the results
    sort_versions_with_originals(original_affected)
  end

  def fixed_versions(range)
    # Map original versions to cleaned versions
    version_map = build_version_map(version_numbers)
    platform = ecosystem.humanize

    # Get affected originals
    affected_originals = version_map.select do |original, cleaned|
      version_satisfies_range?(cleaned, range, platform)
    end.keys

    # Get fixed versions (all versions minus affected)
    original_fixed = version_map.keys - affected_originals

    # ignore prerelease versions for now and sort
    sort_versions_with_originals original_fixed.reject {|v| v.include?('-') }
  end

  def sort_versions(versions)
    versions.sort_by do |v|
      # Split version by dots
      parts = v.split('.')

      # Normalize to have consistent structure for comparison
      normalized_parts = []
      4.times do |i|
        part = parts[i] || '0'

        # Split each part into numeric and non-numeric segments
        segments = part.split(/(\d+)/).reject(&:empty?)

        part_comparison = []
        segments.each do |segment|
          if segment.match?(/^\d+$/)
            part_comparison << [0, segment.to_i] # Numbers sort first
          else
            part_comparison << [1, segment] # Strings sort after numbers
          end
        end

        # If no segments (empty part), treat as [0, 0]
        part_comparison = [[0, 0]] if part_comparison.empty?

        normalized_parts << part_comparison
      end

      normalized_parts
    end
  end

  def sort_versions_with_originals(versions)
    # Create mapping of cleaned version to original
    version_map = {}
    versions.each do |v|
      cleaned = SemanticRange.clean(v, loose: true)
      version_map[cleaned] = v if cleaned
    end

    # Sort cleaned versions
    sorted_cleaned = sort_versions(version_map.keys)

    # Map back to originals
    sorted_cleaned.map {|v| version_map[v] }
  end

  def update_advisories_count
    count = advisories.count
    update_column(:advisories_count, count) if advisories_count != count
  end

  def purl
    PurlParser.generate_purl(
      ecosystem: ecosystem,
      package_name: name
    )
  end

  def escaped_registry_package_path
    "/registries/#{URI.encode_www_form_component(registry.name)}/packages/#{URI.encode_www_form_component(name)}"
  end

  def extract_owner
    repository_url.to_s.split('/')[3] if repository_url.present?
  end

  def owner_url
    repository_url.to_s.split('/')[0..3].join('/') if repository_url.present?
  end

  def repository_host
    return nil unless repository_url.present?
    URI.parse(repository_url).host
  rescue URI::InvalidURIError
    nil
  end

  def registry_name
    return nil unless registry_url.present?
    registry&.name || URI.parse(registry_url).host
  rescue URI::InvalidURIError
    nil
  end
end
