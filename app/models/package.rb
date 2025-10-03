class Package < ApplicationRecord
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

  def ping_for_resync
    return if registry.nil?
    conn = EcosystemsFaradayClient.build
    conn.post(ping_url)
  rescue => e
    Rails.logger.warn "Failed to ping #{ping_url}: #{e.message}"
  end

  def sync
    return if registry.nil?

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
      self.owner = extract_owner
      self.package_etag = package_response[:etag]
      save
    elsif package_response[:not_modified]
      # Data hasn't changed, just update last_synced_at
      update_column(:last_synced_at, Time.now)
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
    v = version_numbers.map {|v| SemanticRange.clean(v, loose: true) }.compact
    sort_versions v.select {|v| SemanticRange.satisfies?(v, range, platform: ecosystem.humanize, loose: true) }
  end

  def fixed_versions(range)
    av = affected_versions(range)
    v = version_numbers.map {|v| SemanticRange.clean(v, loose: true) }.compact - av
    # ignore prerelease versions for now
    sort_versions v.reject {|v| v.include?('-') }
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
  end

  def registry_name
    return nil unless registry_url.present?
    registry&.name || URI.parse(registry_url).host
  end
end
