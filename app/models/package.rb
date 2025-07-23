class Package < ApplicationRecord
  validates :ecosystem, presence: true
  validates :name, presence: true, uniqueness: { scope: :ecosystem }

  scope :ecosystem, ->(ecosystem) { where(ecosystem: ecosystem) }
  scope :critical, -> { where(critical: true) }

  def registry
    @registry = Registry.find_by_ecosystem(ecosystem)
  end

  def packages_url
    "https://packages.ecosyste.ms/registries/#{registry.name}/packages/#{name}"
  end

  def ping_url
    "#{packages_url}/ping"
  end

  def extract_owner
    repository_url.to_s.split('/')[3] if repository_url.present?
  end

  def owner_url
    repository_url.to_s.split('/')[0..3].join('/') if repository_url.present?
  end

  def sync
    return if registry.nil?
    conn = EcosystemsFaradayClient.build
    
    response = conn.get("/api/v1/registries/#{CGI.escape(registry.name)}/packages/#{name}")
    return nil unless response.success?
    json = response.body

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
    save

    # download version numbers
    response = conn.get("/api/v1/registries/#{CGI.escape(registry.name)}/packages/#{name}/version_numbers")
    return nil unless response.success?

    self.version_numbers = response.body
    save
    
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
    # split by major, minor, patch, prerelease and sort each part
    versions.sort_by do |v|
      v.split('.').map do |part|
        part.split(/(\d+)|(\D+)/).map { |p| p.match?(/\d+/) ? p.to_i : p }
      end
    end
  end

  def update_advisories_count
    count = advisories.count
    update_column(:advisories_count, count) if advisories_count != count
  end

  def ping_for_resync
    return if registry.nil?
    conn = EcosystemsFaradayClient.build
    conn.post(ping_url)
  rescue => e
    Rails.logger.warn "Failed to ping #{ping_url}: #{e.message}"
  end
end
