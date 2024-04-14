class Package < ApplicationRecord
  validates :ecosystem, presence: true
  validates :name, presence: true, uniqueness: { scope: :ecosystem }

  scope :ecosystem, ->(ecosystem) { where(ecosystem: ecosystem) }

  def registry
    @registry = Registry.find_by_ecosystem(ecosystem)
  end

  def sync
    return if registry.nil?
    conn = Faraday.new('https://packages.ecosyste.ms') do |f|
      f.request :json
      f.request :retry
      f.response :json
    end
    
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
    save

    # download version numbers
    response = conn.get("/api/v1/registries/#{CGI.escape(registry.name)}/packages/#{name}/version_numbers")
    return nil unless response.success?

    self.version_numbers = response.body
    save
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
end
