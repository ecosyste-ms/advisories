class Advisory < ApplicationRecord
  belongs_to :source

  validates :uuid, presence: true, uniqueness: true

  counter_culture :source

  scope :ecosystem, ->(ecosystem) { where("? <@ ANY ( ARRAY(select jsonb_array_elements ( packages )) )",{ecosystem:ecosystem}.to_json) }
  scope :package_name, ->(package_name) { where("? <@ ANY ( ARRAY(select jsonb_array_elements ( packages )) )",{package_name:package_name}.to_json) }
  scope :severity, ->(severity) { where(severity: severity) }
  scope :repository_url, ->(repository_url) { where(repository_url: repository_url) }
  scope :created_after, ->(created_at) { where('created_at > ?', created_at) }
  scope :updated_after, ->(updated_at) { where('updated_at > ?', updated_at) }

  scope :withdrawn, -> { where.not(withdrawn_at: nil) }
  scope :not_withdrawn, -> { where(withdrawn_at: nil) }

  before_save :set_repository_url
  before_save :set_blast_radius
  after_create :sync_packages
  after_commit :update_package_advisory_counts
  after_commit :ping_packages_for_resync

  def to_s
    uuid
  end

  def to_param
    uuid
  end

  def withdrawn?
    withdrawn_at.present?
  end

  def self.packages
    all.select(:packages).map{|a| a.packages.map{|p| p.except("versions") } }.flatten.uniq
  end

  def self.ecosystems
    all.select(:packages).map{|a| a.packages.map{|p| p['ecosystem'] } }.flatten.uniq
  end

  def self.ecosystem_counts
    connection.select_all(<<~SQL).rows.map { |row| [row[0], row[1].to_i] }
      SELECT 
        package_element->>'ecosystem' as ecosystem,
        COUNT(*) as count
      FROM (
        SELECT jsonb_array_elements(packages) as package_element
        FROM (#{all.to_sql}) as scoped_advisories
      ) as package_elements
      GROUP BY package_element->>'ecosystem'
      ORDER BY count DESC
    SQL
  end

  def self.package_counts
    connection.select_all(<<~SQL).rows.map { |row| [JSON.parse(row[0]), row[1].to_i] }
      SELECT 
        jsonb_build_object(
          'ecosystem', package_element->>'ecosystem',
          'package_name', package_element->>'package_name'
        ) as package,
        COUNT(*) as count
      FROM (
        SELECT jsonb_array_elements(packages) as package_element
        FROM (#{all.to_sql}) as scoped_advisories
      ) as package_elements
      GROUP BY package_element->>'ecosystem', package_element->>'package_name'
      ORDER BY count DESC
    SQL
  end

  def self.repositories
    group(:repository_url).count
  end

  def ecosystems
    packages.map{|p| p['ecosystem'] }.uniq
  end

  def package_names
    packages.map{|p| p['package_name'] }.uniq
  end

  def version_numbers(package)
    conn = EcosystemsFaradayClient.build
    resp = conn.get(Registry.package_versions_api_link_for(package))
    return [] unless resp.success?
    json = resp.body
    json.map{|v| v['number'] }
  end
  
  def dependent_packages_api_url(package)
    "https://packages.ecosyste.ms/api/v1/dependencies?ecosystem=#{package['ecosystem']}&package_name=#{package['package_name']}&per_page=1000"
  end

  def affected_versions(package, range)
    v = version_numbers(package).map {|v| SemanticRange.clean(v, loose: true) }.compact
    v.select {|v| SemanticRange.satisfies?(v, range, platform: package['ecosystem'].humanize, loose: true) }
  end

  def affected_range_for(package)
    package['versions'].map{|v| v['vulnerable_version_range']}.join(' || ')
  end

  def affected_versions_for_package(package)
    affected_versions(package, affected_range_for(package))
  end

  def total_affected_versions
    packages.map do |package|
      affected_versions_for_package(package).count
    end.sum
  end

  def latest_resolved_version(package, version_numbers, range)
    v = version_numbers.map {|v| SemanticRange.clean(v, loose: true) }.compact
    v.select {|v| SemanticRange.satisfies?(v, range, platform: package['ecosystem'].humanize, loose: true) }.max
  end

  def affected_dependencies(package)
    vulns = affected_versions_for_package(package)
    version_numbers = version_numbers(package)

    conn = EcosystemsFaradayClient.build
    resp = conn.get(dependent_packages_api_url(package)) # TODO pagination if headers next link is present
    return [] unless resp.success?
    json = resp.body
    json.select do |dep|
      SemanticRange.satisfies?(latest_resolved_version(package, version_numbers, dep['requirements']), affected_range_for(package), platform: package['ecosystem'].humanize, loose: true)
    end
  end

  def affected_dependent_versions(package)
    affected_dependencies(package).map{|d| [d['package'], d['version']] }.uniq
  end

  def affected_dependent_packages(package)
    affected_dependencies(package).map{|d| d['package'] }.uniq
  end

  def all_affected_dependent_packages
    packages.map do |p|
      affected_dependent_packages(p)
    end.flatten.uniq.count
  end

  def all_affected_dependent_versions
    packages.map do |p|
      affected_dependent_versions(p)
    end.flatten(1).uniq.count
  end

  def set_repository_url
    self.repository_url = repository_urls.first
  end

  def repository_urls
    references.map.reject{|u| invalid_repository_urls.any?{|r| u.downcase.include?(r.downcase) }  }.map{|u| URLParser.try_all(u) }.compact.uniq
  end 

  def invalid_repository_urls
    [
      'github.com/advisories', 'github.io', 'gist.github.com', 'docs.github.com', 'github.com/dependabot', 'github.com/FriendsOfPHP/security-advisories',
      'github.com/pypa/advisory-database', 'github.com/rubysec/ruby-advisory-db', 'github.com/dotnet/announcements', 'github.com/aspnet/Announcements',
      'github.com/google/security-research', 'github.com/jacksongl/NPM-Vuln-PoC', 'github.com/rustsec/advisory-db', 'github.com/nodejs/security-wg',
      'github.com/jenkins-infra/update-center2'
    ]
  end

  # TODO store affected_dependent_packages_count and affected_dependent_versions_count in the database and sync on a regular basis

  def sync_packages
    packages.each do |package|
      pkg = Package.find_or_create_by(ecosystem: package['ecosystem'], name: package['package_name'])
      pkg.sync if pkg.last_synced_at.nil? || pkg.last_synced_at < 1.day.ago
    end
  end

  def package_records
    packages.map do |package|
      Package.find_by(ecosystem: package['ecosystem'], name: package['package_name'])
    end.compact
  end

  def total_dependent_packages_count
    package_records.map(&:dependent_packages_count).compact.sum
  end

  def total_dependent_repos_count
    package_records.map(&:dependent_repos_count).compact.sum
  end

  def total_downloads
    package_records.map(&:downloads).sum
  end

  def calculate_blast_radius
    # take the most depended upon package in each ecosystem and sum the dependent repos count and multiply by the cvss score
    ecosystems.map do |ecosystem|
      packages = package_records.select{|p| p.ecosystem == ecosystem }
      package = packages.max_by{|p| p.dependent_repos_count || 0}
      if package && package.dependent_repos_count && package.dependent_repos_count > 0
        Math.log10(package.dependent_repos_count) * cvss_score
      else
        1
      end
    end.sum
  end

  def set_blast_radius
    self.blast_radius = calculate_blast_radius
  end

  def update_blast_radius
    update_column(:blast_radius, calculate_blast_radius)
  end

  def cve
    identifiers.find{|id| id.start_with?('CVE-') }
  end

  def update_package_advisory_counts
    package_records.each(&:update_advisories_count)
  end

  def ping_packages_for_resync
    package_records.each(&:ping_for_resync)
  end
end
