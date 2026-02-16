class Advisory < ApplicationRecord
  include VersionNormalization

  belongs_to :source

  has_many :related_packages, dependent: :delete_all
  has_many :related_package_records, through: :related_packages, source: :package

  validates :uuid, presence: true, uniqueness: true

  counter_culture :source

  scope :ecosystem, ->(ecosystem) { where("packages @> ?::jsonb", [{ecosystem: ecosystem.downcase}].to_json) }
  scope :package_name, ->(package_name) { 
    where("packages @> ?::jsonb", [{package_name: package_name}].to_json)
      .or(where("packages @> ?::jsonb", [{package_name: package_name.downcase}].to_json))
      .or(where("EXISTS (SELECT 1 FROM jsonb_array_elements(packages) AS p WHERE LOWER(p->>'package_name') = LOWER(?))", package_name))
  }
  scope :severity, ->(severity) { where(severity: severity) }
  scope :repository_url, ->(repository_url) { where(repository_url: repository_url) }
  scope :source_kind, ->(source_kind) { joins(:source).where(sources: { kind: source_kind }) }
  scope :created_after, ->(created_at) { where('created_at > ?', created_at) }
  scope :updated_after, ->(updated_at) { where('updated_at > ?', updated_at) }

  scope :withdrawn, -> { where.not(withdrawn_at: nil) }
  scope :not_withdrawn, -> { where(withdrawn_at: nil) }

  before_save :set_repository_url
  before_save :set_blast_radius
  after_commit :enqueue_package_sync
  after_commit :enqueue_related_packages_sync

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
    # Try to find cached package record
    pkg = Package.find_by(ecosystem: package['ecosystem'], name: package['package_name'])

    # If we have cached version numbers, use them
    if pkg && pkg.version_numbers.present?
      return pkg.version_numbers
    end

    # Otherwise fetch from API
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
    originals = version_numbers(package)
    version_map = build_version_map(originals)
    platform = package['ecosystem'].humanize

    # Filter using cleaned versions, return originals
    version_map.select do |original, cleaned|
      version_satisfies_range?(cleaned, range, platform)
    end.keys
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
    version_map = build_version_map(version_numbers)
    platform = package['ecosystem'].humanize

    # Filter using cleaned versions
    matching_versions = version_map.select do |original, cleaned|
      version_satisfies_range?(cleaned, range, platform)
    end

    # Return the max cleaned version (not original) for comparison purposes
    matching_versions.values.max
  end

  def affected_dependencies(package)
    vulns = affected_versions_for_package(package)
    version_numbers = version_numbers(package)

    # Check if we have a cached package record to potentially avoid API calls
    pkg = Package.find_by(ecosystem: package['ecosystem'], name: package['package_name'])

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
    new_url = repository_urls.first
    self.repository_url = new_url if repository_url != new_url
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

  def enqueue_package_sync
    packages.each do |package|
      PackageSyncWorker.perform_async(package['ecosystem'], package['package_name'])
    end
  end

  def enqueue_related_packages_sync
    RelatedPackagesSyncWorker.perform_async(id) if repository_url.present?
  end

  def sync_related_packages
    return if repository_url.blank?

    conn = EcosystemsFaradayClient.build
    resp = conn.get("/api/v1/packages/lookup", { repository_url: repository_url })
    return unless resp.success?

    api_packages = resp.body
    return unless api_packages.is_a?(Array)

    existing_pairs = packages.map { |p| [p['ecosystem'].downcase, p['package_name'].downcase] }.to_set
    advisory_package_names = packages.map { |p| p['package_name'] }
    repo_package_count = api_packages.size

    current_related_ids = Set.new
    api_packages.each do |api_pkg|
      ecosystem = api_pkg['ecosystem']&.downcase
      name = api_pkg['name']
      next if ecosystem.blank? || name.blank?
      next if existing_pairs.include?([ecosystem, name.downcase])

      pkg = Package.find_or_create_by(ecosystem: ecosystem, name: name)
      next unless pkg.persisted?

      name_match = RelatedPackage.compute_name_match(name, advisory_package_names)
      is_fork = api_pkg.dig('repo_metadata', 'fork') == true
      related = RelatedPackage.find_or_create_by(advisory: self, package: pkg)
      related.update(name_match: name_match, repo_package_count: repo_package_count, fork: is_fork)
      current_related_ids << related.id
    end

    related_packages.where.not(id: current_related_ids).delete_all
  end

  def sync_packages
    packages.each do |package|
      PackageSyncWorker.perform_async(package['ecosystem'], package['package_name'])
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
    new_radius = calculate_blast_radius
    self.blast_radius = new_radius if blast_radius != new_radius
  end

  def update_blast_radius
    update_column(:blast_radius, calculate_blast_radius)
  end

  def cve
    identifiers.find{|id| id.start_with?('CVE-') }
  end

  def related_advisories
    return Advisory.none unless cve
    Advisory.where("? = ANY(identifiers)", cve).where.not(id: id)
  end

  def ecosystems_repo_url
    return nil unless repository_url
    parsed = URLParser.try_all(repository_url)
    return nil unless parsed

    uri = URI.parse(parsed)
    host = uri.host
    path = uri.path.sub(/^\//, '').sub(/\.git$/, '')

    "https://repos.ecosyste.ms/hosts/#{host}/repositories/#{path}"
  rescue URI::InvalidURIError
    nil
  end

  def repository_full_name
    return nil unless repository_url
    parsed = URLParser.try_all(repository_url)
    return nil unless parsed

    uri = URI.parse(parsed)
    uri.path.sub(/^\//, '').sub(/\.git$/, '')
  rescue URI::InvalidURIError
    nil
  end

  def update_package_advisory_counts
    packages.each do |package|
      PackageSyncWorker.perform_async(package['ecosystem'], package['package_name'])
    end
  end

  def ping_packages_for_resync
    packages.each do |package|
      PackageSyncWorker.perform_async(package['ecosystem'], package['package_name'])
    end
  end

  def packages_with_records
    # Collect all unique ecosystem/name pairs
    package_keys = packages.map { |p| [p['ecosystem'], p['package_name']] }

    # Batch load all package records in a single query
    package_records = Package.where(
      package_keys.map { |ecosystem, name|
        "(ecosystem = ? AND name = ?)"
      }.join(" OR "),
      *package_keys.flatten
    ).index_by { |p| [p.ecosystem, p.name] }

    # Map packages with their records
    packages.map do |package|
      package_record = package_records[[package['ecosystem'], package['package_name']]]
      [package, package_record]
    end
  end
end
