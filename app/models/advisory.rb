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
    connection.select_all(<<~SQL).rows.map { |row| JSON.parse(row[0]) }
      SELECT DISTINCT jsonb_build_object(
        'ecosystem', package_element->>'ecosystem',
        'package_name', package_element->>'package_name'
      )::text as package
      FROM (
        SELECT jsonb_array_elements(packages) as package_element
        FROM (#{all.to_sql}) as scoped_advisories
      ) as package_elements
      ORDER BY package
    SQL
  end

  def self.ecosystems
    connection.select_values(<<~SQL)
      SELECT DISTINCT package_element->>'ecosystem' as ecosystem
      FROM (
        SELECT jsonb_array_elements(packages) as package_element
        FROM (#{all.to_sql}) as scoped_advisories
      ) as package_elements
      ORDER BY ecosystem
    SQL
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

    version_map.select do |original, cleaned|
      version_satisfies_range?(cleaned, range, package['ecosystem'])
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

    matching_versions = version_map.select do |original, cleaned|
      version_satisfies_range?(cleaned, range, package['ecosystem'])
    end

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
      resolved = latest_resolved_version(package, version_numbers, dep['requirements'])
      resolved && version_satisfies_range?(resolved, affected_range_for(package), package['ecosystem'])
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

    existing_pairs = packages.map { |p| [p['ecosystem'].downcase, p['package_name'].downcase.sub(%r{/v\d+\z}, '')] }.to_set
    advisory_package_names = packages.map { |p| p['package_name'] }
    advisory_ecosystems = packages.map { |p| p['ecosystem'] }
    repo_package_count = api_packages.size

    # Filter to only new/related packages (not already in advisory)
    filtered_api_packages = api_packages.filter_map do |api_pkg|
      ecosystem = api_pkg['ecosystem']&.downcase
      name = api_pkg['name']
      next if ecosystem.blank? || name.blank?
      next if existing_pairs.include?([ecosystem, name.downcase.sub(%r{/v\d+\z}, '')])
      api_pkg
    end

    return related_packages.delete_all if filtered_api_packages.empty?

    # Batch find or create all packages in 2 queries instead of N
    package_keys = filtered_api_packages.map { |p| [p['ecosystem'].downcase, p['name']] }
    existing_packages = Package.where(
      package_keys.map { "(ecosystem = ? AND name = ?)" }.join(" OR "),
      *package_keys.flatten
    ).index_by { |p| [p.ecosystem, p.name] }

    missing_packages = package_keys.reject { |key| existing_packages.key?(key) }
    if missing_packages.any?
      now = Time.current
      Package.insert_all(
        missing_packages.map { |eco, name| { ecosystem: eco, name: name, created_at: now, updated_at: now } }
      )
      # Reload to get IDs for newly inserted packages
      existing_packages = Package.where(
        package_keys.map { "(ecosystem = ? AND name = ?)" }.join(" OR "),
        *package_keys.flatten
      ).index_by { |p| [p.ecosystem, p.name] }
    end

    # Build related package records in bulk
    now = Time.current
    related_records = filtered_api_packages.filter_map do |api_pkg|
      ecosystem = api_pkg['ecosystem'].downcase
      name = api_pkg['name']
      pkg = existing_packages[[ecosystem, name]]
      next unless pkg

      name_match = RelatedPackage.compute_name_match(name, advisory_package_names, package_ecosystem: ecosystem)
      is_fork = api_pkg.dig('repo_metadata', 'fork') == true
      match_kind = RelatedPackage.compute_match_kind(
        name_match: name_match, repo_fork: is_fork,
        package_ecosystem: ecosystem, advisory_ecosystems: advisory_ecosystems
      )

      {
        advisory_id: id,
        package_id: pkg.id,
        name_match: name_match,
        repo_fork: is_fork,
        match_kind: match_kind,
        repo_package_count: repo_package_count,
        created_at: now,
        updated_at: now
      }
    end

    # Upsert all related packages in one query
    if related_records.any?
      RelatedPackage.upsert_all(
        related_records,
        unique_by: [:advisory_id, :package_id],
        update_only: [:name_match, :repo_fork, :match_kind, :repo_package_count]
      )
    end

    # Remove stale related packages
    current_package_ids = related_records.map { |r| r[:package_id] }
    related_packages.where.not(package_id: current_package_ids).delete_all
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

  MATCH_KIND_ORDER = %w[repo_fork likely_fork repackage].freeze

  def classified_related_packages
    related_packages.where(match_kind: MATCH_KIND_ORDER).includes(:package).order(
      Arel.sql("CASE match_kind WHEN 'repo_fork' THEN 0 WHEN 'likely_fork' THEN 1 WHEN 'repackage' THEN 2 END")
    )
  end

  def unclassified_related_packages
    related_packages.where(match_kind: [nil, "unknown"]).includes(:package)
  end

  def related_advisories
    return @preloaded_related_advisories if instance_variable_defined?(:@preloaded_related_advisories)
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
    package_keys = packages.map { |p| [p['ecosystem'], p['package_name']] }

    pkg_records = if instance_variable_defined?(:@preloaded_package_records)
      @preloaded_package_records
    else
      Package.where(
        package_keys.map { "(ecosystem = ? AND name = ?)" }.join(" OR "),
        *package_keys.flatten
      ).index_by { |p| [p.ecosystem, p.name] }
    end

    packages.map do |package|
      package_record = pkg_records[[package['ecosystem'], package['package_name']]]
      [package, package_record]
    end
  end

  # Batch preload package records and related advisories for a collection.
  # Uses subqueries on advisory IDs so Postgres extracts the JSONB/array
  # values itself, instead of passing hundreds of parameters.
  def self.preload_associations(advisories)
    advisories = advisories.to_a
    return if advisories.empty?

    advisory_ids = advisories.map(&:id)

    # Batch load all package records via subquery on the JSONB packages column
    all_pkg_records = Package.where(
      "(ecosystem, name) IN (SELECT pe->>'ecosystem', pe->>'package_name' FROM advisories, jsonb_array_elements(packages) AS pe WHERE advisories.id IN (?))",
      advisory_ids
    ).index_by { |p| [p.ecosystem, p.name] }

    advisories.each { |a| a.instance_variable_set(:@preloaded_package_records, all_pkg_records) }

    # Batch load related advisories via subquery extracting CVEs from identifiers
    has_cves = advisories.any? { |a| a.cve }

    if has_cves
      related = Advisory.where(
        "identifiers && (SELECT array_agg(DISTINCT ident) FROM advisories, unnest(identifiers) AS ident WHERE advisories.id IN (?) AND ident LIKE 'CVE-%')::varchar[]",
        advisory_ids
      ).where.not(id: advisory_ids).includes(:source)

      cve_to_advisory = {}
      advisories.each do |a|
        c = a.cve
        cve_to_advisory[c] = a if c
      end

      grouped = {}
      related.each do |r|
        r.identifiers.each do |ident|
          if cve_to_advisory.key?(ident)
            grouped[ident] ||= []
            grouped[ident] << r
          end
        end
      end

      advisories.each do |a|
        a.instance_variable_set(:@preloaded_related_advisories, grouped[a.cve] || [])
      end
    else
      advisories.each { |a| a.instance_variable_set(:@preloaded_related_advisories, []) }
    end
  end

  def cache_affected_versions!
    return if packages.blank?

    package_keys = packages.map { |p| [p['ecosystem'], p['package_name']] }
    package_records = Package.where(
      package_keys.map { "(ecosystem = ? AND name = ?)" }.join(" OR "),
      *package_keys.flatten
    ).index_by { |p| [p.ecosystem, p.name] }

    updated_packages = packages.map do |package|
      pkg = package_records[[package['ecosystem'], package['package_name']]]
      if pkg&.version_numbers.present?
        vulnerable_range = (package['versions'] || []).map { |v| v['vulnerable_version_range'] }.compact.join(' || ')
        package.merge(
          'affected_versions' => pkg.affected_versions(vulnerable_range),
          'unaffected_versions' => pkg.fixed_versions(vulnerable_range)
        )
      else
        package.merge('affected_versions' => [], 'unaffected_versions' => [])
      end
    end

    update_column(:packages, updated_packages)
  end
end
