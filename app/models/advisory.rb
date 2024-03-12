class Advisory < ApplicationRecord
  belongs_to :source

  validates :uuid, presence: true, uniqueness: true

  counter_culture :source

  scope :ecosystem, ->(ecosystem) { where("? <@ ANY ( ARRAY(select jsonb_array_elements ( packages )) )",{ecosystem:ecosystem}.to_json) }
  scope :package_name, ->(package_name) { where("? <@ ANY ( ARRAY(select jsonb_array_elements ( packages )) )",{package_name:package_name}.to_json) }
  scope :severity, ->(severity) { where(severity: severity) }
  scope :created_after, ->(created_at) { where('created_at > ?', created_at) }
  scope :updated_after, ->(updated_at) { where('updated_at > ?', updated_at) }

  before_save :set_repository_url

  def to_s
    uuid
  end

  def to_param
    uuid
  end

  def self.packages
    all.select(:packages).map{|a| a.packages.map{|p| p.except("versions") } }.flatten.uniq
  end

  def self.ecosystems
    all.select(:packages).map{|a| a.packages.map{|p| p['ecosystem'] } }.flatten.uniq
  end

  def ecosystems
    packages.map{|p| p['ecosystem'] }.uniq
  end

  def package_names
    packages.map{|p| p['package_name'] }.uniq
  end

  def version_numbers(package)
    resp = Faraday.get(Registry.package_versions_api_link_for(package))
    return [] unless resp.success?
    json = JSON.parse(resp.body)
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

  def latest_resolved_version(package, version_numbers, range)
    v = version_numbers.map {|v| SemanticRange.clean(v, loose: true) }.compact
    v.select {|v| SemanticRange.satisfies?(v, range, platform: package['ecosystem'].humanize, loose: true) }.max
  end

  def affected_dependencies(package)
    vulns = affected_versions_for_package(package)
    version_numbers = version_numbers(package)

    resp = Faraday.get(dependent_packages_api_url(package)) # TODO pagination if headers next link is present
    return [] unless resp.success?
    json = JSON.parse(resp.body)
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

  def affected_dependent_packages
    packages.map do |p|
      affected_dependent_packages(p)
    end.flatten.uniq.count
  end

  def affected_dependent_versions
    packages.map do |p|
      affected_dependent_versions(p)
    end.flatten(1).uniq.count
  end

  def set_repository_url
    self.repository_url = repository_urls.first
  end

  def repository_urls
    references.reject{|u| invalid_repository_urls.any?{|r| u.include?(r) }  }.map{|u| URLParser.try_all(u) }.compact.uniq
  end 

  def invalid_repository_urls
    ['github.com/advisories', 'github.io', 'gist.github.com', 'docs.github.com', 'github.com/dependabot']
  end

  # TODO store affected_dependent_packages_count and affected_dependent_versions_count in the database and sync on a regular basis
end
