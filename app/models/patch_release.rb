class PatchRelease < ApplicationRecord
  DISTRIBUTIONS = %w[debian homebrew ubuntu].freeze
  PURL_DISTRIBUTIONS = { %w[deb debian] => 'debian', %w[deb ubuntu] => 'ubuntu', ['brew', nil] => 'homebrew' }.freeze

  has_many :patch_occurrences, dependent: :delete_all

  scope :repackaging, ->(ecosystem, name) {
    where(upstream_ecosystem: ecosystem.to_s.downcase).where('LOWER(upstream_package_name) = ?', name.to_s.downcase)
  }

  # A distro package matches by name. A registry package matches releases that name it as their upstream,
  # and releases built from its repository that name no upstream package.
  def self.for_package(ecosystem, name, version: nil)
    ecosystem, name = Package.identity_key(ecosystem, name)
    if DISTRIBUTIONS.include?(ecosystem)
      scope = where(distribution: ecosystem, package_name: name)
      return version.present? ? scope.where(version: version) : scope
    end
    scope = repackaging(ecosystem, name)
    repository = PatchIndex::Repository.normalize(Package.find_by_identity(ecosystem, name)&.repository_url)
    scope = scope.or(where(repository_url: repository, upstream_package_name: nil)) if repository
    version.present? ? scope.shipping(version) : scope
  end

  # Debian writes a pre-release as 1.0~rc1 where the registry has 1.0-rc1.
  scope :shipping, ->(version) { where(upstream_version: [version, version.tr('-', '~')].uniq) }

  def upstream_purl
    "pkg:#{upstream_ecosystem}/#{upstream_package_name}" if upstream_package_name
  end

  def registry_version
    upstream_version&.tr('~', '-')
  end

  # Advisories for the upstream package whose affected range includes the version this release ships.
  def upstream_advisories
    return Advisory.none unless upstream_package_name && upstream_version
    Advisory.not_withdrawn.affecting_version(upstream_ecosystem, upstream_package_name, registry_version)
  rescue Advisory::InvalidVersionFilter
    Advisory.none
  end

  def self.for_purl(string)
    purl = Purl.parse(string)
    if purl.type == 'github'
      scope = where(repository_url: "https://github.com/#{purl.namespace}/#{purl.name}".downcase)
      purl.version.present? ? scope.shipping(purl.version.delete_prefix('v')) : scope
    elsif (distribution = PURL_DISTRIBUTIONS[[purl.type, purl.namespace]])
      for_package(distribution, purl.name, version: purl.version)
    elsif (identity = PurlParser.parse(string))
      for_package(identity[:ecosystem], identity[:package_name], version: purl.version)
    else
      none
    end
  end

  def self.record!(identity, entries, attributes)
    names = entries.pluck(:name)
    raise ArgumentError, 'duplicate declaration name' unless names.uniq == names
    transaction do
      release = create_or_find_by!(identity) { |record| record.assign_attributes(attributes) }
      release.lock!
      release.update!(attributes.merge(last_error: nil, imported_at: Time.current))
      entries.each do |entry|
        bytes = entry.fetch(:bytes)
        patch = Patch.create_or_find_by!(sha256: entry.fetch(:sha256)) do |record|
          record.assign_attributes(headers: entry.fetch(:headers), byte_size: bytes.bytesize)
        end
        PatchBody.store!(patch.sha256, bytes)
        occurrence = release.patch_occurrences.find_or_initialize_by(name: entry.fetch(:name))
        occurrence.update!(entry.slice(:position, :source_url, :advisory_ids, :declaration).merge(patch: patch))
      end
      release.patch_occurrences.where.not(name: names).delete_all
      release
    end
  end

  # Keeps any earlier declarations and remembers the digest that failed.
  def self.record_failure!(identity, source_url:, sync_sha256:, last_error:)
    release = create_or_find_by!(identity) { |record| record.source_url = source_url }
    release.update!(sync_sha256: sync_sha256, last_error: last_error)
  end
end
