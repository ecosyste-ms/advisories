class Patch < ApplicationRecord
  EMPTY_SHA256 = Digest::SHA256.hexdigest('').freeze

  has_one :patch_body, primary_key: :sha256, foreign_key: :sha256
  has_many :patch_occurrences, dependent: :delete_all

  INDEX_ORDERS = {
    'newest' => 'patches.id DESC',
    'oldest' => 'patches.id ASC',
    'largest' => 'byte_size DESC NULLS LAST, patches.id DESC',
    'smallest' => 'byte_size ASC NULLS LAST, patches.id DESC'
  }.freeze

  scope :declared, -> { where(id: PatchOccurrence.select(:patch_id)) }

  def display_name(occurrences = patch_occurrences)
    return 'Empty patch file' if sha256 == EMPTY_SHA256

    headers['Subject'].presence || occurrences.min_by(&:id)&.name || sha256
  end

  def debian_observations(occurrences)
    declared_ids = occurrences.map(&:patch_release_id).to_set
    names = occurrences.map(&:patch_release).select { |release| release.distribution == 'debian' }.map(&:package_name).uniq
    releases = PatchRelease.where(distribution: 'debian', package_name: names).select(:id, :package_name, :version, :source_url)
    releases.group_by(&:package_name).filter_map do |name, snapshots|
      next unless snapshots.many?
      sorted = snapshots.sort { |a, b| Vers.compare_with_scheme(a.version, b.version, 'deb') }
      [name, sorted.map { |release| [release, declared_ids.include?(release.id)] }]
    end
  end

  def self.advisories_by_identifier(occurrences)
    ids = occurrences.flat_map(&:advisory_ids).uniq
    matches = Hash.new { |hash, key| hash[key] = [] }
    return matches if ids.empty?
    advisories_for(ids).select(:uuid, :identifiers, :url, :packages, :withdrawn_at).each do |advisory|
      ([advisory.uuid] + Array(advisory.identifiers)).intersection(ids).each { |id| matches[id] << advisory }
    end
    matches
  end

  def self.advisories_for(ids)
    Advisory.where("uuid IN (?) OR identifiers && ARRAY[?]::varchar[]", ids, ids)
  end
end
