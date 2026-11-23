class Patch < ApplicationRecord
  EMPTY_SHA256 = Digest::SHA256.hexdigest('').freeze
  INDEX_ORDERS = {
    'newest' => { id: :desc },
    'oldest' => { id: :asc },
    'largest' => { byte_size: :desc, id: :desc },
    'smallest' => { byte_size: :asc, id: :desc }
  }.freeze

  has_one :patch_body, primary_key: :sha256, foreign_key: :sha256
  has_many :patch_occurrences, dependent: :delete_all

  scope :declared, -> { where(id: PatchOccurrence.select(:patch_id)) }

  def to_param
    sha256
  end

  def display_name(occurrences = patch_occurrences)
    return 'Empty patch file' if sha256 == EMPTY_SHA256
    headers['Subject'].presence || occurrences.min_by(&:id)&.name || sha256
  end

  def self.advisories_by_identifier(occurrences)
    ids = occurrences.flat_map(&:advisory_ids).uniq
    matches = Hash.new { |hash, key| hash[key] = [] }
    return matches if ids.empty?
    Advisory.where('uuid IN (?) OR identifiers && ARRAY[?]::varchar[]', ids, ids).each do |advisory|
      advisory.patch_identifiers.intersection(ids).each { |id| matches[id] << advisory }
    end
    matches
  end
end
