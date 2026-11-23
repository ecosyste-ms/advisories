class PatchOccurrence < ApplicationRecord
  ROLES = { 'explicit_fix' => 'Identified as a fix', 'patch_name' => 'In filename', 'context' => 'Contextual mention' }.freeze

  belongs_to :patch
  belongs_to :patch_release

  scope :referencing, ->(identifiers) { where('advisory_ids && ARRAY[?]::varchar[]', Array(identifiers)) }

  def self.matching(filters)
    scope = all
    scope = scope.where(patch_release: PatchRelease.for_purl(filters[:purl])) if filters[:purl].present?
    if filters[:repository_url].present?
      repository = PatchIndex::Repository.normalize(filters[:repository_url])
      scope = scope.where(patch_release: PatchRelease.where(repository_url: repository.to_s))
    end
    if filters[:distribution].present?
      scope = scope.where(patch_release: PatchRelease.where(distribution: filters[:distribution].to_s.downcase))
    end
    return scope if filters[:advisory].blank?
    given = filters[:advisory].to_s.strip
    # Advisory UUIDs keep their case; identifiers named by patches are normalised.
    ids = [given, PatchIndex::Document.identifier(given)].uniq
    advisories = Advisory.where('uuid IN (?) OR identifiers && ARRAY[?]::varchar[]', ids, ids)
    scope.referencing((ids + advisories.flat_map(&:patch_identifiers)).uniq)
  end

  # Says how each advisory identifier relates to this patch.
  def advisory_roles
    fixes = explicit_fix_ids
    advisory_ids.index_with do |identifier|
      if fixes.include?(identifier)
        'explicit_fix'
      elsif Array(declaration.dig('advisory_evidence', identifier)).include?('name')
        'patch_name'
      else
        'context'
      end
    end
  end

  def explicit_fix_ids
    id = PatchIndex::Document::ADVISORY
    ids = Array(declaration['resolves']).filter_map do |resolution|
      resolution['id'] if resolution.is_a?(Hash) && resolution['type'] == 'security' && resolution['id'].is_a?(String)
    end
    Array(declaration['changelog']).each do |item|
      match = item.squish.match(/\A(?:Add|Apply|Backport) (?:patch )?#{Regexp.escape(name)}(?: cherry[ -]picked from upstream)? to fix (?:[\w -]+ vulnerability\. )?(#{id}(?:[, ]+#{id})*)(?: \(Closes: #\d+\))?\.?\z/i)
      ids.concat(match[1].scan(id)) if match
    end
    patch.headers.values_at('Subject', 'Description').compact.each do |text|
      match = text.match(/\A(?:\[PATCH\]\s*)?Fix(?:es|ed)?[: ]+(#{id}(?:[, ]+#{id})*)[.]?\z/i)
      ids.concat(match[1].scan(id)) if match
    end
    ids.map { |value| PatchIndex::Document.identifier(value) }
  end
end
