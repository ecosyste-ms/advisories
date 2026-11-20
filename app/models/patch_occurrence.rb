class PatchOccurrence < ApplicationRecord
  belongs_to :patch
  belongs_to :patch_release

  class InvalidRange < ArgumentError; end

  def upstream_package_key
    identity = PurlParser.parse(project_purl)
    Package.identity_key(identity[:ecosystem], identity[:package_name]) if identity
  end

  def self.for_package(ecosystem, name, version: nil)
    ecosystem, name = Package.identity_key(ecosystem, name)
    if %w[conda-forge debian fedora homebrew nixpkgs ubuntu].include?(ecosystem)
      releases = PatchRelease.where(distribution: ecosystem, package_name: name)
      releases = releases.where(version: version) if version.present?
      where(patch_release: releases)
    else
      purl = PurlParser.generate_purl(ecosystem: ecosystem, package_name: name, version: version.presence)
      return none if purl.blank?
      where((version.present? ? :purl : :project_purl) => purl)
    end
  end

  def self.matching(filters)
    scope = all
    if filters[:distribution].present?
      scope = scope.joins(:patch_release).where('LOWER(patch_releases.distribution) = ?', filters[:distribution].downcase)
    end
    if filters[:advisory].present?
      identifier = PatchIndex::Document.identifier(filters[:advisory])
      aliases = Patch.advisories_for([identifier]).pluck(:identifiers).flatten.compact
      scope = scope.where("advisory_ids && ARRAY[?]::varchar[]", [identifier, *aliases].uniq)
    end
    parsed = Purl.parse(filters[:purl]) if filters[:purl].present?
    if parsed&.type == 'github'
      scope = scope.where(patch_release_id: PatchRelease.for_source_repository(parsed.to_s).select(:id))
    elsif parsed
      column = parsed.version ? :purl : :project_purl
      scope = scope.where(column => parsed.to_s)
    end
    return scope if filters[:version_range].blank?
    unless parsed && !parsed.version && %w[gem cargo pypi].include?(parsed.type)
      raise InvalidRange, 'version_range requires an unversioned gem, cargo or pypi PURL'
    end
    range = Vers.parse_native(filters[:version_range], parsed.type)
    raise InvalidRange, 'invalid version_range' unless range
    observed = scope.distinct.pluck(:purl).select do |purl|
      version = Purl.parse(purl).version
      version && range.contains?(version, include_prerelease: true)
    end
    scope.where(purl: observed)
  rescue ArgumentError => error
    raise InvalidRange, error.message
  end

  def source_repository
    source = patch_release.source_repository
    return unless source

    comparison = PatchIndex::RepositoryComparison.for_occurrence(self)
    kind = comparison&.fetch('all_paths_corroborated') ? 'changed_file_match' : 'release_source_declaration'
    source.merge('kind' => kind, 'comparison' => comparison).compact
  end

  def assertions
    attributions = declaration.fetch('advisory_evidence', {}).map do |identifier, fields|
      { kind: 'advisory_reference', identifier: identifier, fields: fields }
    end
    headers = patch.headers
    if headers['commit'].present?
      attributions << { kind: 'commit_reference', identifier: headers['commit'], fields: ['header.commit'] }
    end
    [headers['Origin'], declaration['url']].zip(%w[header.Origin declaration.url]).each do |value, field|
      value.to_s.scan(%r{https?://[^\s,]+/commits?/([0-9a-f]{40})\b}i) do |(sha)|
        attributions << { kind: 'commit_reference', identifier: sha, fields: [field], source: value }
      end
    end
    { declared: { source_url: patch_release.source_url }, attributed: attributions, verified: nil }
  end

  def advisory_roles
    return {} if advisory_ids.empty?
    fixes = explicit_fix_ids
    advisory_ids.index_with do |identifier|
      fields = Array(declaration.dig('advisory_evidence', identifier))
      if fixes.include?(identifier)
        'explicit_fix'
      elsif fields.include?('name')
        'patch_name'
      else
        'context'
      end
    end
  end

  def explicit_fix_ids
    ids = Array(declaration['resolves']).filter_map do |resolution|
      resolution['id'] if resolution.is_a?(Hash) && resolution['type'] == 'security' && resolution['id'].is_a?(String)
    end
    id = PatchIndex::Document::ADVISORY
    Array(declaration.dig('changelog', 'items')).each do |item|
      text = item.squish
      # named_changes retains bullets tied to exactly one patch in this release.
      match = text.match(/\A(?:Add|Apply|Backport) (?:patch )?#{Regexp.escape(name)}(?: cherry[ -]picked from upstream)? to fix (?:[\w -]+ vulnerability\. )?(#{id}(?:[, ]+#{id})*)(?: \(Closes: #\d+\))?\.?\z/i)
      ids.concat(match[1].scan(id)) if match
    end
    [patch.headers['Subject'], patch.headers['Description']].compact.each do |text|
      match = text.match(/\A(?:\[PATCH\]\s*)?Fix(?:es|ed)?[: ]+(#{id}(?:[, ]+#{id})*)[.]?\z/i)
      ids.concat(match[1].scan(id)) if match
    end
    ids.map { |value| PatchIndex::Document.identifier(value) }
  end

  def resolve!
    component = PatchIndex::Component.resolve(patch_release.component)
    candidate = component['identity']
    supported = candidate && scope_evidence['reason'].nil?
    self.project_purl = self.purl = nil
    if supported
      identity = { ecosystem: candidate.fetch('ecosystem'), package_name: candidate.fetch('name') }
      self.project_purl = PurlParser.generate_purl(**identity)
      self.purl = PurlParser.generate_purl(**identity, version: candidate['version'])
    end
    status = if purl
      'mapped'
    elsif component['ambiguous'] || candidate
      'ambiguous'
    else
      'unresolved'
    end
    self.mapping = {
      status: status,
      confidence: purl ? 'inferred' : nil,
      method: component['method'],
      reason: component['reason'] || scope_evidence['reason'],
      candidate: candidate,
      evidence: component['evidence']
    }.compact
    save!
  end
end
