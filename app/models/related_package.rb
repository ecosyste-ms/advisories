class RelatedPackage < ApplicationRecord
  belongs_to :advisory
  belongs_to :package

  validates :package_id, uniqueness: { scope: :advisory_id }

  MATCH_KINDS = %w[repo_fork likely_fork repackage unknown].freeze

  scope :name_matched, -> { where(name_match: true) }
  scope :forked, -> { where(repo_fork: true) }
  scope :not_monorepo, -> { where("repo_package_count < ?", 20) }
  scope :match_kind, ->(kind) { where(match_kind: kind) }

  ECOSYSTEM_PREFIXES = /\A(python\d*-|py\d*-|py-|ruby-|node-|lib|ghc-|haskell-|perl-|r-|erlang-|elixir-|ocaml-|lua-|php-|golang-|rust-|apache-)/i
  DISTRO_SUFFIXES = /-(dev|devel|doc|dbg|openrc|bash-completion|zsh-completion|fish-completion|libs?|static|common|utils?|tools|data|lang|locales|examples?|tests?)\z/i
  NIX_PACKAGE_SETS = /\A(python\d*Packages(_latest)?|rubyPackages|perlPackages|nodePackages(_latest)?|haskellPackages|luaPackages|ocamlPackages|beam\.packages\.\w+)\./i

  def self.normalize_name(name)
    # Extract last path segment from Go module paths like github.com/foo/bar
    if name.include?('/')
      segments = name.split('/')
      segment = segments.reverse.find { |s| !s.match?(/\Av\d+\z/) } || segments.last
      return segment.downcase
    end
    # Handle nix package set prefixes like python312Packages.requests
    stripped = name.sub(NIX_PACKAGE_SETS, '')
    # Handle distro prefixes like python3-requests, ruby-rails
    stripped = stripped.sub(ECOSYSTEM_PREFIXES, '')
    # Handle distro suffixes like -dev, -doc, -dbg
    stripped = stripped.sub(DISTRO_SUFFIXES, '')
    stripped.downcase
  end

  def self.normalize_advisory_name(name)
    # Extract last path segment from Go module paths like github.com/sigstore/cosign/v2
    if name.include?('/')
      segment = name.split('/').last
      # Skip version segments like v2, v3
      segments = name.split('/')
      segment = segments.reverse.find { |s| !s.match?(/\Av\d+\z/) } || segment
      return segment.downcase
    end
    # Strip common prefixes from advisory names too
    stripped = name.sub(ECOSYSTEM_PREFIXES, '')
    stripped.downcase
  end

  def self.compute_name_match(package_name, advisory_package_names)
    normalized = normalize_name(package_name)
    normalized_advisory_names = advisory_package_names.map { |n| normalize_advisory_name(n) }
    normalized_advisory_names.include?(normalized)
  end

  def self.compute_match_kind(name_match:, repo_fork:, package_ecosystem:, advisory_ecosystems:)
    return "repo_fork" if repo_fork
    return "unknown" unless name_match
    if advisory_ecosystems.any? { |e| e.downcase == package_ecosystem.downcase }
      "likely_fork"
    else
      "repackage"
    end
  end

  # Signal: what does the ecosystem distribution of the repo look like?
  # Returns a hash with the signal type and supporting data.
  #
  #   ecosystem_counts: { "npm" => 150, "go" => 2 }
  #   package_ecosystem: "npm"
  #   advisory_ecosystems: ["npm"]
  #
  REPACKAGER_ECOSYSTEMS = %w[conda homebrew nixpkgs debian alpine ubuntu spack adelie].freeze

  def self.compute_ecosystem_signal(ecosystem_counts:, package_ecosystem:, advisory_ecosystems:)
    total = ecosystem_counts.values.sum
    return { signal: "too_few", total: total } if total < 2

    dominant_ecosystem, dominant_count = ecosystem_counts.max_by { |_, v| v }
    dominant_ratio = dominant_count.to_f / total
    ecosystem_count = ecosystem_counts.keys.size

    repackager_ecosystems = ecosystem_counts.keys.select { |e| REPACKAGER_ECOSYSTEMS.include?(e.downcase) }
    same_ecosystem = advisory_ecosystems.any? { |e| e.downcase == package_ecosystem.downcase }

    if same_ecosystem && dominant_ratio > 0.8 && total > 100
      { signal: "fork_farm", total: total, dominant_ecosystem: dominant_ecosystem, dominant_ratio: dominant_ratio }
    elsif ecosystem_count > 3 && repackager_ecosystems.any?
      { signal: "repackaging", total: total, ecosystem_count: ecosystem_count, repackager_ecosystems: repackager_ecosystems }
    elsif same_ecosystem && dominant_ratio > 0.8
      { signal: "same_ecosystem", total: total, dominant_ecosystem: dominant_ecosystem, dominant_ratio: dominant_ratio }
    else
      { signal: "mixed", total: total, ecosystem_count: ecosystem_count }
    end
  end

  # Signal: how much do the related package's version numbers overlap
  # with the advisory package's version numbers?
  # Returns a hash with overlap count, ratio, and the overlapping versions.
  #
  #   related_versions: ["2.28.0", "2.29.0", "2.31.0"]
  #   advisory_versions: ["2.28.0", "2.28.1", "2.29.0", "2.31.0", "2.32.0"]
  #
  MIN_VERSIONS_FOR_OVERLAP = 3

  def self.compute_version_overlap(related_versions, advisory_versions, min_versions: MIN_VERSIONS_FOR_OVERLAP)
    insufficient = { overlap_count: 0, overlap_ratio: 0.0, overlapping_versions: [], sufficient_data: false }
    return insufficient if related_versions.blank? || advisory_versions.blank?

    # Normalize both sets using SemanticRange.clean
    normalize = ->(versions) {
      versions.filter_map { |v| SemanticRange.clean(v, loose: true) }.to_set
    }

    normalized_related = normalize.call(related_versions)
    normalized_advisory = normalize.call(advisory_versions)

    return insufficient if normalized_related.size < min_versions || normalized_advisory.size < min_versions

    overlapping = normalized_related & normalized_advisory
    ratio = overlapping.size.to_f / normalized_related.size

    { overlap_count: overlapping.size, overlap_ratio: ratio, overlapping_versions: overlapping.to_a, sufficient_data: true }
  end
end
