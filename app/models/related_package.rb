class RelatedPackage < ApplicationRecord
  belongs_to :advisory
  belongs_to :package

  validates :package_id, uniqueness: { scope: :advisory_id }

  scope :name_matched, -> { where(name_match: true) }
  scope :forked, -> { where(fork: true) }
  scope :not_monorepo, -> { where("repo_package_count < ?", 20) }

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
end
