require 'test_helper'
require 'rubygems/package'

class PatchIndex::ImportTest < ActiveSupport::TestCase
  setup do
    @http = PatchIndex::Http.new(cache: ActiveSupport::Cache::NullStore.new, interval: 0)
    @fixture = Rails.root.join('test/fixtures/files/patch_index')
    @bytes = @fixture.join('relax-dep.patch').binread
    @debian = JSON.parse(@fixture.join('debian.json').read)
    @host = PatchIndex::Debian::HOST
    @raw = "#{@host}/data/main/r/rust-regex/1.11.1-2"
    @summary = "#{@host}/patches/api/rust-regex/1.11.1-2/"
    @root = "#{@host}/api/src/rust-regex/1.11.1-2/"
  end

  test 'a pinned formula imports through the same declaration parser without fetching the live formula' do
    url = 'https://example.org/link.patch'
    response_at(url, @bytes)
    formula = { 'name' => 'example', 'tap' => 'homebrew/core', 'tap_git_head' => 'a' * 40,
      'versions' => { 'stable' => '1.0' }, 'revision' => 2, 'variations' => {}, 'ruby_source_path' => 'Formula/e/example.rb',
      'urls' => { 'stable' => { 'url' => 'https://example.org/src.tgz' } },
      'patches' => [{ 'url' => url, 'sha256' => Digest::SHA256.hexdigest(@bytes), 'strip' => 'p1' }] }
    release = PatchIndex::Homebrew.new(@http).import('example', formula: formula)
    assert_equal '2', release.revision
    assert_equal Digest::SHA256.hexdigest(@bytes), release.patch_occurrences.sole.patch.sha256
    assert_not_requested :get, 'https://formulae.brew.sh/api/formula/example.json'
  end

  def response_at(url, data)
    stub_request(:get, url).to_return(body: data.is_a?(String) ? data : data.to_json)
  end

  def debian_responses
    response_at(@summary, @debian['summary'])
    response_at(@root, @debian['root'])
    response_at("#{@raw}/Cargo.toml", @debian['manifest'])
    response_at("#{@raw}/debian/patches/series", @debian['series'])
    response_at("#{@raw}/debian/changelog", "rust-regex (1.11.1-2) unstable; urgency=medium\n\n  * relax-dep.patch updates a dependency.\n  * Another change mentions CVE-2099-1234.\n")
    response_at(@summary + 'relax-dep.patch/', @debian['detail'])
    response_at(@host + @debian['detail']['url'], @bytes)
  end

  def import_debian
    PatchIndex::Debian.new(@http).import('rust-regex', '1.11.1-2')
  end

  test 'Debian release repository survives a missing optional upstream metadata file' do
    debian_responses
    @debian['root']['content'] << { name: 'debian', type: 'directory' }
    response_at(@root, @debian['root'])
    stub_request(:get, "#{@raw}/debian/upstream/metadata").to_return(status: 404)
    response_at("#{@raw}/debian/copyright", "Source: https://github.com/rust-lang/regex\n")
    assert_equal 'pkg:github/rust-lang/regex', import_debian.source_repository.fetch('purl')
  end

  def homebrew_response(patch, stable: { url: 'https://example.org/src.tgz' }, build_dependencies: [])
    formula = { name: 'example', tap: 'homebrew/core', tap_git_head: 'a' * 40,
      ruby_source_path: 'Formula/e/example.rb', patches: [patch], versions: { stable: '2' },
      urls: { stable: stable }, build_dependencies: build_dependencies, revision: 1, variations: {} }
    response_at('https://formulae.brew.sh/api/formula/example.json', formula)
  end

  test 'two feeds and repeated imports share bytes and keep distinct evidence' do
    debian_responses
    release = import_debian
    assert_equal 'pkg:cargo/regex@1.11.1', release.patch_occurrences.sole.purl
    refute release.patch_occurrences.sole.advisory_ids.any?
    url = 'https://example.org/other-name.diff'
    homebrew_response({ url: url, sha256: Digest::SHA256.hexdigest(@bytes), strip: 'p1', type: 'backport',
                      resolves: [{ type: 'security', id: 'GHSA-f8vr-r385-rh5r' }] })
    response_at(url, @bytes)
    brew = PatchIndex::Homebrew.new(@http)
    twice = 2.times.map { brew.import('example').patch_occurrences.sole }
    assert_equal twice.first.id, twice.last.id
    assert_equal import_debian.patch_occurrences.sole.patch_id, twice.first.patch_id
    assert_equal 1, Patch.count
    assert_equal 2, PatchOccurrence.count
    assert_nil twice.first.purl
    assert_equal ['resolves'], twice.first.declaration['advisory_evidence']['GHSA-f8vr-r385-rh5r']
    response_at(url, 'changed bytes')
    assert_raises(IOError) { brew.import('example') }
    assert_equal 2, PatchOccurrence.count
  end

  test 'a patch touching another component withholds the whole mapping' do
    debian_responses
    @debian['root']['content'] << { name: 'other', type: 'directory' }
    response_at(@root, @debian['root'])
    response_at(@root + 'other/', { content: [{ name: 'Cargo.toml', type: 'file' }] })
    response_at(@host + @debian['detail']['url'], @bytes + @bytes.gsub('a/Cargo.toml', 'a/other/Cargo.toml').gsub('b/Cargo.toml', 'b/other/Cargo.toml'))
    occurrence = import_debian.patch_occurrences.sole
    assert_nil occurrence.purl
    assert_equal 'ambiguous', occurrence.mapping['status']
    assert_includes occurrence.scope_evidence['reason'], 'nested component'
  end

  test 'Debian captures registry evidence only for the same repository and observed release' do
    debian_responses
    create(:registry, name: 'crates.io', ecosystem: 'cargo')
    pkg = create(:package, name: 'regex', ecosystem: 'cargo', repository_url: 'https://github.com/rust-lang/regex',
      version_numbers: ['1.11.1'], last_synced_at: Time.current)
    claim = import_debian.patch_occurrences.sole
    assert_equal 'manifest_and_registry_release', claim.mapping['method']
    assert_equal '1.11.1', claim.mapping.dig('evidence', 'registry_release', 'version')
    pkg.update!(repository_url: 'https://example.org/a-fork')
    assert_nil import_debian.component['registry_release']
    pkg.update!(repository_url: 'https://github.com/rust-lang/regex', version_numbers: ['2.0.0'])
    assert_nil import_debian.component['registry_release']
  end

  test 'a required Ruby version file needs a matching registry release and repository' do
    name = 'ruby-widget'
    version = '1.2-3'
    raw = "#{@host}/data/main/r/#{name}/#{version}"
    repo = 'https://github.com/example/widget'
    response_at("#{@host}/patches/api/#{name}/#{version}/", { package: name, version: version, patches: [] })
    response_at("#{@host}/api/src/#{name}/#{version}/", { pkg_infos: { area: 'main' }, content: [{ type: 'file', name: 'widget.gemspec' }] })
    response_at("#{raw}/widget.gemspec", "require 'widget/version'\ns.name = 'widget'\ns.version = Widget::VERSION\ns.homepage = '#{repo}'\n")
    response_at("#{raw}/lib/widget/version.rb", "module Widget\n VERSION = '1.2'.freeze\nend")
    registry = 'https://rubygems.org/api/v2/rubygems/widget/versions/1.2.json'
    response_at(registry, { name: 'widget', version: '1.2', source_code_uri: repo })
    importer = PatchIndex::Debian.new(@http)
    mapped = PatchIndex::Component.resolve(importer.import(name, version).component)
    assert_equal registry, mapped.dig('evidence', 'registry_release', 'url')
    assert_equal '1.2', mapped.dig('identity', 'version')
    response_at(registry, { name: 'widget', version: '1.2', source_code_uri: 'https://example.org/other' })
    project = PatchIndex::Component.resolve(importer.import(name, version).component)
    assert_equal 'widget', project.dig('identity', 'name')
    assert_nil project.dig('identity', 'version')
  end

  test 'archive security references stay scoped to the bundle' do
    tar = StringIO.new(''.b)
    Gem::Package::TarWriter.new(tar) do |writer|
      %w[CVE-2099-1234.patch packaging.patch].each do |name|
        writer.add_file_simple("debian/patches/#{name}", 0o644, @bytes.bytesize) { |io| io.write(@bytes) }
      end
    end
    archive = Zlib.gzip(tar.string)
    url = 'https://example.org/patches.tar.gz'
    homebrew_response({ url: url, strip: 'p1', sha256: Digest::SHA256.hexdigest(archive),
      apply: %w[patches/CVE-2099-1234.patch patches/packaging.patch], resolves: [{ type: 'security', id: 'CVE-2099-1234' }] })
    response_at(url, archive)
    claims = PatchIndex::Homebrew.new(@http).import('example').patch_occurrences.order(:name)
    assert_equal [%w[CVE-2099-1234], []], claims.map(&:advisory_ids)
    assert_equal 1, claims.distinct.count(:patch_id)
    assert_equal Digest::SHA256.hexdigest(@bytes), claims.first.patch.sha256
  end

  test 'Homebrew GitHub archive requires registry, repository, release and patch paths to agree' do
    repo = 'https://github.com/nikolassv/bartib'
    tar = StringIO.new(''.b)
    files = { 'Cargo.toml' => "[package]\nname = 'bartib'\nversion = '1.1.0'\n", 'Cargo.lock' => 'content' }
    Gem::Package::TarWriter.new(tar) do |writer|
      files.each do |name, body|
        writer.add_file_simple("bartib-1.1.0/#{name}", 0o644, body.bytesize) { |io| io.write(body) }
      end
    end
    archive = Zlib.gzip(tar.string)
    url = "#{repo}/archive/refs/tags/v1.1.0.tar.gz"
    response_at(url, archive)
    homebrew_response({ data: true, strip: 'p1' }, stable: { url: url, checksum: Digest::SHA256.hexdigest(archive) }, build_dependencies: ['rust'])
    response_at("https://raw.githubusercontent.com/Homebrew/homebrew-core/#{'a' * 40}/Formula/e/example.rb", "__END__\n" + @bytes.gsub('Cargo.toml', 'Cargo.lock'))
    registry = 'https://packages.ecosyste.ms/api/v1/registries/crates.io/packages/bartib'
    record = { name: 'bartib', ecosystem: 'cargo', repository_url: repo }
    response_at(registry, record)
    response_at("#{registry}/versions/1.1.0", { number: '1.1.0' })
    importer = PatchIndex::Homebrew.new(@http)
    assert_equal 'pkg:cargo/bartib@1.1.0', importer.import('example').patch_occurrences.sole.purl
    response_at(registry, record.merge(repository_url: 'https://example.org/elsewhere'))
    occurrence = importer.import('example').patch_occurrences.sole
    assert_nil occurrence.purl
    assert_equal 'ambiguous', occurrence.mapping['status']
  end

  test 'changelog references require one named patch in the same release and bullet' do
    text = "rust-h2 (1-2) stable; urgency=medium\n\n  * Add fix.patch for\n    RUSTSEC-2099-1234.\n  * Add follow-up.patch separately.\n  * fix.patch and follow-up.patch jointly mention CVE-2099-9999.\n\n -- Maintainer\n\n  * fix.patch mentions an old CVE.\n"
    parser = PatchIndex::Debian.new(@http)
    changes = parser.named_changes(text, 'rust-h2', '1-2', %w[fix.patch follow-up.patch])
    assert_equal ["Add fix.patch for\n    RUSTSEC-2099-1234."], changes['fix.patch']
    assert_equal ['Add follow-up.patch separately.'], changes['follow-up.patch']
    assert_empty parser.named_changes(text, 'rust-h2', '1-1', %w[fix.patch])
  end
end
