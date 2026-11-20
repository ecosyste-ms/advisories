require 'tempfile'
require 'tmpdir'

module PatchIndex
  class AptCatalog
    DEBIAN = 'https://deb.debian.org/debian'
    UBUNTU = 'https://archive.ubuntu.com/ubuntu'
    POCKETS = {
      'debian' => [[DEBIAN + '-security', 'trixie-security'], [DEBIAN, 'trixie-updates'], [DEBIAN, 'trixie']],
      'ubuntu' => %w[noble-security noble-updates noble].map { |suite| [UBUNTU, suite] }
    }.freeze
    COMPONENTS = { 'debian' => %w[main contrib non-free non-free-firmware], 'ubuntu' => %w[main universe restricted multiverse] }.freeze

    def initialize(distribution, http)
      @distribution = distribution
      @http = http
    end

    def each_release(package: nil)
      POCKETS.fetch(@distribution).each do |base, suite|
        COMPONENTS.fetch(@distribution).each do |component|
          url = "#{base}/dists/#{suite}/#{component}/source/Sources.xz"
          each_stanza(url) do |stanza|
            next unless stanza.include?("Format: 3.0 (quilt)\n")
            name = stanza[/^Package: (\S+)/, 1]
            next if package && name != package
            version = stanza[/^Version: (\S+)/, 1]
            raise IOError, "missing package or version in #{url}" unless name && version
            digest, size, path = packaging_archive(stanza)
            row = { 'suite' => suite, 'component' => component, 'index' => url, 'homepage' => stanza[/^Homepage: (\S+)/, 1],
              'url' => "#{base}/#{path}", 'size' => size }
            yield [name, version, version.rpartition('-').last], digest, row
          end
        end
      end
    end

    def each_stanza(url)
      Tempfile.create('apt-sources', binmode: true) do |file|
        file.write(@http.get(url))
        file.flush
        IO.popen(['xz', '-dc', file.path], 'rb') { |io| io.each_line("\n\n") { |stanza| yield stanza } }
        raise IOError, "invalid xz index #{url}" unless $?.success?
      end
    end

    def packaging_archive(stanza)
      directory = stanza[/^Directory: (\S+)/, 1]
      hashes = stanza[/^Checksums-Sha256:\n((?: [^\n]+\n?)+)/, 1].to_s
      members = hashes.lines.filter_map { |line| line.split if line.match?(/\.debian\.tar\.\w+\s*\z/) }
      raise IOError, "expected one packaging archive in #{directory}" unless members.one?
      digest, size, filename = members.first
      unless directory&.match?(%r{\Apool/(?:[\w.+-]+/)*[\w.+-]+\z}) && !directory.split('/').intersect?(%w[. ..]) &&
          filename.match?(/\A[\w.+~-]+\z/) && digest.match?(/\A[0-9a-f]{64}\z/) && size.match?(/\A\d+\z/)
        raise IOError, "invalid packaging archive record for #{directory}/#{filename}"
      end
      [digest, Integer(size), "#{directory}/#{filename}"]
    end

    def import(key, digest, row)
      raise IOError, 'packaging archive exceeds 128 MB' if row.fetch('size') > 128.megabytes
      name, version, revision = key
      identity = { distribution: @distribution, package_name: name, version: version, revision: revision }
      url = row.fetch('url')
      Dir.mktmpdir('quilt') do |dir|
        archive = File.join(dir, 'archive')
        File.binwrite(archive, @http.verified(url, digest))
        blobs = Pathname.new(dir).join('patches')
        extracted = QuiltArchive.new(blobs).extract(archive, digest, vendor: @distribution)
        entries = DebianCatalog.new(blobs).quilt_entries(name, version, extracted, url)
        sources = SourceRepository.debian_sources(row, extracted.fetch('repository_files'))
        metadata = row.merge('sync_sha256' => digest, 'source_repository' => SourceRepository.declaration(sources, archive_sha256: digest))
        previous = PatchRelease.find_by(identity)
        component = { 'reason' => 'upstream identity has not been assessed' }
        if previous && !previous.metadata['sync_sha256']
          component = previous.component
          metadata = previous.metadata.merge(metadata)
          indexed = previous.patch_occurrences.includes(:patch).index_by(&:name)
          entries.each do |entry|
            old = indexed[entry.fetch(:name)]
            next unless old && old.patch.sha256 == entry[:sha256]
            next unless old.declaration['quilt_options'] == entry[:declaration]['quilt_options']
            entry[:scope_evidence] = old.scope_evidence
            evidence = old.declaration.fetch('advisory_evidence', {}).merge(entry[:declaration].fetch('advisory_evidence')) { |_, a, b| a | b }
            entry[:declaration] = old.declaration.merge(entry[:declaration]).merge('advisory_evidence' => evidence)
            entry[:advisory_ids] = evidence.keys
          end
        end
        PatchRelease.record!(identity, source_url: url, metadata: metadata, component: component, entries: entries)
      end
    end
  end
end
