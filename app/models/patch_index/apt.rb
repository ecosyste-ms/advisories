require 'tempfile'

module PatchIndex
  class Apt
    DEBIAN = 'https://deb.debian.org/debian'
    UBUNTU = 'https://archive.ubuntu.com/ubuntu'
    POCKETS = {
      'debian' => [[DEBIAN + '-security', 'trixie-security'], [DEBIAN, 'trixie-updates'], [DEBIAN, 'trixie']],
      'ubuntu' => %w[noble-security noble-updates noble].map { |suite| [UBUNTU, suite] }
    }.freeze
    COMPONENTS = { 'debian' => %w[main contrib non-free non-free-firmware], 'ubuntu' => %w[main universe restricted multiverse] }.freeze
    ARCHIVE_LIMIT = 128.megabytes

    def initialize(distribution, http)
      @distribution = distribution
      @http = http
    end

    def each_release(package: nil, tracked: nil)
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
            yield [name, version], digest, { 'suite' => suite, 'component' => component,
              'homepage' => stanza[/^Homepage: (\S+)/, 1], 'url' => "#{base}/#{path}", 'size' => size }
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

    def source_url(row)
      row.fetch('url')
    end

    def import(key, digest, row)
      raise IOError, 'packaging archive exceeds size limit' if row.fetch('size') > ARCHIVE_LIMIT
      name, version = key
      url = row.fetch('url')
      Tempfile.create('quilt', binmode: true) do |file|
        file.write(@http.verified(url, digest, limit: row.fetch('size')))
        file.flush
        archive = QuiltArchive.new(file.path, vendor: @distribution)
        patches = archive.patches
        changes = Changelog.items(archive.changelog, name, version, patches.map(&:first))
        entries = patches.each_with_index.map do |(patch, options, bytes), index|
          declaration = { 'member' => "debian/patches/#{patch}", 'series_path' => archive.series_path,
            'quilt_options' => options.presence, 'changelog' => changes[patch] }.compact
          Document.new(bytes).entry(name: patch, position: index + 1, source_url: url, declaration: declaration)
        end
        field, repository = Repository.debian(row['homepage'], archive.metadata)
        PatchRelease.record!({ distribution: @distribution, package_name: name, version: version }, entries,
          source_url: url, sync_sha256: digest, upstream_version: self.class.upstream_version(version),
          repository_url: repository, metadata: row.slice('suite', 'component').merge('repository_field' => field).compact)
      end
    end

    def self.upstream_version(version)
      upstream = version.sub(/\A\d+:/, '')
      upstream = upstream.rpartition('-').first if upstream.include?('-')
      upstream.sub(/[+~.](?:dfsg|ds|repack)[\w.+~]*\z/i, '')
    end
  end
end
