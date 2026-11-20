require 'open3'

module PatchIndex
  class NixBuild
    def initialize(root:, published:, release_url:, http: Http.new)
      @root = Pathname(root).realpath
      @revision = @root.join('.git-revision').read.strip
      raise ArgumentError, 'invalid snapshot revision' unless @revision.match?(/\A[0-9a-f]{40}\z/)
      @published = published
      @release_url = release_url
      @http = http
    end

    def import(row)
      output = row.fetch('output')
      raise IOError, 'output absent from published store paths' unless @published.include?(output)
      evidence = row.slice('system', 'attr', 'derivation', 'output').merge('nixpkgs_revision' => @revision,
        'published_manifest' => "#{@release_url}/store-paths.xz")
      identity = { distribution: 'nixpkgs', package_name: row.fetch('pname'), version: row.fetch('version'),
        revision: "#{@revision}/#{row.fetch('system')}/#{File.basename(row.fetch('derivation')).split('-').first}" }
      existing = PatchRelease.find_by(identity)
      return existing if existing && existing.metadata['derivation'] == row.fetch('derivation') &&
        existing.metadata['output'] == output && existing.metadata['inputs'] == row.fetch('patches')

      entries = row.fetch('patches').map.with_index do |input, index|
        bytes, url = read_input(input)
        Document.new(bytes, strip: nil).entry(name: "#{index + 1}/#{File.basename(input)}", source_url: url,
          declaration: evidence.merge('input' => input, 'position' => index + 1, 'attribute' => 'patches'))
      end
      PatchRelease.record!(identity, source_url: evidence.fetch('published_manifest'), metadata: evidence.merge('inputs' => row.fetch('patches')), component: {}, entries: entries)
    end

    def read_input(input)
      if input.start_with?('/release/')
        path = input.delete_prefix('/release/')
        file = @root.join(path).realpath
        raise IOError, 'patch outside snapshot' unless file.to_s.start_with?("#{@root}/") && file.file?
        url = "https://raw.githubusercontent.com/NixOS/nixpkgs/#{@revision}/#{URI::DEFAULT_PARSER.escape(path)}"
        return [file.binread, url]
      end
      hash = input[%r{\A/nix/store/([0-9a-z]{32})-[^/]+\z}, 1]
      raise IOError, "unsupported patch input #{input}" unless hash
      url = "https://cache.nixos.org/#{hash}.narinfo"
      info = @http.get(url).lines.to_h { |line| line.chomp.split(': ', 2).then { |k, v| [k, v] } }
      raise IOError, 'unexpected store path' unless info.fetch('StorePath') == input
      path = info.fetch('URL')
      raise IOError, 'invalid NAR location' unless path.match?(%r{\Anar/[\w.\-]+\z})
      blob = @http.get("https://cache.nixos.org/#{path}")
      codec = { 'xz' => 'xz', 'zstd' => 'zstd', 'bzip2' => 'bzip2' }.fetch(info.fetch('Compression'))
      nar, error, status = Open3.capture3(codec, '-dc', stdin_data: blob, binmode: true)
      raise IOError, error unless status.success?
      digest = Digest::SHA256.digest(nar).unpack1('b*').scan(/.{1,5}/)
      nix_hash = digest.reverse.map { |bits| '0123456789abcdfghijklmnpqrsvwxyz'[bits.reverse.to_i(2)] }.join
      raise IOError, 'NAR checksum mismatch' unless "sha256:#{nix_hash}" == info.fetch('NarHash')
      io = StringIO.new(nar)
      fields = Array.new(5) { nar_string(io) }
      raise IOError, 'expected regular NAR file' unless fields.first(4) == %w[nix-archive-1 ( type regular]
      key = fields.last
      if key == 'executable' && nar_string(io).empty?
        key = nar_string(io)
      end
      raise IOError, 'missing NAR contents' unless key == 'contents'
      bytes = nar_string(io)
      raise IOError, 'invalid NAR terminator' unless nar_string(io) == ')' && io.eof?
      [bytes, url]
    end

    def nar_string(io)
      size = io.read(8)&.unpack1('Q<')
      raise IOError, 'invalid NAR member length' unless size && size <= io.size - io.pos
      value = io.read(size)
      io.read((8 - size % 8) % 8)
      value
    end
  end
end
