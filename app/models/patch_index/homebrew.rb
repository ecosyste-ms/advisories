module PatchIndex
  class Homebrew
    INDEX = 'https://formulae.brew.sh/api/formula.json'
    RAW = 'https://raw.githubusercontent.com/Homebrew/homebrew-core'
    INPUTS = %w[name homepage urls versions revision ruby_source_path ruby_source_checksum local_patch_checksums patches].freeze
    BUNDLE_LIMIT = 32.megabytes

    def initialize(http)
      @http = http
    end

    # Formulae without patches are skipped unless an earlier release declared some.
    def each_release(package: nil, tracked: Set.new)
      @http.json(INDEX).each do |formula|
        name = formula.fetch('name')
        next if package && name != package
        next if formula.fetch('patches').empty? && !tracked.include?(name)
        stable = formula.fetch('versions').fetch('stable')
        next unless stable
        revision = formula.fetch('revision').to_i
        version = revision.positive? ? "#{stable}_#{revision}" : stable
        yield [name, version], Digest::SHA256.hexdigest(formula.slice(*INPUTS).to_json), formula
      end
    end

    def source_url(formula)
      "#{raw(formula)}/#{formula.fetch('ruby_source_path')}"
    end

    def raw(formula)
      head = formula.fetch('tap_git_head').to_s
      raise IOError, 'missing tap commit' unless head.match?(/\A[0-9a-f]{40}\z/)
      "#{RAW}/#{head}"
    end

    def import(key, digest, formula)
      name, version = key
      raise IOError, 'unexpected formula' unless formula.values_at('name', 'tap') == [name, 'homebrew/core']
      entries = formula.fetch('patches').each_with_index.flat_map { |patch, index| declarations(formula, patch, index + 1) }
      # Two declarations can share a file name, so a repeated name carries its position.
      repeated = entries.pluck(:name).tally.select { |_, count| count > 1 }
      entries.each { |entry| entry[:name] = "#{entry[:position]}-#{entry[:name]}" if repeated.key?(entry[:name]) }
      field, repository = Repository.homebrew(formula)
      PatchRelease.record!({ distribution: 'homebrew', package_name: name, version: version }, entries,
        source_url: source_url(formula), sync_sha256: digest, upstream_version: formula.fetch('versions').fetch('stable'),
        repository_url: repository, metadata: { 'repository_field' => field }.compact)
    end

    def declarations(formula, patch, position)
      url = if patch['file']
        "#{raw(formula)}/#{patch['file']}"
      elsif patch['data']
        source_url(formula)
      else
        patch.fetch('url')
      end
      bytes = @http.get(url)
      bytes = bytes.split(/^__END__\r?\n/, 2)[1] || raise(IOError, "no DATA patch in #{url}") if patch['data']
      checksum = patch['sha256'] || formula.dig('local_patch_checksums', patch['file'])
      raise Http::Error, "SHA-256 mismatch for #{url}" if checksum && Digest::SHA256.hexdigest(bytes) != checksum
      declaration = patch.slice('strip', 'type', 'directory', 'resolves')
      return [Document.new(bytes).entry(name: patch['data'] ? 'DATA' : File.basename(URI.parse(url).path),
        position: position, source_url: url, declaration: declaration)] unless patch['apply']

      files = ArchiveReader.files(bytes, limit: BUNDLE_LIMIT)
      patch.fetch('apply').map do |member|
        matches = files.keys.select { |path| path == member || path.split('/', 2)[1] == member }
        raise IOError, "expected one archive member #{member} in #{url}" unless matches.one?
        # The resolves list describes the bundle as a whole.
        Document.new(files.fetch(matches.first)).entry(name: member, position: position, source_url: url,
          declaration: declaration.except('resolves').merge('member' => matches.first, 'bundle_resolves' => patch['resolves']).compact)
      end
    end
  end
end
