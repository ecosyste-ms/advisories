module PatchIndex
  class Homebrew

    def initialize(http = Http.new)
      @http = http
    end

    def each_release(package: nil)
      @http.json('https://formulae.brew.sh/api/formula.json').each do |formula|
        name = formula.fetch('name')
        next if package && name != package
        key = [name, formula.fetch('versions').fetch('stable'), formula.fetch('revision').to_s]
        inputs = formula.slice('name', 'homepage', 'urls', 'versions', 'revision', 'version_scheme', 'ruby_source_path',
          'ruby_source_checksum', 'local_patch_checksums', 'build_dependencies', 'patches')
        inputs['platform_patch_overrides'] = formula.fetch('variations').filter_map { |platform, v| [platform, v['patches']] if v.key?('patches') }.to_h
        if !formula.dig('ruby_source_checksum', 'sha256') || formula.fetch('patches').any? { |p| p['file'] && !formula.dig('local_patch_checksums', p['file']) }
          inputs['tap_git_head'] = formula.fetch('tap_git_head')
        end
        yield key, Digest::SHA256.hexdigest(inputs.to_json), formula
      end
    end

    def import(name, formula: nil, sync_sha256: nil)
      url = "https://formulae.brew.sh/api/formula/#{name}.json"
      formula ||= @http.json(url)
      raise IOError, 'unexpected formula' unless formula.values_at('name', 'tap') == [name, 'homebrew/core']
      head = formula.fetch('tap_git_head')
      raise IOError, 'missing tap commit' unless head.match?(/\A[0-9a-f]{40}\z/)
      @raw = "https://raw.githubusercontent.com/Homebrew/homebrew-core/#{head}"
      @formula_url = "#{@raw}/#{formula.fetch('ruby_source_path')}"
      entries = formula.fetch('patches').each_with_index.flat_map do |patch, index|
        checksum = formula.dig('local_patch_checksums', patch['file']) if patch['file']
        declarations(checksum ? patch.merge('sha256' => checksum) : patch, index + 1)
      end
      stable = formula.fetch('urls').fetch('stable')
      component = entries.empty? ? {} : component_for(stable, entries, rust: Array(formula['build_dependencies']).include?('rust'))
      identity = { distribution: 'homebrew', package_name: name, version: formula.fetch('versions').fetch('stable'), revision: formula.fetch('revision').to_s }
      metadata = formula.slice('full_name', 'homepage', 'urls', 'versions', 'tap_git_head', 'ruby_source_path', 'patches', 'version_scheme')
      metadata['sync_sha256'] = sync_sha256 if sync_sha256
      metadata['platform_patch_overrides'] = formula.fetch('variations').select { |_, v| v.key?('patches') }
      PatchRelease.record!(identity, source_url: @formula_url, metadata: metadata, component: component, entries: entries)
    end

    def declarations(patch, position)
      declaration = patch.merge('position' => position, 'scope' => 'formula_default')
      url = if patch['file']
        "#{@raw}/#{patch['file']}"
      elsif patch['data']
        @formula_url
      else
        patch.fetch('url')
      end
      bytes = @http.get(url)
      if patch['data']
        bytes = bytes.split(/^__END__\r?\n/, 2)[1] || raise(IOError, "no DATA patch in #{url}")
      end
      verify!(bytes, patch['sha256'], url) if patch['sha256']
      strip = patch['strip'].to_s[/\Ap(\d+)\z/, 1]&.to_i
      if patch['apply']
        archive = Archive.new(bytes)
        patch.fetch('apply').map do |member|
          matches = archive.files.keys.select { |path| path == member || path.split('/', 2)[1] == member }
          raise IOError, "expected one archive member #{member} in #{url}" unless matches.one?
          document = Document.new(archive.files.fetch(matches.first), strip: strip)
          # The resolves list describes the bundle as a whole.
          metadata = declaration.except('resolves').merge('bundle_resolves' => patch['resolves'], 'member' => matches.first)
          document.entry(name: member, source_url: url, declaration: metadata)
        end
      else
        name = patch['data'] ? 'DATA' : File.basename(URI.parse(url).path)
        [Document.new(bytes, strip: strip).entry(name: name, source_url: url, declaration: declaration)]
      end
    end

    def verify!(bytes, digest, url)
      raise IOError, "SHA-256 mismatch for #{url}" unless Digest::SHA256.hexdigest(bytes) == digest
    end

    def component_for(stable, entries, rust:)
      url = stable.fetch('url')
      repo = url[%r{\A(https://github\.com/[^/]+/[^/]+)/archive/refs/tags/[^/]+\.tar\.gz\z}, 1] if rust
      pypi = URI.parse(url).host == 'files.pythonhosted.org' && url.end_with?('.tar.gz')
      unless (repo || pypi) && stable['checksum'].present?
        return { 'reason' => 'no supported language registry archive', 'evidence' => stable }
      end
      bytes = @http.get(url)
      verify!(bytes, stable.fetch('checksum'), url)
      files = Archive.new(bytes).files
      manifest_name = repo ? 'Cargo.toml' : 'PKG-INFO'
      manifests = files.keys.select { |path| path.split('/').size == 2 && File.basename(path) == manifest_name }
      unless manifests.one?
        return { 'reason' => "expected one root #{manifest_name}", 'ambiguous' => manifests.many?, 'evidence' => manifests }
      end
      manifest = manifests.first
      prefix = manifest.split('/').first + '/'
      check_archive_paths(entries, files, prefix)
      evidence = stable.slice('url', 'checksum').merge('manifest' => manifest)
      if repo
        cargo_component(files.fetch(manifest), repo, evidence)
      else
        headers = files.fetch(manifest).split(/\r?\n\r?\n/, 2).first
        name = headers[/^Name: ([\w.-]+)\s*$/, 1]
        version = headers[/^Version: ([\w.+-]+)\s*$/, 1]
        raise IOError, "incomplete PKG-INFO in #{url}" unless name && version
        { 'identity' => { 'ecosystem' => 'pypi', 'name' => name, 'version' => version },
          'method' => 'registry_archive', 'evidence' => evidence.merge('name' => name, 'version' => version) }
      end
    end

    def cargo_component(body, repo, evidence)
      source = { 'manifest' => 'Cargo.toml', 'url' => evidence.fetch('url'), 'body' => body }
      package = Component.resolve(source)['identity']
      return { 'reason' => 'no literal crate identity', 'evidence' => evidence } unless package
      link = "https://packages.ecosyste.ms/api/v1/registries/crates.io/packages/#{ERB::Util.url_encode(package.fetch('name'))}"
      evidence = evidence.merge('manifest_identity' => package, 'registry_record' => link)
      record = @http.json(link)
      evidence['registry_repository'] = record['repository_url']
      unless record['name'] == package['name'] && record['ecosystem'] == 'cargo' && repo.casecmp?(record['repository_url'].to_s.delete_suffix('.git').delete_suffix('/'))
        return { 'reason' => 'registry identity or repository differs', 'ambiguous' => true, 'evidence' => evidence }
      end
      if package['version']
        version_url = "#{link}/versions/#{ERB::Util.url_encode(package['version'])}"
        evidence['registry_release'] = version_url
        release = @http.json(version_url)
        return { 'reason' => 'registry version differs', 'ambiguous' => true, 'evidence' => evidence } unless release['number'] == package['version']
      end
      { 'identity' => package, 'method' => 'manifest_and_registry_repository', 'evidence' => evidence }
    rescue Http::NotFound
      { 'reason' => 'registry record unavailable', 'evidence' => evidence }
    end

    def check_archive_paths(entries, files, prefix)
      entries.each do |entry|
        Component.check_paths(entry) do |file|
          ancestors = File.dirname(file).split('/')
          nested = ancestors.each_index.any? do |i|
            dir = prefix + ancestors.take(i + 1).join('/') + '/'
            %w[pyproject.toml setup.py Cargo.toml package.json].any? { |f| files.key?(dir + f) } ||
              files.keys.any? { |path| File.dirname(path) + '/' == dir && path.end_with?('.gemspec') }
          end
          if nested
            "nested component at #{file}"
          elsif !files.key?(prefix + file)
            "path absent from source archive: #{file}"
          end
        end
      end
    end
  end
end
