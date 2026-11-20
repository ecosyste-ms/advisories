module PatchIndex
  class Debian
    HOST = 'https://sources.debian.org'

    def initialize(http = Http.new)
      @http = http
    end

    def import(name, version)
      @directories = {}
      @release = [name, version].map { |s| ERB::Util.url_encode(s) }.join('/')
      summary_url = "#{HOST}/patches/api/#{@release}/"
      summary = @http.json(summary_url)
      raise IOError, 'Debian returned another release' unless summary.values_at('package', 'version') == [name, version]
      root = directory('')
      area = root.fetch('pkg_infos').fetch('area')
      prefix = name.start_with?('lib') ? name[0, 4] : name[0]
      @raw = "#{HOST}/data/#{area}/#{prefix}/#{@release}"
      component = find_component(root)
      paths = summary.fetch('patches')
      series = paths.empty? ? [] : @http.get("#{@raw}/debian/patches/series").lines.map { |line| line.sub(/#.*/, '').split }.reject(&:empty?)
      raise IOError, "Debpatches and quilt series disagree for #{@release}" unless paths.sort == series.map(&:first).sort
      changelog_url = "#{@raw}/debian/changelog"
      changes = paths.empty? ? {} : named_changes(@http.get(changelog_url), name, version, paths)
      entries = series.map.with_index do |(path, *options), index|
        detail = @http.json("#{summary_url}#{encode_path(path)}/")
        url = HOST + detail.fetch('url')
        strip = if options.empty?
          1
        elsif options.size == 1 && options.first.match?(/\A-p\d+\z/)
          options.first.delete_prefix('-p').to_i
        end
        patch = Document.new(@http.get(url), strip: strip)
        declaration = detail.merge('quilt_options' => options, 'position' => index + 1)
        if changes.key?(path)
          declaration['changelog'] = { 'url' => changelog_url, 'items' => changes.fetch(path) }
        end
        entry = patch.entry(name: path, source_url: url, declaration: declaration)
        Component.check_paths(entry) { |file| path_problem(file) } if component['manifest']
        entry
      end
      revision = version.rpartition('-').last if version.include?('-')
      identity = { distribution: 'debian', package_name: name, version: version, revision: revision.to_s }
      metadata = summary.merge('pkg_infos' => root['pkg_infos'])
      if paths.any? && root.fetch('content').any? { |node| node.values_at('name', 'type') == %w[debian directory] }
        packaging = {}
        %w[debian/upstream/metadata debian/copyright].each do |file|
          packaging[file] = @http.get("#{@raw}/#{file}")
        rescue Http::NotFound
          next
        end
        sources = SourceRepository.debian_sources(root.fetch('pkg_infos'), packaging)
        metadata['source_repository'] = SourceRepository.declaration(sources)
      end
      PatchRelease.record!(identity, source_url: summary_url, metadata: metadata, component: component, entries: entries)
    end

    def named_changes(text, name, version, patches)
      lines = text.lines
      return {} unless lines.shift.to_s.start_with?("#{name} (#{version}) ")
      items = lines.take_while { |line| line.start_with?(' ', "\n") && !line.start_with?(' -- ') }.join.split(/^  \* /)
      matches = Hash.new { |hash, path| hash[path] = [] }
      items.each do |item|
        named = patches.select { |path| item.match?(/(?<![\w.\/-])#{Regexp.escape(path)}(?![\w\/-]|\.\w)/) }
        matches[named.first] << item.strip if named.one?
      end
      matches
    end

    def encode_path(path)
      path.split('/').map { |part| ERB::Util.url_encode(part) }.join('/')
    end

    def directory(path)
      suffix = path.empty? ? '' : "#{encode_path(path)}/"
      @directories[path] ||= @http.json("#{HOST}/api/src/#{@release}/#{suffix}")
    end

    def find_component(root)
      manifests = root.fetch('content').select { |node| node['type'] == 'file' && node['name'].match?(Component::MANIFEST) }.pluck('name')
      unless manifests.one?
        return { 'reason' => 'expected one root language manifest', 'ambiguous' => manifests.many?, 'evidence' => manifests }
      end
      name = manifests.first
      url = "#{@raw}/#{encode_path(name)}"
      body = @http.get(url)
      component = { 'manifest' => name, 'url' => url, 'body' => body }
      if name.end_with?('.gemspec') && (path = GemVersion.path(body))
        file_url = "#{@raw}/#{path}"
        begin
          component['version_file'] = { 'url' => file_url, 'body' => @http.get(file_url) }
        rescue Http::NotFound
          # A packaged gemspec may require a file absent from the source tree.
        end
      end
      parsed = Component.resolve(component)
      registry = synced_release(parsed)
      if !registry && parsed.dig('evidence', 'version_source')
        registry = gem_release(parsed)
        component.delete('version_file') unless registry
      end
      component['registry_release'] = registry if registry
      component
    end

    def gem_release(parsed)
      name, version = parsed.fetch('identity').values_at('name', 'version')
      url = "https://rubygems.org/api/v2/rubygems/#{ERB::Util.url_encode(name)}/versions/#{ERB::Util.url_encode(version)}.json"
      record = @http.json(url)
      return unless record.values_at('name', 'version') == [name, version]
      upstream = parsed.dig('evidence', 'fields', 'homepage')
      return unless upstream.present? && [record['source_code_uri'], record['homepage_uri']].include?(upstream)
      { 'url' => url, 'versions_url' => url, 'repository' => upstream, 'name' => name, 'version' => version }
    rescue Http::NotFound
      nil
    end

    def synced_release(parsed)
      identity = parsed['identity']
      return unless identity && identity['version']
      fields = parsed.dig('evidence', 'fields')
      repository = fields['repository'] || fields['homepage']
      return if repository.blank?
      package = Package.find_by_identity(identity['ecosystem'], identity['name'])
      return unless package&.last_synced_at && package.registry && package.version_numbers&.include?(identity['version'])
      return unless package.repository_url.present? && repository.delete_suffix('.git') == package.repository_url.delete_suffix('.git')
      { 'url' => package.packages_api_url, 'versions_url' => "#{package.packages_api_url}/version_numbers",
        'repository' => package.repository_url, 'version' => identity['version'], 'name' => package.name,
        'synced_at' => package.last_synced_at.iso8601 }
    end

    def path_problem(file)
      parent = ''
      parts = file.split('/')
      parts.each_with_index do |part, index|
        nodes = directory(parent).fetch('content')
        if parent.present? && nodes.any? { |node| node['name'].match?(Component::MANIFEST) || %w[setup.py package.json go.mod].include?(node['name']) }
          return "nested component at #{parent}"
        end
        expected = index == parts.size - 1 ? 'file' : 'directory'
        return "missing #{expected} in Debian source: #{file}" unless nodes.any? { |node| node['name'] == part && node['type'] == expected && !node.dig('stat', 'symlink_dest') }
        parent = [parent.presence, part].compact.join('/')
      end
      nil
    end
  end
end
