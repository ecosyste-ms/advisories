module PatchIndex
  module Component
    MANIFEST = /\A(?:Cargo\.toml|pyproject\.toml|.+\.gemspec)\z/
    BOUNDARY = %r{(?:\A|/)(?:vendor(?:ed)?|third[-_]party|debian|node_modules|deps|external)(?:/|\z)}i

    def self.resolve(source)
      return source unless source['manifest']
      name, body, url = source.values_at('manifest', 'body', 'url')
      if name.end_with?('.gemspec')
        ecosystem = 'rubygems'
        fields = body.scan(/^\s*\w+\.(name|version|homepage)\s*=\s*["']([^"'#\n]+)["'](?:\.freeze)?\s*$/).to_h
      else
        cargo = name == 'Cargo.toml'
        ecosystem = cargo ? 'cargo' : 'pypi'
        section = cargo ? 'package' : 'project'
        lines = body.lines.drop_while { |line| line.strip != "[#{section}]" }.drop(1)
        fields = lines.take_while { |line| !line.start_with?('[') }.join.scan(/^\s*(name|version|repository)\s*=\s*["']([\w.:+\/-]+)["']\s*$/).to_h
      end
      evidence = { 'url' => url, 'fields' => fields }
      return { 'evidence' => evidence, 'reason' => 'no literal package name' } unless fields['name']&.match?(/\A[\w.-]+\z/)
      if source['version_file']
        file = source.fetch('version_file')
        version = GemVersion.read(body, file.fetch('body'))
        if version
          fields['version'] = version.fetch('value')
          evidence['version_source'] = version.merge('url' => file.fetch('url'))
        end
      end
      evidence['registry_release'] = source['registry_release'] if source['registry_release']
      { 'identity' => { 'ecosystem' => ecosystem, 'name' => fields['name'], 'version' => fields['version'] }.compact,
        'method' => source['registry_release'] ? 'manifest_and_registry_release' : 'source_manifest', 'evidence' => evidence }
    end

    def self.check_paths(entry)
      scope = entry.fetch(:scope_evidence)
      return if scope['reason']
      scope['files'].each do |file|
        reason = if file.match?(BOUNDARY)
          "distribution or bundled component path: #{file}"
        else
          yield file
        end
        if reason
          scope['reason'] = reason
          break
        end
      end
    end
  end
end
