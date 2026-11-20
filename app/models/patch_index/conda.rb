require 'open3'
require 'yaml'
require 'rubygems/package'

module PatchIndex
  class Conda
    attr_reader :transferred

    def initialize(http = Http.new)
      @http = http
    end

    def import(pin)
      url = pin.fetch('archive_url')
      digest = pin.fetch('archive_sha256')
      bytes = @http.verified(url, digest)
      if url.end_with?('.conda')
        stem = File.basename(URI.parse(url).path, '.conda')
        bytes = member(bytes, "info-#{stem}.tar.zst")
      end

      read = ->(*paths) { [paths.first, member(bytes, paths.first)] }
      record(pin, { 'archive_sha256' => digest, 'verification' => 'whole_archive_sha256' }, read)
    end

    def import_build(pin, max_bytes:)
      @transferred = 0
      reader = CondaMetadata.new(pin, max_bytes)
      evidence = { 'catalog_sha256' => pin['archive_sha256'], 'catalog_md5' => pin['md5'],
        'verification' => 'archive_byte_ranges' }.compact
      reader.with_recipe do |members|
        read = lambda do |*paths|
          row = members.call(*paths)
          evidence.merge!('etag' => reader.etag, 'transferred' => reader.transferred)
          row
        end
        record(pin, evidence, read)
      end
    ensure
      @transferred = reader&.transferred.to_i
    end

    def record(pin, verification, read)
      url = pin.fetch('archive_url')
      index = JSON.parse(read.call('info/index.json').last)
      keys = %w[name version build build_number subdir]
      # Early conda-build versions omitted subdir from info/index.json.
      index['subdir'] ||= pin.fetch('subdir')
      raise IOError, 'unexpected conda build' unless index.fetch_values(*keys) == pin.fetch_values(*keys)

      paths = pin['recipe'] ? [pin.fetch('recipe')] : %w[info/recipe/rendered_recipe.yaml info/recipe/meta.yaml]
      recipe_path, rendered = read.call(*paths)
      if rendered.match?(/^\s*-\s+[^\n#]+#\s*\[[^\]]+\]\s*$/)
        raise IOError, 'unevaluated selector in conda recipe'
      end
      data = YAML.safe_load(rendered, permitted_classes: [Time, Date])
      recipe = recipe_path.end_with?('/rendered_recipe.yaml') ? data.fetch('recipe') : data
      raise IOError, 'unexpected rendered recipe format' unless recipe.is_a?(Hash) && recipe['package'].is_a?(Hash) && recipe['build'].is_a?(Hash)
      build = recipe.fetch('build')
      unless recipe.fetch('package').fetch_values('name', 'version').map(&:to_s) == index.fetch_values('name', 'version') &&
          (!build.key?('string') || build['string'].to_s == index.fetch('build')) &&
          Integer(build.fetch('number', 0)) == index.fetch('build_number')
        raise IOError, 'recipe does not describe the indexed build'
      end
      sources = Array.wrap(recipe['source'])
      evidence = index.slice(*keys).merge('channel' => 'conda-forge', 'recipe' => recipe_path)
      entries = sources.each_with_index.flat_map do |source, i|
        raise IOError, 'unexpected rendered source format' unless source.is_a?(Hash)
        Array.wrap(source['patches']).map.with_index do |path, j|
          raise IOError, 'unsupported conda patch path' unless path.is_a?(String) && path.match?(%r{\A[\w.+/-]+\z}) &&
            !path.start_with?('/') && !path.split('/').intersect?(%w[. ..])
          location, bytes = read.call("info/recipe/#{path}", "info/recipe/parent/#{path}")
          declaration = evidence.merge('source_index' => i, 'source' => source.except('patches'),
            'member' => location, 'position' => j + 1)
          name = sources.one? ? path : "source[#{i}]/#{path}"
          Document.new(bytes, strip: nil).entry(name: name, source_url: url, declaration: declaration.merge(verification))
        end
      end
      identity = { distribution: 'conda-forge', package_name: index['name'], version: index['version'],
        revision: "#{index['subdir']}/#{index['build']}" }
      PatchRelease.record!(identity, source_url: url, metadata: evidence.merge(verification, 'sources' => sources),
        component: component(sources), entries: entries)
    end

    def component(sources)
      source = sources.first if sources.one?
      url = source&.fetch('url', nil)
      if url.is_a?(String) && url.match?(%r{\Ahttps://rubygems\.org/downloads/[\w.+-]+\.gem\z}) && source['sha256'].present?
        bytes = @http.verified(url, source.fetch('sha256'))
        spec = Gem::Package.new(StringIO.new(bytes)).spec
        return { 'identity' => { 'ecosystem' => 'rubygems', 'name' => spec.name, 'version' => spec.version.to_s },
          'method' => 'registry_archive', 'evidence' => source.slice('url', 'sha256') }
      end
      { 'reason' => 'No upstream registry identity established from the rendered conda recipe.' }
    end

    def member(archive, path)
      contents, error, status = Open3.capture3('bsdtar', '-xOf', '-', '--', path, stdin_data: archive, binmode: true)
      raise IOError, "cannot read conda archive member #{path}: #{error}" unless status.success?
      contents
    end
  end
end
