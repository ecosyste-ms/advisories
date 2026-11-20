module PatchIndex
  module SourceRepository
    def self.github_purl(url)
      return unless url.to_s.match?(%r{\Ahttps?://(?:www\.)?github\.com/[\w.-]+/[\w.-]+(?:/tree/[^\s]+|/\.git|/)?\z}i)
      root = URLParser.try_all(url)
      return unless root && (match = root.match(%r{\Ahttps://github\.com/([\w.-]+)/([\w.-]+)\z}i))
      return if [match[1], match[2]].any? { |part| %w[. ..].include?(part) }
      Purl::PackageURL.new(type: 'github', namespace: match[1], name: match[2]).to_s
    end

    def self.debian_sources(row, packaging)
      fields = { 'Sources.Homepage' => [row['homepage']] }
      { 'debian/upstream/metadata' => %w[Repository Repository-Browse], 'debian/copyright' => %w[Source] }.each do |file, keys|
        text = packaging.fetch(file, '').dup.force_encoding('UTF-8').scrub
        text = text.split(/\r?\n\s*\r?\n/, 2).first.to_s if file == 'debian/copyright'
        keys.each { |key| fields["#{file}:#{key}"] = text.scan(/^#{key}:[ \t]*(https?:\/\/\S+)[ \t]*\r?$/i).flatten }
      end
      fields.flat_map do |field, urls|
        urls.filter_map do |url|
          purl = github_purl(url)
          { 'field' => field, 'url' => url, 'purl' => purl } if purl
        end
      end
    end

    def self.declaration(sources, archive_sha256: nil)
      purls = sources.pluck('purl').uniq
      return unless purls.one?
      { 'purl' => purls.first, 'sources' => sources, 'archive_sha256' => archive_sha256 }.compact
    end

    def self.homebrew_sources(metadata)
      url = metadata.dig('urls', 'stable', 'url')
      root = url.to_s[%r{\A(https://github\.com/[\w.-]+/[\w.-]+)/(?:archive/|releases/download/)\S+\z}i, 1]
      purl = github_purl(root || url)
      return [] unless purl
      [{ 'field' => 'urls.stable.url', 'url' => url, 'purl' => purl }]
    end
  end
end
