module PatchIndex
  module Repository
    PATTERN = %r{
      \A(?:https?|git)://(?:www\.)?(github\.com|gitlab\.com|codeberg\.org|bitbucket\.org)
      /([\w.-]+)/([\w.-]+?)(?:\.git)?
      (?:/(?:tree|blob|archive|releases|-)/.*|/)?\z
    }xi

    def self.normalize(url)
      match = PATTERN.match(url.to_s.strip)
      return unless match && [match[2], match[3]].none? { |part| %w[. ..].include?(part) }
      "https://#{match[1]}/#{match[2]}/#{match[3]}".downcase
    end

    # Returns the field and URL of the first candidate that names a repository.
    def self.first(candidates)
      candidates.each do |field, url|
        repository = normalize(url)
        return [field, repository] if repository
      end
      nil
    end

    def self.debian(homepage, files)
      fields = { 'debian/upstream/metadata' => %w[Repository Repository-Browse], 'debian/copyright' => %w[Source] }
      candidates = fields.flat_map do |file, keys|
        text = files.fetch(file, '')
        text = text.split(/\r?\n\s*\r?\n/, 2).first.to_s if file == 'debian/copyright'
        keys.flat_map { |key| text.scan(/^#{key}:[ \t]*(\S+)[ \t]*\r?$/i).flatten.map { |url| ["#{file}:#{key}", url] } }
      end
      first(candidates + [['Sources:Homepage', homepage]])
    end

    def self.homebrew(formula)
      first([['urls.stable.url', formula.dig('urls', 'stable', 'url')], ['urls.head.url', formula.dig('urls', 'head', 'url')],
        ['homepage', formula['homepage']]])
    end
  end
end
