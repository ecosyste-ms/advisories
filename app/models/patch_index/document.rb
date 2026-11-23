module PatchIndex
  class Document
    ADVISORY = /\b(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}|(?:OSV|PYSEC|RUSTSEC)-\d{4}-\d+)\b/i
    attr_reader :bytes, :headers, :sha256

    def initialize(bytes)
      @bytes = bytes.b
      @sha256 = Digest::SHA256.hexdigest(@bytes)
      text = @bytes.dup.force_encoding('UTF-8').scrub.tr("\0", "�")
      preamble = text.each_line(chomp: true).take_while { |line| !line.start_with?('---', 'diff ', 'Index:') }
      @headers = {}
      field = nil
      preamble.each do |line|
        if (match = line.match(/\A([\w-]+):\s*(.*)/))
          field = match[1]
          @headers[field] = [@headers[field], match[2]].compact.join("\n")
        elsif field && line.start_with?(' ', "\t")
          @headers[field] += "\n#{line.strip}"
        else
          field = nil
        end
      end
      commit = preamble.first.to_s[/\A(?:From|commit) ([0-9a-f]{40})(?: |$)/, 1]
      return unless commit
      @headers['commit'] = commit
      subject = preamble.find { |line| line.start_with?('    ') } if preamble.first.start_with?('commit ')
      @headers['Subject'] ||= subject.strip if subject
    end

    def self.identifier(value)
      value.match?(/\AGHSA-/i) ? "GHSA-#{value[5..].downcase}" : value.upcase
    end

    # Maps each advisory identifier to the fields that mention it.
    def self.references(sources)
      sources.each_with_object({}) do |(field, value), ids|
        strings(value).flat_map { |text| text.scan(ADVISORY) }.map { |id| identifier(id) }.uniq.each { |id| (ids[id] ||= []) << field }
      end
    end

    def self.strings(value)
      case value
      when Hash then value.values.flat_map { |item| strings(item) }
      when Array then value.flat_map { |item| strings(item) }
      else [value.to_s]
      end
    end

    def entry(name:, position:, source_url:, declaration: {})
      sources = headers.transform_keys { |key| "header.#{key}" }
      sources.merge!(declaration.slice('resolves', 'changelog')).merge!('name' => name)
      evidence = self.class.references(sources)
      { name: name, position: position, source_url: source_url, sha256: sha256, bytes: bytes, headers: headers,
        advisory_ids: evidence.keys, declaration: declaration.merge('advisory_evidence' => evidence) }
    end
  end
end
