module PatchIndex
  class Document
    ADVISORY = /\b(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}|(?:OSV|PYSEC|RUSTSEC)-\d{4}-\d+)\b/i
    attr_reader :headers, :files, :sha256

    def initialize(bytes, strip:)
      @bytes = bytes.b
      @sha256 = Digest::SHA256.hexdigest(bytes)
      text = bytes.dup.force_encoding('UTF-8')
      text.scrub!
      text.tr!("\0", "\uFFFD")
      lines = text.lines(chomp: true)
      preamble = lines.take_while { |line| !line.start_with?('---', 'diff ', 'Index:') }
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
      if commit
        @headers['commit'] = commit
        subject = preamble.find { |line| line.start_with?('    ') } if preamble.first.start_with?('commit ')
        @headers['Subject'] ||= subject.strip if subject
      end
      @files = []
      supported = strip.is_a?(Integer) && strip >= 0
      sections = lines.count { |line| line.start_with?('diff --git ') }
      pairs = 0
      lines.each_cons(2) do |old, new_line|
        next unless old.start_with?('--- ') && new_line.start_with?('+++ ')
        pairs += 1
        [old, new_line].each do |line|
          path = line[4..].split("\t", 2).first
          next if path == '/dev/null'
          if supported && path.match?(%r{\A[\w.+@/-]+\z}) && !path.start_with?('/') && (path.split('/') & %w[. ..]).empty?
            relative = path.split('/').drop(strip).join('/')
            relative.empty? ? supported = false : @files << relative
          else
            supported = false
          end
        end
      end
      @files.uniq!
      @complete = supported && files.any? && pairs.positive? && (sections.zero? || sections == pairs)
    end

    def self.identifier(value)
      value.match?(/\AGHSA-/i) ? "GHSA-#{value[5..].downcase}" : value.upcase
    end

    def self.references(sources)
      sources.each_with_object({}) do |(field, value), ids|
        value.to_json.scan(ADVISORY).uniq.each do |id|
          (ids[identifier(id)] ||= []) << field
        end
      end
    end

    def self.udd_references(udd)
      fields = udd.slice('description', 'origin', 'upstream_bug', 'debian_bug', 'forwarded_url', 'applied_upstream')
      references(fields.transform_keys { |key| "udd.#{key}" })
    end

    def entry(name:, source_url:, declaration:)
      sources = headers.transform_keys { |key| "header.#{key}" }
      sources.merge!(declaration.slice('bug', 'description', 'resolves')).merge!('name' => name)
      sources['changelog'] = declaration.dig('changelog', 'items') if declaration['changelog']
      references = self.class.references(sources)
      if declaration['udd']
        references.merge!(self.class.udd_references(declaration['udd'])) { |_, a, b| a | b }
      end
      changelog = Array(declaration.dig('changelog', 'items')).join(' ')
      kind = declaration['type'] || headers['Origin'].to_s[/\A(backport|upstream|vendor|other),/i, 1]
      kind ||= 'cherry-pick' if changelog.match?(/\bcherry[ -]pick(?:ed)?\b/i)
      declaration = declaration.merge('classification' => kind).compact
      declaration = declaration.merge('advisory_evidence' => references.transform_values(&:uniq))
      {
        name: name, source_url: source_url, declaration: declaration, headers: headers, sha256: sha256, body: @bytes,
        advisory_ids: references.keys,
        scope_evidence: { 'files' => files, 'reason' => ('unsupported diff paths or strip options' unless @complete) }.compact
      }
    end
  end
end
