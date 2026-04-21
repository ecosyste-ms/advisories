module Sources
  class Cpansa < Base
    DATA_URL = 'https://raw.githubusercontent.com/briandfoy/cpan-security-advisory/master/cpan-security-advisory.json'.freeze
    REPO_URL = 'https://github.com/briandfoy/cpan-security-advisory'.freeze

    def fetch_advisories
      response = Faraday.get(DATA_URL)
      return [] unless response.success?

      json = JSON.parse(response.body)
      dists = json['dists'] || {}

      dists.flat_map do |dist_name, dist|
        (dist['advisories'] || []).map do |advisory|
          advisory.merge('distribution' => advisory['distribution'] || dist_name)
        end
      end
    end

    def map_advisories(advisories)
      advisories.group_by { |a| a['id'] }.map do |_id, entries|
        map_advisory(merge_entries(entries))
      end
    end

    def merge_entries(entries)
      return entries.first if entries.length == 1

      base = entries.first.dup
      base['affected_versions'] = entries.flat_map { |e| Array(e['affected_versions']) }.uniq
      base['fixed_versions'] = entries.flat_map { |e| Array(e['fixed_versions']) }.uniq
      base['references'] = entries.flat_map { |e| Array(e['references']) }.compact.uniq
      base['cves'] = entries.flat_map { |e| Array(e['cves']) }.compact.uniq
      base['reported'] ||= entries.map { |e| e['reported'] }.compact.first
      base['severity'] ||= entries.map { |e| e['severity'] }.compact.first
      base
    end

    def map_advisory(advisory)
      references = Array(advisory['references']).compact

      {
        uuid: advisory['id'],
        url: references.first || REPO_URL,
        title: derive_title(advisory),
        description: advisory['description']&.strip,
        origin: 'CPANSA',
        severity: normalize_severity(advisory['severity']),
        published_at: derive_published_at(advisory),
        withdrawn_at: nil,
        classification: nil,
        cvss_score: nil,
        cvss_vector: nil,
        references: references,
        source_kind: 'cpansa',
        identifiers: extract_identifiers(advisory),
        epss_percentage: nil,
        epss_percentile: nil,
        packages: extract_packages(advisory)
      }
    end

    def derive_published_at(advisory)
      return advisory['reported'] if advisory['reported'].present?

      year = year_from_cve(advisory['cves']) || year_from_id(advisory['id'])
      return nil unless year

      "#{year}-01-01"
    end

    def year_from_cve(cves)
      Array(cves).each do |cve|
        return $1 if cve =~ /\ACVE-(\d{4})-/
      end
      nil
    end

    def year_from_id(id)
      return nil unless id
      return $1 if id =~ /-((?:19|20)\d{2})-/
      nil
    end

    def derive_title(advisory)
      description = advisory['description'].to_s.strip
      return advisory['id'] if description.blank?

      description.split("\n").first.truncate(255)
    end

    def extract_identifiers(advisory)
      ids = [advisory['id']]
      ids += Array(advisory['cves'])
      ids.compact.uniq
    end

    def extract_packages(advisory)
      dist = advisory['distribution']
      return [] if dist.blank?

      affected = Array(advisory['affected_versions'])
      fixed = Array(advisory['fixed_versions'])

      versions = if affected.any?
        affected.each_with_index.map do |range, i|
          {
            vulnerable_version_range: normalize_range(range),
            first_patched_version: extract_patched_version(fixed[i] || fixed.first)
          }
        end
      elsif fixed.any?
        fixed.map do |range|
          {
            vulnerable_version_range: invert_fixed_range(range),
            first_patched_version: extract_patched_version(range)
          }
        end
      else
        []
      end

      return [] if versions.empty?

      [{
        ecosystem: 'cpan',
        package_name: dist,
        versions: versions
      }]
    end

    def normalize_range(range)
      return nil if range.blank?

      range.split(',').map { |part| normalize_constraint(part) }.compact.join(', ')
    end

    def normalize_constraint(constraint)
      constraint = constraint.strip
      return nil if constraint.blank?

      if (match = constraint.match(/\A(<=|>=|==|!=|<|>|=)\s*(.+)\z/))
        op = match[1] == '==' ? '=' : match[1]
        "#{op} #{match[2].strip}"
      else
        "= #{constraint}"
      end
    end

    def extract_patched_version(fixed)
      return nil if fixed.blank?

      fixed.strip.sub(/\A>=?\s*/, '')
    end

    def invert_fixed_range(fixed)
      version = extract_patched_version(fixed)
      return nil if version.blank?

      "< #{version}"
    end

    def normalize_severity(severity)
      return nil if severity.blank?

      case severity.downcase
      when 'critical'
        'CRITICAL'
      when 'high'
        'HIGH'
      when 'moderate', 'medium'
        'MODERATE'
      when 'low', 'minor'
        'LOW'
      end
    end
  end
end
