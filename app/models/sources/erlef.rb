module Sources
  class Erlef < Base
    BASE_URL = 'https://cna.erlef.org'.freeze

    def fetch_advisories
      index_url = "#{BASE_URL}/osv/all.json"
      response = Faraday.get(index_url)
      return [] unless response.success?

      index = JSON.parse(response.body)
      index.map do |entry|
        fetch_advisory(entry['id'])
      end.compact
    end

    def fetch_advisory(id)
      url = "#{BASE_URL}/osv/#{id}.json"
      response = Faraday.get(url)
      return nil unless response.success?

      JSON.parse(response.body, symbolize_names: true)
    end

    def map_advisories(advisories)
      advisories.map do |osv|
        map_osv_advisory(osv)
      end.compact
    end

    def map_osv_advisory(osv)
      packages = extract_packages(osv[:affected] || [])

      cvss_vector = osv.dig(:severity, 0, :score)
      cvss_score = parse_cvss_score(cvss_vector)

      {
        uuid: osv[:id],
        url: osv.dig(:references, 0, :url) || "#{BASE_URL}/osv/#{osv[:id]}.json",
        title: osv[:summary],
        description: osv[:details],
        origin: 'ERLEF',
        severity: severity_from_score(cvss_score),
        published_at: osv[:published],
        updated_at: osv[:modified],
        withdrawn_at: osv[:withdrawn],
        classification: nil,
        cvss_score: cvss_score,
        cvss_vector: cvss_vector,
        references: extract_references(osv[:references] || []),
        source_kind: 'erlef',
        identifiers: extract_identifiers(osv),
        epss_percentage: nil,
        epss_percentile: nil,
        packages: packages
      }
    end

    def extract_packages(affected)
      affected.filter_map do |entry|
        next unless entry[:package]

        ecosystem = correct_ecosystem(entry.dig(:package, :ecosystem))
        package_name = entry.dig(:package, :name)
        next unless ecosystem && package_name

        versions = extract_version_ranges(entry[:ranges] || [])
        next if versions.empty?

        {
          ecosystem: ecosystem,
          package_name: package_name,
          versions: versions
        }
      end
    end

    def extract_version_ranges(ranges)
      ranges.filter_map do |range|
        next unless range[:type] == 'SEMVER'

        events = range[:events] || []
        introduced = events.find { |e| e[:introduced] }&.dig(:introduced)
        fixed = events.find { |e| e[:fixed] }&.dig(:fixed)

        vulnerable_range = build_version_range(introduced, fixed)
        next unless vulnerable_range

        {
          vulnerable_version_range: vulnerable_range,
          first_patched_version: fixed
        }
      end
    end

    def build_version_range(introduced, fixed)
      return nil unless introduced

      if introduced == '0' && fixed
        "< #{fixed}"
      elsif introduced != '0' && fixed
        ">= #{introduced}, < #{fixed}"
      elsif introduced != '0' && fixed.nil?
        ">= #{introduced}"
      elsif introduced == '0' && fixed.nil?
        nil
      end
    end

    def extract_references(references)
      references.map { |r| r[:url] }.compact
    end

    def extract_identifiers(osv)
      ids = [osv[:id]]
      ids += osv[:aliases] || []
      ids.compact.uniq
    end

    def correct_ecosystem(ecosystem)
      return nil unless ecosystem

      case ecosystem.downcase
      when 'hex'
        'hex'
      else
        ecosystem.downcase
      end
    end

    def parse_cvss_score(vector)
      return nil unless vector

      if vector.start_with?('CVSS:4.0/')
        parse_cvss4_score(vector)
      elsif vector.start_with?('CVSS:3.')
        parse_cvss3_score(vector)
      end
    end

    def parse_cvss4_score(vector)
      av = extract_metric(vector, 'AV')
      ac = extract_metric(vector, 'AC')
      at = extract_metric(vector, 'AT')
      pr = extract_metric(vector, 'PR')
      ui = extract_metric(vector, 'UI')
      vc = extract_metric(vector, 'VC')
      vi = extract_metric(vector, 'VI')
      va = extract_metric(vector, 'VA')

      base_score = 0.0
      base_score += impact_weight(vc) * 3.0
      base_score += impact_weight(vi) * 3.0
      base_score += impact_weight(va) * 3.0

      exploitability = 1.0
      exploitability *= av_weight(av)
      exploitability *= ac_weight(ac)
      exploitability *= at_weight(at)
      exploitability *= pr_weight(pr)
      exploitability *= ui_weight(ui)

      score = (base_score * exploitability).round(1)
      [[score, 10.0].min, 0.0].max
    end

    def parse_cvss3_score(vector)
      av = extract_metric(vector, 'AV')
      ac = extract_metric(vector, 'AC')
      pr = extract_metric(vector, 'PR')
      ui = extract_metric(vector, 'UI')
      c = extract_metric(vector, 'C')
      i = extract_metric(vector, 'I')
      a = extract_metric(vector, 'A')

      base_score = 0.0
      base_score += impact_weight(c) * 3.0
      base_score += impact_weight(i) * 3.0
      base_score += impact_weight(a) * 3.0

      exploitability = 1.0
      exploitability *= av_weight(av)
      exploitability *= ac_weight(ac)
      exploitability *= pr_weight(pr)
      exploitability *= ui_weight(ui)

      score = (base_score * exploitability).round(1)
      [[score, 10.0].min, 0.0].max
    end

    def extract_metric(vector, metric)
      match = vector.match(/#{metric}:([A-Z])/)
      match ? match[1] : nil
    end

    def impact_weight(value)
      case value
      when 'H' then 1.0
      when 'L' then 0.3
      when 'N' then 0.0
      else 0.0
      end
    end

    def av_weight(value)
      case value
      when 'N' then 1.0
      when 'A' then 0.85
      when 'L' then 0.6
      when 'P' then 0.4
      else 0.6
      end
    end

    def ac_weight(value)
      case value
      when 'L' then 1.0
      when 'H' then 0.5
      else 0.8
      end
    end

    def at_weight(value)
      case value
      when 'N' then 1.0
      when 'P' then 0.7
      else 0.8
      end
    end

    def pr_weight(value)
      case value
      when 'N' then 1.0
      when 'L' then 0.7
      when 'H' then 0.4
      else 0.7
      end
    end

    def ui_weight(value)
      case value
      when 'N' then 1.0
      when 'P' then 0.7
      when 'A' then 0.5
      else 0.7
      end
    end

    def severity_from_score(score)
      return nil unless score

      case score
      when 9.0..10.0 then 'CRITICAL'
      when 7.0...9.0 then 'HIGH'
      when 4.0...7.0 then 'MEDIUM'
      when 0.1...4.0 then 'LOW'
      else nil
      end
    end
  end
end
