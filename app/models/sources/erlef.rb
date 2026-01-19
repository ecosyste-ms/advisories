require 'cvss_suite'

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

      cvss = CvssSuite.new(vector)
      return nil unless cvss.valid?

      cvss.overall_score
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
