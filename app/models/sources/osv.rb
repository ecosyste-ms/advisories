require 'zip'
require 'cvss_suite'

module Sources
  class Osv < Base
    BASE_URL = 'https://storage.googleapis.com/osv-vulnerabilities'.freeze

    ECOSYSTEM_MAPPING = {
      'crates.io' => 'cargo',
      'PyPI' => 'pypi',
      'RubyGems' => 'rubygems',
      'Maven' => 'maven',
      'NuGet' => 'nuget',
      'Packagist' => 'packagist',
      'Hex' => 'hex',
      'Pub' => 'pub',
      'Go' => 'go',
      'npm' => 'npm',
      'GitHub Actions' => 'actions',
      'CRAN' => 'cran',
      'GHC' => 'ghc',
      'Hackage' => 'hackage',
      'Julia' => 'julia',
      'SwiftURL' => 'swift',
      'Debian' => 'debian',
      'Alpine' => 'alpine',
      'Ubuntu' => 'ubuntu',
      'AlmaLinux' => 'almalinux',
      'Rocky Linux' => 'rocky',
      'SUSE' => 'suse',
      'openSUSE' => 'opensuse',
      'Red Hat' => 'redhat',
      'Mageia' => 'mageia',
      'openEuler' => 'openeuler',
      'Wolfi' => 'wolfi',
      'Chainguard' => 'chainguard',
      'Bitnami' => 'bitnami',
      'Android' => 'android',
      'Linux' => 'linux',
      'OSS-Fuzz' => 'oss-fuzz',
      'GIT' => 'git',
      'MinimOS' => 'minimos'
    }.freeze

    EXCLUDED_ECOSYSTEMS = %w[
      Debian
      Ubuntu
      Alpine
      AlmaLinux
      Alpaquita
      Rocky\ Linux
      SUSE
      openSUSE
      Red\ Hat
      Mageia
      openEuler
      Wolfi
      Chainguard
      Bitnami
      Linux
      Android
      MinimOS
      BellSoft\ Hardened\ Containers
      Echo
    ].freeze

    def fetch_ecosystems
      response = Faraday.get("#{BASE_URL}/ecosystems.txt")
      return [] unless response.success?

      response.body.split("\n").map(&:strip).reject(&:empty?).select { |ecosystem| correct_ecosystem(ecosystem) }
    end

    def fetch_advisories
      ecosystems = fetch_ecosystems
      advisories = []

      ecosystems.each do |ecosystem|
        Rails.logger.info "Fetching OSV advisories for ecosystem: #{ecosystem}"
        ecosystem_advisories = fetch_ecosystem_advisories(ecosystem)
        advisories.concat(ecosystem_advisories)
      end

      advisories
    end

    def fetch_ecosystem_advisories(ecosystem)
      each_ecosystem_advisory(ecosystem).to_a
    end

    def each_ecosystem_advisory(ecosystem)
      return enum_for(__method__, ecosystem) unless block_given?

      Tempfile.create(['osv', '.zip']) do |tempfile|
        tempfile.binmode
        response = Faraday.get(ecosystem_zip_url(ecosystem)) do |request|
          request.options.on_data = proc { |chunk, _bytes| tempfile.write(chunk) }
        end
        return unless response.success?
        tempfile.flush

        Zip::File.open(tempfile.path) do |zip|
          zip.each do |entry|
            next unless entry.name.end_with?('.json')
            content = entry.get_input_stream.read
            begin
              osv = JSON.parse(content, symbolize_names: true)
            rescue JSON::ParserError => e
              Rails.logger.error "Failed to parse OSV advisory #{entry.name} for #{ecosystem}: #{e.message}"
              next
            end
            yield osv
          end
        end
      end
    rescue Faraday::Error, Zip::Error => e
      Rails.logger.error "Failed to fetch OSV advisories for #{ecosystem}: #{e.message}"
    end

    def ecosystem_zip_url(ecosystem)
      encoded = URI.encode_uri_component(ecosystem)
      "#{BASE_URL}/#{encoded}/all.zip"
    end

    def sync_advisories
      ecosystems = fetch_ecosystems
      total_synced = 0
      packages_to_sync = Set.new

      ecosystems.each do |ecosystem|
        Rails.logger.info "Syncing OSV advisories for ecosystem: #{ecosystem}"
        count = sync_ecosystem(ecosystem, packages_to_sync)
        total_synced += count
        Rails.logger.info "Synced #{count} advisories for #{ecosystem} (#{total_synced} total)"
      end

      unless Rails.env.development?
        Rails.logger.info "Enqueueing sync jobs for #{packages_to_sync.size} unique packages"
        packages_to_sync.each do |pkg_ecosystem, package_name|
          PackageSyncWorker.perform_async(pkg_ecosystem, package_name)
        end
      end

      total_synced
    end

    def sync_ecosystem(ecosystem, packages_to_sync)
      count = 0
      each_ecosystem_advisory(ecosystem).each_slice(100) do |advisories|
        entries = advisories.filter_map do |raw|
          attributes = map_osv_advisory(raw)
          [attributes, raw] if attributes
        end
        result = AdvisoryRecord.import(source, entries)
        packages_to_sync.merge(result[:packages])
        enqueue_related_sync(result[:advisory_ids])
        count += entries.size
      end
      count
    end

    def map_advisories(advisories)
      advisories.filter_map { |osv| map_osv_advisory(osv) }
    end

    def map_osv_advisory(osv)
      packages = extract_packages(osv[:affected] || [])

      cvss_vector = extract_cvss_vector(osv[:severity])
      cvss_score = parse_cvss_score(cvss_vector)

      {
        uuid: osv[:id],
        url: extract_url(osv),
        title: osv[:summary],
        description: osv[:details],
        origin: 'OSV',
        severity: severity_from_score(cvss_score),
        published_at: osv[:published],
        updated_at: osv[:modified],
        withdrawn_at: osv[:withdrawn],
        classification: extract_classification(osv[:id]),
        cvss_score: cvss_score,
        cvss_vector: cvss_vector,
        references: extract_references(osv[:references] || []),
        source_kind: 'osv',
        identifiers: extract_identifiers(osv),
        epss_percentage: nil,
        epss_percentile: nil,
        packages: packages
      }
    end

    def extract_url(osv)
      advisory_ref = (osv[:references] || []).find { |r| r[:type] == 'ADVISORY' }
      advisory_ref&.dig(:url) || "https://osv.dev/vulnerability/#{osv[:id]}"
    end

    def extract_cvss_vector(severity)
      return nil unless severity.is_a?(Array)

      cvss4 = severity.find { |s| s[:type] == 'CVSS_V4' }
      return cvss4[:score] if cvss4

      cvss31 = severity.find { |s| s[:type] == 'CVSS_V3' }
      cvss31&.dig(:score)
    end

    def extract_packages(affected)
      affected.filter_map do |entry|
        next unless entry[:package]

        ecosystem = correct_ecosystem(entry.dig(:package, :ecosystem))
        package_name = entry.dig(:package, :name)
        next unless ecosystem && package_name

        versions = extract_version_ranges(entry[:ranges] || [], ecosystem: ecosystem)
        versions += (entry[:versions] || []).map do |version|
          { vulnerable_version_range: "= #{version}", first_patched_version: nil }
        end
        next if versions.empty?

        {
          ecosystem: ecosystem,
          package_name: package_name,
          versions: versions.uniq
        }
      end
    end

    def extract_version_ranges(ranges, ecosystem: nil)
      ranges.flat_map do |range|
        next [] unless %w[SEMVER ECOSYSTEM].include?(range[:type])

        scheme = range[:type] == 'SEMVER' ? 'semver' : (PurlParser.reverse_map_ecosystem(ecosystem) || ecosystem&.downcase)
        events = (range[:events] || []).select { |event| event[:introduced] || event[:fixed] || event[:last_affected] }
        events = events.sort do |left, right|
          if left[:introduced] == '0'
            -1
          elsif right[:introduced] == '0'
            1
          else
            VersionNormalization::RANGE_MUTEX.synchronize { Vers.compare_with_scheme(left.values.first, right.values.first, scheme) }
          end
        end
        introduced = nil
        versions = []
        events.each do |event|
          if event[:introduced]
            introduced = event[:introduced]
          elsif introduced && (event[:fixed] || event[:last_affected])
            versions << {
              vulnerable_version_range: build_version_range(introduced, event[:fixed], last_affected: event[:last_affected]),
              first_patched_version: event[:fixed]
            }
            introduced = nil
          end
        end
        versions << { vulnerable_version_range: build_version_range(introduced, nil), first_patched_version: nil } if introduced
        versions
      end
    end

    def build_version_range(introduced, fixed, last_affected: nil)
      return nil unless introduced

      lower = ">= #{introduced}" unless introduced == '0' && (fixed || last_affected)
      upper = fixed ? "< #{fixed}" : "<= #{last_affected}" if fixed || last_affected
      [lower, upper].compact.join(', ')
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

      # Strip URL suffixes (e.g., "packagist:https://packages.drupal.org/8" -> "packagist")
      # Strip version suffixes (e.g., "Debian:12" -> "Debian", "Alpine:v3.17" -> "Alpine")
      base_ecosystem = ecosystem.split(':').first

      # Check if this is an excluded ecosystem
      return nil if EXCLUDED_ECOSYSTEMS.any? { |e| base_ecosystem.casecmp?(e) }

      ECOSYSTEM_MAPPING[base_ecosystem] || base_ecosystem.downcase.gsub(/\s+/, '-')
    end

    def extract_classification(id)
      return 'MALWARE' if id&.start_with?('MAL-')
      nil
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
      end
    end
  end
end
