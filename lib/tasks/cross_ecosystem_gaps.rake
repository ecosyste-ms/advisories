ADVISORIES_API_BASE = "https://advisories.ecosyste.ms"
PACKAGES_API_BASE = "https://packages.ecosyste.ms"
OSV_API_BASE = "https://api.osv.dev"
REPOLOGY_API_BASE = "https://repology.org"
NVD_API_BASE = "https://services.nvd.nist.gov"

REPACKAGED_ECOSYSTEMS = %w[
  conda homebrew nixpkgs debian ubuntu alpine
  fedora arch gentoo freebsd spack vcpkg
].freeze

# OSV ecosystem names are case-sensitive and differ from ecosyste.ms names.
# OSV supports Debian, Ubuntu, Alpine, FreeBSD for distros but not conda,
# nixpkgs, or homebrew.
OSV_SUPPORTED_ECOSYSTEMS = %w[Debian Ubuntu Alpine FreeBSD].freeze

def advisories_client
  @advisories_client ||= Faraday.new(ADVISORIES_API_BASE) do |f|
    f.request :json
    f.request :retry
    f.response :json
    f.headers['User-Agent'] = 'advisories.ecosyste.ms/gap-finder'
  end
end

def packages_client
  @packages_client ||= EcosystemsFaradayClient.build(PACKAGES_API_BASE)
end

def osv_client
  @osv_client ||= Faraday.new(OSV_API_BASE) do |f|
    f.request :json
    f.request :retry
    f.response :json
    f.headers['User-Agent'] = 'advisories.ecosyste.ms/gap-finder'
  end
end

def repology_client
  @repology_client ||= Faraday.new(REPOLOGY_API_BASE) do |f|
    f.request :json
    f.request :retry, max: 2, retry_statuses: [429, 503]
    f.response :json
    f.headers['User-Agent'] = 'advisories.ecosyste.ms/gap-finder'
  end
end

def nvd_client
  @nvd_client ||= Faraday.new(NVD_API_BASE) do |f|
    f.request :json
    f.request :retry, max: 2, retry_statuses: [403, 503]
    f.response :json
    f.headers['User-Agent'] = 'advisories.ecosyste.ms/gap-finder'
    f.headers['apiKey'] = ENV['NVD_API_KEY'] if ENV['NVD_API_KEY']
  end
end

def advisories_get(path)
  response = advisories_client.get(path)
  response.success? ? response.body : nil
rescue Faraday::Error => e
  $stderr.puts "  Advisories API error: #{e.message}"
  nil
end

def packages_get(path)
  response = packages_client.get(path)
  response.success? ? response.body : nil
rescue Faraday::Error => e
  $stderr.puts "  Packages API error: #{e.message}"
  nil
end

def osv_get(path)
  response = osv_client.get(path)
  response.success? ? response.body : nil
rescue Faraday::Error => e
  $stderr.puts "  OSV API error: #{e.message}"
  nil
end

def repology_get(path)
  response = repology_client.get(path)
  response.success? ? response.body : nil
rescue Faraday::Error => e
  $stderr.puts "  Repology API error: #{e.message}"
  nil
end

def nvd_get(path)
  response = nvd_client.get(path)
  response.success? ? response.body : nil
rescue Faraday::Error => e
  $stderr.puts "  NVD API error: #{e.message}"
  nil
end

# Repology uses "python:requests" for pypi "requests", "ruby:rails" for rubygems "rails", etc.
# Some packages use bare names if they're not language-specific.
REPOLOGY_ECOSYSTEM_PREFIXES = {
  "pypi" => "python",
  "rubygems" => "ruby",
  "npm" => "node",
  "cargo" => "rust",
  "go" => "go",
  "packagist" => "php",
  "nuget" => nil,
  "maven" => nil,
  "hex" => "erlang"
}.freeze

def repology_project_name(ecosystem, package_name)
  prefix = REPOLOGY_ECOSYSTEM_PREFIXES[ecosystem&.downcase]
  # Repology lowercases and uses the bare package name after the prefix
  name = package_name.downcase
  prefix ? "#{prefix}:#{name}" : name
end

# Returns array of unique repo names from Repology that ship this project.
def repology_repos(project_name)
  data = repology_get("/api/v1/project/#{ERB::Util.url_encode(project_name)}")
  return [] if data.nil? || !data.is_a?(Array)
  data.map { |entry| entry["repo"] }.compact.uniq
end

# Returns array of unique repo "families" (debian, ubuntu, alpine, fedora, etc.)
# by stripping version suffixes like "alpine_3_18" -> "alpine"
def repology_families(project_name)
  repos = repology_repos(project_name)
  repos.map { |r| r.split("_").first.downcase }.uniq.sort
end

# Returns full Repology entries for a project, grouped by repo family.
def repology_project_detail(project_name)
  data = repology_get("/api/v1/project/#{ERB::Util.url_encode(project_name)}")
  return {} if data.nil? || !data.is_a?(Array)

  by_family = Hash.new { |h, k| h[k] = [] }
  data.each do |entry|
    family = entry["repo"].to_s.split("_").first.downcase
    by_family[family] << {
      repo: entry["repo"],
      version: entry["version"],
      status: entry["status"],
      vulnerable: entry["vulnerable"]
    }
  end
  by_family
end

# Extracts CPE vendor/product pairs and downstream distro products from NVD response.
def nvd_cpe_products(cve_id)
  data = nvd_get("/rest/json/cves/2.0?cveId=#{ERB::Util.url_encode(cve_id)}")
  return { upstream: [], downstream: [] } if data.nil?

  vulns = data.dig("vulnerabilities") || []
  return { upstream: [], downstream: [] } if vulns.empty?

  configs = vulns.first.dig("cve", "configurations") || []

  upstream = []
  downstream = []

  configs.each do |config|
    (config["nodes"] || []).each do |node|
      (node["cpeMatch"] || []).each do |match|
        next unless match["vulnerable"]

        cpe = match["criteria"].to_s
        parts = cpe.split(":")
        next if parts.length < 6

        part_type = parts[2] # a=application, o=OS
        vendor = parts[3]
        product = parts[4]

        entry = {
          vendor: vendor,
          product: product,
          cpe: cpe,
          version_start: match["versionStartIncluding"],
          version_end: match["versionEndExcluding"]
        }

        # OS-level entries (fedoraproject, debian, canonical) are downstream distros
        if part_type == "o" || %w[fedoraproject debian canonical].include?(vendor)
          downstream << entry
        else
          upstream << entry
        end
      end
    end
  end

  { upstream: upstream.uniq { |e| [e[:vendor], e[:product]] },
    downstream: downstream.uniq { |e| [e[:vendor], e[:product]] } }
end

def osv_vulns_ecosystems(cve_id)
  vuln = osv_get("/v1/vulns/#{cve_id}")
  return [] if vuln.nil?

  (vuln["affected"] || []).map { |a| a.dig("package", "ecosystem") }.compact.uniq
end

def normalize_repo_url(url)
  return nil if url.nil? || url.empty?
  url.downcase.strip.sub(/\.git$/, "").sub(%r{/$}, "")
end

namespace :gaps do
  desc "Quick check: test a handful of well-known Python packages for cross-ecosystem advisory gaps"
  task quick: :environment do
    test_packages = %w[requests django flask numpy pillow urllib3 cryptography paramiko pyyaml jinja2]

    puts "Fetching known registries..."
    registries = packages_get("/api/v1/registries?per_page=200")
    if registries
      puts "#{registries.length} registries tracked by packages.ecosyste.ms"
      puts
    end

    test_packages.each do |pkg_name|
      puts "--- #{pkg_name} ---"

      advisories = advisories_get("/api/v1/advisories?ecosystem=pypi&package_name=#{pkg_name}&per_page=5")
      sleep 0.3

      if advisories.nil? || advisories.empty?
        puts "  No pypi advisories found"
        puts
        next
      end

      puts "  #{advisories.length} PyPI advisories (showing up to 3):"
      advisories.first(3).each do |adv|
        cve = (adv["identifiers"] || []).find { |id| id&.start_with?("CVE-") }
        ecosystems = (adv["packages"] || []).map { |p| p["ecosystem"] }
        puts "    #{cve || adv['uuid']} [#{adv['severity']}] ecosystems: #{ecosystems.join(', ')}"
      end

      pypi_pkg = packages_get("/api/v1/registries/pypi.org/packages/#{ERB::Util.url_encode(pkg_name)}")
      sleep 0.3

      if pypi_pkg.nil?
        puts "  Not found on packages.ecosyste.ms"
        puts
        next
      end

      repo_url = pypi_pkg["repository_url"]
      if repo_url.nil? || repo_url.empty?
        puts "  No repository URL"
        puts
        next
      end

      puts "  Repo: #{repo_url}"

      all_packages = packages_get("/api/v1/packages/lookup?repository_url=#{ERB::Util.url_encode(repo_url)}")
      sleep 0.3

      if all_packages.nil? || all_packages.empty?
        puts "  No packages found for this repo"
        puts
        next
      end

      puts "  #{all_packages.length} packages across ecosystems:"
      all_packages.each do |p|
        registry_name = p.dig("registry", "name") || "unknown"
        parsed = begin; Purl.parse(p["purl"]); rescue; nil; end if p["purl"]
        purl_type = parsed ? parsed.type : "?"
        puts "    #{p['ecosystem']}: #{p['name']} (#{registry_name}) [purl type: #{purl_type}]"
      end

      first_adv = advisories.first
      cve = (first_adv["identifiers"] || []).find { |id| id&.start_with?("CVE-") } || first_adv["uuid"]
      advisory_ecosystems = (first_adv["packages"] || []).map { |p| p["ecosystem"]&.downcase }.compact.uniq

      puts
      puts "  Checking coverage for #{cve}:"
      puts "  Advisory lists ecosystems: #{advisory_ecosystems.join(', ')}"

      non_pypi = all_packages.reject { |p| p["ecosystem"]&.downcase == "pypi" }
      if non_pypi.empty?
        puts "  No non-pypi packages to check"
        puts
        next
      end

      missing = []
      present = []

      non_pypi.each do |p|
        eco = p["ecosystem"]&.downcase
        if advisory_ecosystems.include?(eco)
          present << "#{p['ecosystem']}:#{p['name']}"
        else
          missing << "#{p['ecosystem']}:#{p['name']} (#{p.dig('registry', 'name')})"
        end
      end

      if missing.any?
        puts "  MISSING from advisory (#{missing.length}):"
        missing.each { |m| puts "    - #{m}" }
      end

      if present.any?
        puts "  Present in advisory (#{present.length}):"
        present.each { |p| puts "    + #{p}" }
      end

      puts
    end
  end

  desc "Full scan: check all CRITICAL/HIGH pypi advisories for cross-ecosystem gaps"
  task full: :environment do
    gaps = []
    covered = []
    no_repo = []
    no_repackages = []

    puts "Cross-Ecosystem Advisory Gap Finder"
    puts "=" * 50
    puts
    puts "Fetching CRITICAL and HIGH severity pypi advisories..."
    puts

    total_advisories = 0
    total_packages_checked = 0

    %w[CRITICAL HIGH].each do |severity|
      page = 1
      loop do
        advisories = advisories_get("/api/v1/advisories?ecosystem=pypi&page=#{page}&per_page=100&severity=#{severity}")
        break if advisories.nil? || advisories.empty?

        advisories.each do |advisory|
          total_advisories += 1
          uuid = advisory["uuid"]
          title = advisory["title"]
          identifiers = advisory["identifiers"] || []
          cve = identifiers.find { |id| id&.start_with?("CVE-") }
          advisory_ecosystems = (advisory["packages"] || []).map { |p| p["ecosystem"] }.uniq

          pypi_packages = (advisory["packages"] || []).select { |p| p["ecosystem"] == "pypi" }

          pypi_packages.each do |pypi_pkg|
            pkg_name = pypi_pkg["package_name"]
            total_packages_checked += 1

            print "  [#{severity}] #{cve || uuid}: #{pkg_name} ... "

            repo_url = normalize_repo_url(advisory["repository_url"])

            if repo_url.nil?
              pkg_info = packages_get("/api/v1/registries/pypi.org/packages/#{ERB::Util.url_encode(pkg_name)}")
              repo_url = normalize_repo_url(pkg_info["repository_url"]) if pkg_info
              sleep 0.3
            end

            if repo_url.nil?
              puts "no repo URL found"
              no_repo << { advisory: cve || uuid, package: pkg_name }
              next
            end

            all_packages = packages_get("/api/v1/packages/lookup?repository_url=#{ERB::Util.url_encode(repo_url)}")
            sleep 0.3

            if all_packages.nil? || all_packages.empty?
              puts "no packages found for repo"
              no_repackages << { advisory: cve || uuid, package: pkg_name, repo: repo_url }
              next
            end

            repackaged = all_packages.select { |p| REPACKAGED_ECOSYSTEMS.any? { |eco| p["ecosystem"]&.downcase&.include?(eco) } }

            if repackaged.empty?
              puts "not repackaged elsewhere"
              no_repackages << { advisory: cve || uuid, package: pkg_name, repo: repo_url }
              next
            end

            repackaged_ecosystems = repackaged.map { |p| [p["ecosystem"], p["name"], p.dig("registry", "name"), p["purl"]] }.uniq

            missing = []
            present = []

            repackaged_ecosystems.each do |ecosystem, name, registry, purl|
              found = advisory_ecosystems.any? { |ae| ae&.downcase == ecosystem&.downcase }

              if found
                present << { ecosystem: ecosystem, name: name, registry: registry, purl: purl }
              else
                missing << { ecosystem: ecosystem, name: name, registry: registry, purl: purl }
              end
            end

            if missing.any?
              puts "GAP FOUND - #{missing.length} ecosystem(s) missing"
              gaps << {
                advisory: cve || uuid,
                title: title,
                severity: severity,
                pypi_package: pkg_name,
                repo: repo_url,
                missing: missing,
                present: present
              }
            else
              puts "all #{repackaged_ecosystems.length} covered"
              covered << { advisory: cve || uuid, package: pkg_name, ecosystems: present }
            end
          end
        end

        break if advisories.length < 100
        page += 1
        break if page > 3
      end
    end

    puts
    puts "=" * 50
    puts "RESULTS"
    puts "=" * 50
    puts
    puts "Advisories checked: #{total_advisories}"
    puts "Packages checked: #{total_packages_checked}"
    puts "Gaps found: #{gaps.length}"
    puts "Fully covered: #{covered.length}"
    puts "No repo URL: #{no_repo.length}"
    puts "Not repackaged elsewhere: #{no_repackages.length}"
    puts

    if gaps.any?
      puts "-" * 50
      puts "GAPS: Advisories missing from repackaged ecosystems"
      puts "-" * 50
      puts

      gaps.each do |gap|
        puts "#{gap[:advisory]} (#{gap[:severity]})"
        puts "  PyPI package: #{gap[:pypi_package]}"
        puts "  Title: #{gap[:title]}"
        puts "  Repo: #{gap[:repo]}"
        puts "  Missing from:"
        gap[:missing].each do |m|
          puts "    - #{m[:ecosystem]} (#{m[:name]}) via #{m[:registry]}"
          puts "      PURL: #{m[:purl]}" if m[:purl]
        end
        if gap[:present].any?
          puts "  Present in:"
          gap[:present].each do |p|
            puts "    - #{p[:ecosystem]} (#{p[:name]})"
          end
        end
        puts
      end
    end

    output = {
      run_at: Time.now.iso8601,
      summary: {
        advisories_checked: total_advisories,
        packages_checked: total_packages_checked,
        gaps_found: gaps.length,
        fully_covered: covered.length,
        no_repo_url: no_repo.length,
        not_repackaged: no_repackages.length
      },
      gaps: gaps,
      covered: covered,
      no_repo: no_repo,
      no_repackages: no_repackages
    }

    output_path = "tmp/gap_report_#{Time.now.strftime('%Y%m%d_%H%M%S')}.json"
    FileUtils.mkdir_p("tmp")
    File.write(output_path, JSON.pretty_generate(output))
    puts "Full report written to #{output_path}"
  end

  desc "Cross-check: compare ecosyste.ms advisory coverage with OSV.dev for repackaged Python packages"
  task osv_cross_check: :environment do
    test_packages = %w[requests django flask numpy pillow urllib3 cryptography paramiko pyyaml jinja2]

    puts "Cross-checking ecosyste.ms vs OSV.dev coverage"
    puts "=" * 60
    puts
    puts "OSV supports these distro ecosystems: #{OSV_SUPPORTED_ECOSYSTEMS.join(', ')}"
    puts "OSV does NOT support: conda, nixpkgs, homebrew, spack"
    puts

    test_packages.each do |pkg_name|
      puts "--- #{pkg_name} ---"

      # Get advisories with CVEs from ecosyste.ms
      advisories = advisories_get("/api/v1/advisories?ecosystem=pypi&package_name=#{pkg_name}&per_page=5")
      sleep 0.3

      if advisories.nil? || advisories.empty?
        puts "  No pypi advisories found"
        puts
        next
      end

      # Find the repo URL via packages API
      pypi_pkg = packages_get("/api/v1/registries/pypi.org/packages/#{ERB::Util.url_encode(pkg_name)}")
      sleep 0.3

      if pypi_pkg.nil?
        puts "  Not found on packages.ecosyste.ms"
        puts
        next
      end

      repo_url = pypi_pkg["repository_url"]
      if repo_url.nil? || repo_url.empty?
        puts "  No repository URL"
        puts
        next
      end

      # Find all repackaged versions
      all_packages = packages_get("/api/v1/packages/lookup?repository_url=#{ERB::Util.url_encode(repo_url)}")
      sleep 0.3

      if all_packages.nil? || all_packages.empty?
        puts "  No packages found for this repo"
        puts
        next
      end

      non_pypi = all_packages.reject { |p| p["ecosystem"]&.downcase == "pypi" }
      non_pypi_ecosystems = non_pypi.map { |p| p["ecosystem"] }.uniq

      if non_pypi_ecosystems.empty?
        puts "  Not repackaged outside PyPI"
        puts
        next
      end

      puts "  Repackaged into: #{non_pypi_ecosystems.join(', ')}"

      # Check each advisory's CVE against OSV
      advisories.each do |adv|
        cve = (adv["identifiers"] || []).find { |id| id&.start_with?("CVE-") }
        next unless cve

        ecosyste_ms_ecosystems = (adv["packages"] || []).map { |p| p["ecosystem"] }.uniq
        osv_ecosystems = osv_vulns_ecosystems(cve)
        sleep 0.3

        puts
        puts "  #{cve} [#{adv['severity']}]"
        puts "    ecosyste.ms ecosystems: #{ecosyste_ms_ecosystems.join(', ')}"
        puts "    OSV.dev ecosystems:     #{osv_ecosystems.join(', ')}"

        # Check coverage for each repackaged ecosystem
        non_pypi_ecosystems.each do |eco|
          # Normalize for comparison: ecosyste.ms uses "debian", OSV uses "Debian:13"
          eco_base = eco.split(":").first.downcase

          in_ecosystems = ecosyste_ms_ecosystems.any? { |e| e.downcase.start_with?(eco_base) }
          in_osv = osv_ecosystems.any? { |e| e.downcase.start_with?(eco_base) }

          osv_supported = OSV_SUPPORTED_ECOSYSTEMS.any? { |s| s.downcase == eco_base }

          status = if in_ecosystems && in_osv
            "BOTH"
          elsif in_ecosystems && !in_osv
            "ecosyste.ms only"
          elsif !in_ecosystems && in_osv
            "OSV only"
          elsif osv_supported
            "NEITHER (OSV supports #{eco_base} but has no entry)"
          else
            "NEITHER (OSV doesn't support #{eco_base})"
          end

          marker = (in_ecosystems || in_osv) ? "+" : "-"
          puts "    #{marker} #{eco}: #{status}"
        end
      end

      puts
    end
  end

  desc "Compare coverage across ecosyste.ms, Repology, NVD and OSV for known CVEs"
  task source_coverage: :environment do
    test_packages = %w[requests django flask numpy pillow urllib3 cryptography paramiko pyyaml jinja2]

    puts "Source Coverage Comparison (ecosyste.ms vs Repology vs NVD vs OSV)"
    puts "=" * 70
    puts
    puts "NVD rate limit: 5 req/30s without key, 50 req/30s with NVD_API_KEY"
    puts "Repology rate limit: aggressive, expect some 429s"
    puts

    # NVD: 5 req/30s without key, 50 req/30s with key
    nvd_sleep = ENV['NVD_API_KEY'] ? 2 : 8
    # Repology: undocumented limits, they 429 aggressively
    repology_sleep = 3

    results = []

    test_packages.each do |pkg_name|
      puts "=== #{pkg_name} ==="

      # Get advisories from ecosyste.ms
      advisories = advisories_get("/api/v1/advisories?ecosystem=pypi&package_name=#{pkg_name}&per_page=5")
      sleep 1

      if advisories.nil? || advisories.empty?
        puts "  No pypi advisories found"
        puts
        next
      end

      # Get repo URL for ecosyste.ms package lookup
      pypi_pkg = packages_get("/api/v1/registries/pypi.org/packages/#{ERB::Util.url_encode(pkg_name)}")
      sleep 1
      repo_url = pypi_pkg&.dig("repository_url")

      # ecosyste.ms: packages sharing the same repo
      ecosystems_repos = []
      if repo_url.present?
        all_packages = packages_get("/api/v1/packages/lookup?repository_url=#{ERB::Util.url_encode(repo_url)}")
        sleep 1
        ecosystems_repos = (all_packages || []).map { |p| p["ecosystem"]&.downcase }.compact.uniq.sort
      end

      # Repology: repos packaging this project
      repology_name = repology_project_name("pypi", pkg_name)
      repology_detail = repology_project_detail(repology_name)
      sleep repology_sleep
      repology_fams = repology_detail.keys.sort

      puts "  ecosyste.ms registries (#{ecosystems_repos.length}): #{ecosystems_repos.join(', ')}"
      puts "  Repology families (#{repology_fams.length}): #{repology_fams.join(', ')}"
      puts

      # Only in Repology, not in ecosyste.ms
      repology_only = repology_fams - ecosystems_repos.map { |e| e.split(":").first }
      ecosystems_only = ecosystems_repos.map { |e| e.split(":").first } - repology_fams
      if repology_only.any?
        puts "  Repology has but ecosyste.ms does not: #{repology_only.join(', ')}"
      end
      if ecosystems_only.any?
        puts "  ecosyste.ms has but Repology does not: #{ecosystems_only.join(', ')}"
      end
      puts

      # Now check per-CVE across all four sources
      advisories.each do |adv|
        cve = (adv["identifiers"] || []).find { |id| id&.start_with?("CVE-") }
        next unless cve

        puts "  #{cve} [#{adv['severity']}]"
        advisory_ecosystems = (adv["packages"] || []).map { |p| p["ecosystem"]&.downcase }.compact.uniq

        # OSV lookup by CVE
        osv_ecosystems = osv_vulns_ecosystems(cve)
        sleep 1

        # NVD lookup by CVE
        nvd_data = nvd_cpe_products(cve)
        sleep nvd_sleep

        # Repology: which repos mark this project as vulnerable?
        vulnerable_repos = repology_detail.select { |_fam, entries|
          entries.any? { |e| e[:vulnerable] }
        }.keys.sort

        puts "    Advisory ecosystems:         #{advisory_ecosystems.join(', ')}"
        puts "    OSV ecosystems:              #{osv_ecosystems.join(', ')}"
        puts "    NVD upstream CPE:            #{nvd_data[:upstream].map { |e| "#{e[:vendor]}/#{e[:product]}" }.join(', ')}"
        puts "    NVD downstream CPE:          #{nvd_data[:downstream].map { |e| "#{e[:vendor]}/#{e[:product]}" }.join(', ')}"
        puts "    Repology vulnerable in:      #{vulnerable_repos.any? ? vulnerable_repos.join(', ') : '(none flagged)'}"

        # Build comparison table for repackaged ecosystems
        all_known_families = (ecosystems_repos.map { |e| e.split(":").first } + repology_fams).uniq.sort
        distro_families = all_known_families - %w[pypi npm rubygems cargo go maven nuget packagist hex]

        if distro_families.any?
          puts
          puts "    Per-family coverage:"
          distro_families.each do |fam|
            in_advisory = advisory_ecosystems.any? { |e| e.start_with?(fam) }
            in_osv = osv_ecosystems.any? { |e| e.downcase.start_with?(fam) }
            in_nvd = nvd_data[:downstream].any? { |e| e[:vendor].include?(fam) || e[:product].include?(fam) }
            in_repology = vulnerable_repos.include?(fam)
            in_ecosystems = ecosystems_repos.any? { |e| e.start_with?(fam) }

            sources = []
            sources << "advisory" if in_advisory
            sources << "osv" if in_osv
            sources << "nvd" if in_nvd
            sources << "repology" if in_repology

            marker = sources.any? ? "+" : "-"
            pkg_exists = in_ecosystems || repology_fams.include?(fam)
            note = pkg_exists ? "" : " (not packaged here)"

            puts "    #{marker} #{fam}: #{sources.any? ? sources.join(', ') : 'NO COVERAGE'}#{note}"
          end
        end

        results << {
          package: pkg_name,
          cve: cve,
          severity: adv["severity"],
          advisory_ecosystems: advisory_ecosystems,
          osv_ecosystems: osv_ecosystems,
          nvd_upstream: nvd_data[:upstream],
          nvd_downstream: nvd_data[:downstream],
          repology_vulnerable: vulnerable_repos,
          ecosystems_repos: ecosystems_repos,
          repology_families: repology_fams
        }

        puts
      end

      puts
    end

    # Summary
    puts "=" * 70
    puts "SUMMARY"
    puts "=" * 70
    puts
    puts "CVEs checked: #{results.length}"
    puts

    # Count how often each source has coverage for distro families
    source_hits = { advisory: 0, osv: 0, nvd: 0, repology: 0 }
    total_family_checks = 0

    results.each do |r|
      all_fams = (r[:ecosystems_repos].map { |e| e.split(":").first } + r[:repology_families]).uniq
      distro_fams = all_fams - %w[pypi npm rubygems cargo go maven nuget packagist hex]

      distro_fams.each do |fam|
        total_family_checks += 1
        source_hits[:advisory] += 1 if r[:advisory_ecosystems].any? { |e| e.start_with?(fam) }
        source_hits[:osv] += 1 if r[:osv_ecosystems].any? { |e| e.downcase.start_with?(fam) }
        source_hits[:nvd] += 1 if r[:nvd_downstream].any? { |e| e[:vendor].include?(fam) || e[:product].include?(fam) }
        source_hits[:repology] += 1 if r[:repology_vulnerable].include?(fam)
      end
    end

    puts "Distro-family coverage checks: #{total_family_checks}"
    source_hits.each do |source, hits|
      pct = total_family_checks > 0 ? (hits.to_f / total_family_checks * 100).round(1) : 0
      puts "  #{source}: #{hits}/#{total_family_checks} (#{pct}%)"
    end

    output = {
      run_at: Time.now.iso8601,
      summary: {
        cves_checked: results.length,
        total_family_checks: total_family_checks,
        source_hits: source_hits
      },
      results: results
    }

    output_path = "tmp/source_coverage_#{Time.now.strftime('%Y%m%d_%H%M%S')}.json"
    FileUtils.mkdir_p("tmp")
    File.write(output_path, JSON.pretty_generate(output))
    puts
    puts "Full report written to #{output_path}"
  end
end
