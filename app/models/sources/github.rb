module Sources
  class Github < Base

    def fetch_advisories
      advisories = []
      cursor = 'null'
      loop do
        res = fetch_advisories_page(cursor)
        advisories += res[:data][:securityVulnerabilities][:edges]
        break unless res[:data][:securityVulnerabilities][:pageInfo][:hasNextPage]
        cursor = "\"#{res[:data][:securityVulnerabilities][:pageInfo][:endCursor]}\""
      end
      advisories
    end

    def sync_advisories
      cursor = 'null'
      total_synced = 0
      packages_to_sync = Set.new

      loop do
        res = fetch_advisories_page(cursor)
        page_advisories = res[:data][:securityVulnerabilities][:edges]
        mapped_advisories = map_advisories(page_advisories)

        # Get existing advisories to compare
        uuids = mapped_advisories.map { |a| a[:uuid] }
        existing_advisories = source.advisories.where(uuid: uuids).index_by(&:uuid)

        # Prepare records for upsert
        records_to_upsert = []
        mapped_advisories.each do |advisory|
          existing = existing_advisories[advisory[:uuid]]

          # Check if advisory is new or changed
          if existing.nil? || advisory_changed?(existing, advisory)
            # Collect packages that need syncing
            advisory[:packages].each do |pkg|
              packages_to_sync.add([pkg[:ecosystem], pkg[:package_name]])
            end

            # Prepare record for upsert
            records_to_upsert << advisory.merge(
              source_id: source.id,
              created_at: existing&.created_at || Time.current,
              updated_at: Time.current
            )
          end
        end

        # Bulk insert/update - this skips callbacks but is much faster
        if records_to_upsert.any?
          # Split into new and existing
          new_records = records_to_upsert.select { |r| existing_advisories[r[:uuid]].nil? }
          existing_records = records_to_upsert.reject { |r| existing_advisories[r[:uuid]].nil? }

          # Bulk insert new advisories
          if new_records.any?
            Advisory.insert_all(new_records)
          end

          # Update existing advisories
          existing_records.each do |record|
            existing = existing_advisories[record[:uuid]]
            existing.update_columns(record.except(:source_id, :created_at, :uuid))
          end
        end

        total_synced += mapped_advisories.count
        Rails.logger.info "Synced #{mapped_advisories.count} advisories (#{total_synced} total, #{records_to_upsert.count} changed)"

        break unless res[:data][:securityVulnerabilities][:pageInfo][:hasNextPage]
        cursor = "\"#{res[:data][:securityVulnerabilities][:pageInfo][:endCursor]}\""
      end

      # Enqueue package sync jobs for all affected packages
      Rails.logger.info "Enqueueing sync jobs for #{packages_to_sync.size} unique packages"
      packages_to_sync.each do |ecosystem, package_name|
        PackageSyncWorker.perform_async(ecosystem, package_name)
      end

      total_synced
    end

    def advisory_changed?(existing, new_attrs)
      # Assign new attributes temporarily to leverage ActiveRecord's dirty tracking
      # This avoids manually listing every field and handles type conversions properly
      existing.assign_attributes(new_attrs.except(:source_id, :created_at, :uuid))

      # Check if any attributes changed, excluding updated_at (timestamp that always changes)
      # Note: repository_url and blast_radius are now set conditionally in their callbacks,
      # so they won't show as changed unless they actually differ
      changed = existing.changed? && (existing.changed - ['updated_at']).any?

      # Restore original state without saving
      existing.restore_attributes

      changed
    end

    def map_advisories(advisories)
      vulns = advisories.map do |advisory|
        {
          uuid: advisory[:node][:advisory][:id],
          url: advisory[:node][:advisory][:permalink],
          title: advisory[:node][:advisory][:summary],
          description: advisory[:node][:advisory][:description],
          origin: advisory[:node][:advisory][:origin],
          severity: advisory[:node][:advisory][:severity],
          published_at: advisory[:node][:advisory][:publishedAt],
          updated_at: advisory[:node][:advisory][:updatedAt],
          withdrawn_at: advisory[:node][:advisory][:withdrawnAt],
          classification: advisory[:node][:advisory][:classification],
          cvss_score: cvss_score_from_severities(advisory[:node][:advisory][:cvssSeverities]),
          cvss_vector: cvss_vector_from_severities(advisory[:node][:advisory][:cvssSeverities]),
          references: advisory[:node][:advisory][:references].map { |r| r[:url] },
          source_kind: 'github',
          identifiers: advisory[:node][:advisory][:identifiers].map { |i|i[:value] },
          epss_percentage: advisory[:node][:advisory][:epss][:percentage],
          epss_percentile: advisory[:node][:advisory][:epss][:percentile],

          # advisories need to be grouped by uuid and the following fields added together
          ecosystem: correct_ecosystem(advisory[:node][:package][:ecosystem]),
          vulnerable_version_range: advisory[:node][:vulnerableVersionRange],
          first_patched_version: advisory[:node].dig(:firstPatchedVersion, :identifier),
          package_name: advisory[:node][:package][:name],
        }
      end

      vulns.group_by { |v| v[:uuid] }.map do |uuid, vulns|
        advisory = vulns.first.except(:ecosystem, :vulnerable_version_range, :first_patched_version, :package_name)

        packages = vulns.group_by{ |v| [v[:ecosystem], v[:package_name]] }.map do |pkg, vulns|
          {
            ecosystem: pkg[0],
            package_name: pkg[1],
            versions: vulns.map do |v|
              {
                vulnerable_version_range: v[:vulnerable_version_range],
                first_patched_version: v[:first_patched_version]
              }
            end
          }
        end
        advisory[:packages] = packages
        advisory
      end
    end

    def cvss_score_from_severities(severities)
      v4_score = severities.dig(:cvssV4, :score)
      v3_score = severities.dig(:cvssV3, :score)
      v4_score.to_f > 0 ? v4_score : v3_score
    end

    def cvss_vector_from_severities(severities)
      v4_score = severities.dig(:cvssV4, :score)
      v4_score.to_f > 0 ? severities.dig(:cvssV4, :vectorString) : severities.dig(:cvssV3, :vectorString)
    end

    def correct_ecosystem(ecosystem)
      case ecosystem
      when 'COMPOSER'
        'packagist'
      when 'PIP'
        'pypi'
      when 'RUST'
        'cargo'
      when 'ERLANG'
        'hex'
      else
        ecosystem.downcase
      end
    end

    def fetch_advisories_page(cursor = 'null')
      # TODO cwes
      query = <<-GRAPHQL
        {
          securityVulnerabilities(first: 100, after: #{cursor}) {
            edges {
              node {
                advisory {
                  identifiers {
                    value
                  }
                  summary
                  id
                  databaseId
                  description
                  origin
                  permalink
                  references {
                    url
                  }
                  severity
                  publishedAt
                  updatedAt
                  withdrawnAt
                  cvssSeverities{
                    cvssV4 {
                      score
                      vectorString
                    }
                    cvssV3 {
                      score
                      vectorString
                    }
                  }
                  classification
                  epss{
                    percentage
                    percentile
                  }
                }
                firstPatchedVersion {
                  identifier
                }
                package {
                  name
                  ecosystem
                }
                vulnerableVersionRange
              }
            }
            pageInfo {
              hasNextPage
              endCursor
            }
          }
        }
      GRAPHQL
      res = api_client.post('/graphql', { query: query }.to_json).to_h
    end

    def api_client(token = nil, options = {})
      token ||= ENV['GITHUB_TOKEN']
      Octokit::Client.new({access_token: token, auto_paginate: true}.merge(options))
    end
  end
end