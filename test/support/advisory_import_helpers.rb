module AdvisoryImportHelpers
  def github_edge(id: 'GSA_test', ghsa: 'GHSA-test-aaaa')
    {
      'node' => {
        'advisory' => {
          'id' => id, 'summary' => 'GitHub summary', 'description' => 'Details',
          'permalink' => "https://github.com/advisories/#{ghsa}", 'origin' => 'UNSPECIFIED',
          'severity' => 'HIGH', 'publishedAt' => '2026-01-01T00:00:00Z',
          'updatedAt' => '2026-01-02T00:00:00Z', 'withdrawnAt' => nil,
          'classification' => 'GENERAL', 'cvssSeverities' => { 'cvssV3' => { 'score' => 7.5, 'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' } },
          'references' => [{ 'url' => 'https://github.com/example/sample' }],
          'identifiers' => [{ 'value' => ghsa }, { 'value' => 'CVE-TEST-1' }],
          'epss' => { 'percentage' => 0.42, 'percentile' => 0.8 }
        },
        'package' => { 'ecosystem' => 'PIP', 'name' => 'sample' },
        'vulnerableVersionRange' => '< 2.0.0', 'firstPatchedVersion' => { 'identifier' => '2.0.0' }
      }
    }
  end

  def github_response(edges, next_page: false)
    { status: 200, headers: { 'Content-Type' => 'application/json' }, body: {
      data: { securityVulnerabilities: { edges: edges, pageInfo: { hasNextPage: next_page, endCursor: 'next' } } }
    }.to_json }
  end

  def stub_github(edges)
    stub_request(:post, 'https://api.github.com/graphql').to_return(github_response(edges))
  end

  def stub_osv(records)
    stub_request(:get, "#{Sources::Osv::BASE_URL}/ecosystems.txt").to_return(status: 200, body: 'PyPI')
    zip = Zip::OutputStream.write_buffer do |stream|
      records.each do |record|
        stream.put_next_entry("#{record.fetch('id')}.json")
        stream.write(record.to_json)
      end
    end
    stub_request(:get, "#{Sources::Osv::BASE_URL}/PyPI/all.zip").to_return(status: 200, body: zip.string)
  end

  def osv_record(id, **fields)
    {
      'id' => id, 'summary' => 'OSV summary', 'published' => '2026-01-01T00:00:00Z',
      'modified' => '2026-01-02T00:00:00Z', 'affected' => [{
        'package' => { 'ecosystem' => 'PyPI', 'name' => 'sample' },
        'ranges' => [{ 'type' => 'ECOSYSTEM', 'events' => [{ 'introduced' => '0' }, { 'fixed' => '1.0.0' }] }]
      }]
    }.merge(fields.stringify_keys)
  end
end
