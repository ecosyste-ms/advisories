require 'purl'

class PurlParser
  ECOSYSTEM_MAPPING = {
    'npm' => 'npm',
    'pypi' => 'pypi', 
    'gem' => 'rubygems',
    'maven' => 'maven',
    'nuget' => 'nuget',
    'golang' => 'go',
    'go' => 'go',
    'cargo' => 'cargo'
  }.freeze

  def self.parse(purl_string)
    return nil if purl_string.blank?

    begin
      parsed = Purl.parse(purl_string)
      ecosystem = map_ecosystem(parsed.type)
      return nil if ecosystem.nil?

      {
        ecosystem: ecosystem,
        package_name: parsed.name,
        namespace: parsed.namespace,
        version: parsed.version,
        original_purl: purl_string
      }
    rescue => e
      Rails.logger.warn "Failed to parse PURL '#{purl_string}': #{e.message}"
      nil
    end
  end

  def self.map_ecosystem(purl_type)
    ECOSYSTEM_MAPPING[purl_type&.downcase]
  end
end