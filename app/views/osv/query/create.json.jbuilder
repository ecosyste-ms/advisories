json.vulns @advisories do |advisory|
  transformer = Osv::VulnerabilityTransformer.new(advisory)
  json.merge! transformer.transform
end

json.next_page_token @next_page_token if @next_page_token.present?
