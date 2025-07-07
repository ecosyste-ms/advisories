module EcosystemsFaradayClient
  def self.build(base_url = 'https://packages.ecosyste.ms')
    Faraday.new(base_url) do |f|
      f.request :json
      f.request :retry
      f.response :json
      f.headers['User-Agent'] = 'advisories.ecosyste.ms'
    end
  end
end