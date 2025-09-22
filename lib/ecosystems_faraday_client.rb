module EcosystemsFaradayClient
  def self.build(base_url = 'https://packages.ecosyste.ms')
    Faraday.new(base_url) do |f|
      f.request :json
      f.request :retry
      f.response :json
      f.headers['User-Agent'] = 'advisories.ecosyste.ms'
      f.headers['X-API-Key'] = ENV['ECOSYSTEMS_API_KEY'] if ENV['ECOSYSTEMS_API_KEY']
    end
  end
end