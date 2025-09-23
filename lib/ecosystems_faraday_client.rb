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

  def self.conditional_get(path, etag = nil)
    conn = build
    headers = {}
    headers['If-None-Match'] = etag if etag.present?

    response = conn.get(path, nil, headers)
    {
      status: response.status,
      body: response.body,
      etag: response.headers['etag'],
      success: response.success?,
      not_modified: response.status == 304
    }
  end
end