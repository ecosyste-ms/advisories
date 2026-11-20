module PatchIndex
  class Http
    class NotFound < IOError; end

    def initialize(cache: ActiveSupport::Cache::FileStore.new(Rails.root.join('tmp', 'patch-http')), interval: 0.4)
      @cache = cache
      @interval = interval
      @connection = Faraday.new do |f|
        f.request :retry, max: 2, interval: 1, retry_statuses: [429, 503]
        f.response :follow_redirects, limit: 4
        f.options.timeout = 30
        f.options.open_timeout = 10
        f.headers['User-Agent'] = 'advisories.ecosyste.ms patch index'
      end
    end

    def get(url)
      raise ArgumentError, 'expected HTTPS URL' unless URI.parse(url).is_a?(URI::HTTPS)
      @cache.fetch(url, expires_in: 6.hours) do
        sleep @interval
        response = @connection.get(url)
        raise NotFound, "HTTP 404 for #{url}" if response.status == 404
        raise IOError, "HTTP #{response.status} for #{url}" unless response.success?
        response.body.b
      end
    end

    def verified(url, sha256)
      body = get(url)
      raise IOError, "SHA-256 mismatch for #{url}" unless Digest::SHA256.hexdigest(body) == sha256
      body
    end

    def json(url)
      data = JSON.parse(get(url))
      raise IOError, "API error for #{url}: #{data['error']}" if data.is_a?(Hash) && data.key?('error')
      data
    rescue JSON::ParserError
      raise IOError, "Invalid JSON from #{url}"
    end
  end
end
