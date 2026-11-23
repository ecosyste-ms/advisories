module PatchIndex
  class Http
    # Transport failures are worth retrying on the next run.
    class Error < IOError; end

    def initialize(interval: 0.4)
      @interval = interval
      @connection = Faraday.new do |f|
        f.request :retry, max: 2, interval: 1, retry_statuses: [429, 503]
        f.response :follow_redirects, limit: 4, callback: ->(_, redirect) { require_https!(redirect[:url]) }
        f.options.timeout = 30
        f.options.open_timeout = 10
        f.headers['User-Agent'] = 'advisories.ecosyste.ms patch index'
      end
    end

    def get(url)
      require_https!(URI.parse(url))
      sleep @interval
      response = @connection.get(url)
      raise Error, "HTTP #{response.status} for #{url}" unless response.success?
      response.body.b
    rescue Faraday::Error => e
      raise Error, "#{e.class} for #{url}"
    end

    def verified(url, sha256)
      body = get(url)
      raise Error, "SHA-256 mismatch for #{url}" unless Digest::SHA256.hexdigest(body) == sha256
      body
    end

    def json(url)
      JSON.parse(get(url))
    rescue JSON::ParserError
      raise Error, "invalid JSON from #{url}"
    end

    def require_https!(uri)
      raise Error, "refusing non-HTTPS URL #{uri}" unless uri.is_a?(URI::HTTPS)
    end
  end
end
