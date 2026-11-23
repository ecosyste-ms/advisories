module PatchIndex
  class Http
    # Transport failures are worth retrying on the next run.
    class Error < IOError; end
    # Raised inside the download callback, where the adapter would wrap an IOError.
    class TooLarge < StandardError; end
    LIMIT = 256.megabytes

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

    def get(url, limit: LIMIT)
      require_https!(URI.parse(url))
      sleep @interval
      body = ''.b
      response = @connection.get(url) do |request|
        request.options.on_data = proc do |chunk, received, env|
          # Only the final response counts against the limit.
          next if env&.status && !env.success?
          raise TooLarge if received > limit
          # A redirect or retry starts a new response.
          body.clear if received == chunk.bytesize
          body << chunk
        end
      end
      raise Error, "HTTP #{response.status} for #{url}" unless response.success?
      body
    rescue TooLarge
      raise Error, "response exceeds #{limit} bytes for #{url}"
    rescue Faraday::Error => e
      raise Error, "#{e.class} for #{url}"
    end

    def verified(url, sha256, limit: LIMIT)
      body = get(url, limit: limit)
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
