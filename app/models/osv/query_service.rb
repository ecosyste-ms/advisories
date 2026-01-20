module Osv
  class QueryService
    ECOSYSTEM_MAPPING = VulnerabilityTransformer::ECOSYSTEM_MAPPING.invert.freeze
    PAGE_SIZE = 100

    attr_reader :params

    def initialize(params)
      @params = params
    end

    def find_vulnerabilities
      scope = build_scope
      paginate(scope)
    end

    def build_scope
      scope = Advisory.all

      if params[:purl].present?
        return find_by_purl(params[:purl])
      end

      if params[:package].present?
        scope = find_by_package(params[:package], scope)
      end

      scope.order(updated_at: :desc)
    end

    def find_by_purl(purl_string)
      parsed = PurlParser.parse(purl_string)
      return Advisory.none unless parsed

      # Check if version is also in query params - that's an error
      if params.dig(:package, :version).present?
        raise ArgumentError, "version cannot be specified in both purl and package parameters"
      end

      Advisory.ecosystem(parsed[:ecosystem])
              .package_name(parsed[:package_name])
              .order(updated_at: :desc)
    end

    def find_by_package(package_params, scope)
      ecosystem = package_params[:ecosystem]
      name = package_params[:name]

      return scope if ecosystem.blank? && name.blank?

      if ecosystem.present?
        internal_ecosystem = normalize_ecosystem(ecosystem)
        scope = scope.ecosystem(internal_ecosystem)
      end

      scope = scope.package_name(name) if name.present?

      scope
    end

    def normalize_ecosystem(ecosystem)
      ECOSYSTEM_MAPPING[ecosystem] || ecosystem.downcase
    end

    def paginate(scope)
      page_token = params[:page_token]
      offset = decode_page_token(page_token)

      results = scope.offset(offset).limit(PAGE_SIZE + 1).to_a

      next_page_token = nil
      if results.size > PAGE_SIZE
        results.pop
        next_page_token = encode_page_token(offset + PAGE_SIZE)
      end

      {
        advisories: results,
        next_page_token: next_page_token
      }
    end

    def encode_page_token(offset)
      return nil if offset <= 0
      Base64.urlsafe_encode64(offset.to_s, padding: false)
    end

    def decode_page_token(token)
      return 0 if token.blank?
      Base64.urlsafe_decode64(token).to_i
    rescue ArgumentError
      0
    end

    def self.find_by_id(id)
      # Try finding by uuid first
      advisory = Advisory.find_by(uuid: id)
      return advisory if advisory

      # Try finding by CVE identifier
      if id.start_with?('CVE-')
        Advisory.where("? = ANY(identifiers)", id).first
      end
    end
  end
end
