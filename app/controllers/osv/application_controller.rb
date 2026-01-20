module Osv
  class ApplicationController < ::ApplicationController
    skip_forgery_protection

    rescue_from ActionController::ParameterMissing, with: :bad_request
    rescue_from ArgumentError, with: :bad_request

    def json_params
      return @json_params if defined?(@json_params)

      # Use Rails-parsed params if JSON content type, otherwise try reading body
      if request.content_type&.include?('application/json')
        @json_params = params.except(:controller, :action, :format).to_unsafe_h.deep_symbolize_keys
      else
        body = request.body.read
        @json_params = body.present? ? JSON.parse(body).deep_symbolize_keys : {}
      end
    rescue JSON::ParserError
      @json_params = {}
    end

    def bad_request(exception)
      render json: { error: exception.message }, status: :bad_request
    end
  end
end
