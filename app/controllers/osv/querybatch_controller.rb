module Osv
  class QuerybatchController < ApplicationController
    MAX_BATCH_SIZE = 1000

    def create
      queries = json_params[:queries] || []

      if queries.length > MAX_BATCH_SIZE
        render json: { error: "Maximum batch size is #{MAX_BATCH_SIZE}" }, status: :bad_request
        return
      end

      @results = queries.map do |query_params|
        begin
          result = QueryService.new(query_params).find_vulnerabilities
          {
            vulns: result[:advisories].map do |advisory|
              VulnerabilityTransformer.new(advisory).transform(summary_only: true)
            end
          }
        rescue StandardError => e
          { vulns: [], error: e.message }
        end
      end
    end
  end
end
