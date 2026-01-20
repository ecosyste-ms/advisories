module Osv
  class QueryController < ApplicationController
    def create
      result = QueryService.new(json_params).find_vulnerabilities
      @advisories = result[:advisories]
      @next_page_token = result[:next_page_token]
    end
  end
end
