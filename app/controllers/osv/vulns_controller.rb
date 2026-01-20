module Osv
  class VulnsController < ApplicationController
    def show
      @advisory = QueryService.find_by_id(params[:id])

      if @advisory.nil?
        render json: {}, status: :not_found
      end
    end
  end
end
