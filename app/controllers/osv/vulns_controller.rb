module Osv
  class VulnsController < ApplicationController
    def show
      expires_in 1.hour, public: true, stale_while_revalidate: 1.hour

      @advisory = QueryService.find_by_id(params[:id])

      if @advisory.nil?
        render json: {}, status: :not_found
      end
    end
  end
end
