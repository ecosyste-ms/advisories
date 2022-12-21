class Api::V1::AdvisoriesController < Api::V1::ApplicationController
  def index
    scope = Advisory.all.order('published_at DESC')
    
    scope = scope.ecosystem(params[:ecosystem]) if params[:ecosystem].present?
    scope = scope.package_name(params[:package_name]) if params[:package_name].present?

    @pagy, @advisories = pagy(scope)
  end

  def show
    @advisory = Advisory.find_by_uuid!(params[:id])
  end
end