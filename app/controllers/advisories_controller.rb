class AdvisoriesController < ApplicationController
  def index
    scope = Advisory.all.includes(:source).order('published_at DESC')
    
    scope = scope.ecosystem(params[:ecosystem]) if params[:ecosystem].present?
    scope = scope.package_name(params[:package_name]) if params[:package_name].present?

    @pagy, @advisories = pagy(scope)
  end

  def show
    @advisory = Advisory.find_by!(uuid: params[:id])
  end
end