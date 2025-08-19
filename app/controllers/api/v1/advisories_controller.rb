class Api::V1::AdvisoriesController < Api::V1::ApplicationController
  def index
    scope = Advisory.all
    
    scope = scope.severity(params[:severity]) if params[:severity].present?
    scope = scope.ecosystem(params[:ecosystem]) if params[:ecosystem].present?
    scope = scope.package_name(params[:package_name]) if params[:package_name].present?
    scope = scope.repository_url(params[:repository_url]) if params[:repository_url].present?

    scope = scope.created_after(params[:created_after]) if params[:created_after].present?
    scope = scope.updated_after(params[:updated_after]) if params[:updated_after].present?

    if params[:sort].present? || params[:order].present?
      sort = params[:sort] || 'published_at'
      order = params[:order] || 'desc'
      sort_options = sort.split(',').zip(order.split(',')).to_h
      scope = scope.order(sort_options)
    end

    @pagy, @advisories = pagy(scope.includes(:source))
  end

  def show
    @advisory = Advisory.find_by_uuid!(params[:id])
  end

  def packages
    render json: Advisory.packages
  end

  def lookup
    purl = params[:purl]
    
    if purl.blank?
      render json: { error: 'PURL parameter is required' }, status: :bad_request
      return
    end

    parsed_purl = PurlParser.parse(purl)
    
    if parsed_purl.nil?
      render json: { error: 'Invalid PURL format' }, status: :bad_request
      return
    end

    advisories = Advisory.ecosystem(parsed_purl[:ecosystem])
                        .package_name(parsed_purl[:package_name])
                        .includes(:source)

    @purl = purl
    @advisories = advisories
  end
end