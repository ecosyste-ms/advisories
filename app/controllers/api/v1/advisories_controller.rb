class Api::V1::AdvisoriesController < Api::V1::ApplicationController
  def index
    expires_in 5.minutes, public: true, stale_while_revalidate: 1.hour

    scope = Advisory.all
    
    scope = scope.severity(params[:severity]) if params[:severity].present?
    scope = scope.ecosystem(params[:ecosystem]) if params[:ecosystem].present?
    scope = scope.package_name(params[:package_name]) if params[:package_name].present?
    scope = scope.repository_url(params[:repository_url]) if params[:repository_url].present?
    scope = scope.source_kind(params[:source]) if params[:source].present?

    scope = scope.created_after(params[:created_after]) if params[:created_after].present?
    scope = scope.updated_after(params[:updated_after]) if params[:updated_after].present?

    if params[:sort].present? || params[:order].present?
      sort = params[:sort] || 'published_at'
      order = params[:order] || 'desc'
      sort_options = sort.split(',').zip(order.split(',')).to_h
      scope = scope.order(sort_options)
    else
      scope = scope.order(published_at: :desc)
    end

    @pagy, @advisories = pagy(scope.includes(:source))
  end

  def show
    @advisory = Advisory.find_by_uuid!(params[:id])
    expires_in 1.hour, public: true, stale_while_revalidate: 1.hour
    fresh_when @advisory
  end

  def packages
    expires_in 5.minutes, public: true, stale_while_revalidate: 1.hour

    render json: Advisory.packages
  end

  def related_packages
    @advisory = Advisory.find_by_uuid!(params[:id])
    @related_packages = @advisory.related_packages.includes(:package)
    expires_in 1.hour, public: true, stale_while_revalidate: 1.hour
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

    expires_in 5.minutes, public: true, stale_while_revalidate: 1.hour

    advisories = Advisory.ecosystem(parsed_purl[:ecosystem])
                        .package_name(parsed_purl[:package_name])
                        .includes(:source)

    @purl = purl
    @advisories = deduplicate_by_cve(advisories)
  end

  def deduplicate_by_cve(advisories)
    grouped = advisories.group_by(&:cve)

    no_cve = grouped.delete(nil) || []

    deduped = grouped.map do |_cve, dupes|
      dupes.max_by { |a| [a.packages.size, a.id] }
    end

    no_cve + deduped
  end
end