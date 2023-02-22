class AdvisoriesController < ApplicationController
  def index
    scope = Advisory.all

    @severities = scope.group(:severity).count.to_a.sort_by{|a| a[1]}.reverse
    scope = scope.severity(params[:severity]) if params[:severity].present?

    @ecosystems = scope.select(:packages).map{|a| a.packages.map{|p| p['ecosystem'] } }.flatten.inject(Hash.new(0)) { |h, e| h[e] += 1 ; h }.to_a.sort_by{|a| a[1]}.reverse
    scope = scope.ecosystem(params[:ecosystem]) if params[:ecosystem].present?
  
    @packages = scope.select(:packages).map{|a| a.packages.map{|p| p.except("versions") } }.flatten.inject(Hash.new(0)) { |h, e| h[e] += 1 ; h }.to_a.sort_by{|a| a[1]}.reverse 
    scope = scope.package_name(params[:package_name]) if params[:package_name].present?

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

  def recent_advisories_data
    @recent_advisories = Rails.cache.fetch("all_recent_advisories_data", expires_in: 1.hour) do
      Advisory.where('published_at > ?', 3.months.ago.beginning_of_day).group_by_day(:published_at).count
    end
    render json: @recent_advisories
  end

  def show
    @advisory = Advisory.find_by!(uuid: params[:id])
  end
end