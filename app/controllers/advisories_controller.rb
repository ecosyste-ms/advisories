class AdvisoriesController < ApplicationController
  def index
    # Redirect to new ecosystem and package routes
    if params[:ecosystem].present? && params[:package_name].present?
      redirect_to ecosystem_package_path(params[:ecosystem], params[:package_name]), status: :moved_permanently
      return
    elsif params[:ecosystem].present?
      redirect_to ecosystem_path(params[:ecosystem]), status: :moved_permanently
      return
    end

    scope = Advisory.not_withdrawn

    @severities = scope.group(:severity).count.to_a.sort_by{|a| a[1]}.reverse
    scope = scope.severity(params[:severity]) if params[:severity].present?

    @ecosystems = scope.ecosystem_counts

    @packages = scope.package_counts

    @repository_urls = scope.group(:repository_url).count.to_a.sort_by{|a| a[1]}.reverse
    scope = scope.repository_url(params[:repository_url]) if params[:repository_url].present?

    scope = scope.created_after(params[:created_after]) if params[:created_after].present?
    scope = scope.updated_after(params[:updated_after]) if params[:updated_after].present?

    if params[:sort].present? || params[:order].present?
      sort = params[:sort] || 'created_at'
      order = params[:order] || 'desc'
      
      sort_columns = sort.split(',').map(&:strip)
      order_directions = order.split(',').map(&:strip)
      
      arel_orders = []
      sort_columns.zip(order_directions).each do |col, ord|
        if Advisory.column_names.include?(col)
          direction = ord&.downcase == 'asc' ? :asc : :desc
          arel_orders << Advisory.arel_table[col].send(direction)
        end
      end
      
      if arel_orders.any?
        scope = scope.order(arel_orders)
      else
        scope = scope.order(Advisory.arel_table[:published_at].desc)
      end
    else
      scope = scope.order(Advisory.arel_table[:published_at].desc)
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
    fresh_when @advisory
  end
end