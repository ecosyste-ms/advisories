class AdvisoriesController < ApplicationController
  def index
    # Redirect to new ecosystem and package routes
    package_name = params[:package_name] || params[:name]

    if params[:ecosystem].present? && package_name.present?
      redirect_to ecosystem_package_path(params[:ecosystem], package_name), status: :moved_permanently
      return
    elsif params[:ecosystem].present?
      redirect_to ecosystem_path(params[:ecosystem]), status: :moved_permanently
      return
    elsif package_name.present?
      # Look up package by name only
      packages = Package.where(name: package_name).limit(2).to_a
      if packages.length == 1
        redirect_to ecosystem_package_path(packages.first.ecosystem, packages.first.name), status: :moved_permanently
        return
      end
    end

    scope = Advisory.not_withdrawn

    @sources = Source.joins(:advisories).group(:id).order(:name).count.to_a.map { |id, count| [Source.find(id), count] }
    scope = scope.source_kind(params[:source]) if params[:source].present?

    @severities = scope.group(:severity).count.reject { |k, _| k.nil? }.to_a.sort_by{|a| a[1]}.reverse
    scope = scope.severity(params[:severity]) if params[:severity].present?

    @classifications = scope.group(:classification).count.reject { |k, _| k.nil? }.to_a.sort_by{|a| a[1]}.reverse
    scope = scope.where(classification: params[:classification]) if params[:classification].present?

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