class EcosystemsController < ApplicationController
  def index
    expires_in 1.hour, public: true, stale_while_revalidate: 1.hour

    ecosystem_counts = Advisory.not_withdrawn.ecosystem_counts
    @ecosystems = ecosystem_counts.map do |ecosystem, count|
      registry = Registry.find_by_ecosystem(ecosystem)
      {
        name: ecosystem,
        count: count,
        registry: registry
      }
    end
  end

  def show
    expires_in 1.hour, public: true, stale_while_revalidate: 1.hour

    @ecosystem = params[:ecosystem_id]
    @registry = Registry.find_by_ecosystem(@ecosystem)
    scope = Advisory.not_withdrawn.ecosystem(@ecosystem)

    @severities = scope.group(:severity).count.to_a.sort_by{|a| a[1]}.reverse
    scope = scope.severity(params[:severity]) if params[:severity].present?

    @packages = scope.package_counts
    scope = scope.package_name(params[:package_name]) if params[:package_name].present?

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

  def packages
    expires_in 1.hour, public: true, stale_while_revalidate: 1.hour

    @ecosystem = params[:ecosystem_id]
    @registry = Registry.find_by_ecosystem(@ecosystem)
    scope = Package.ecosystem(@ecosystem)

    if params[:related].present?
      scope = scope.joins(:related_packages).distinct
    end

    scope = scope.order(advisories_count: :desc)
    @pagy, @packages = pagy(scope)
  end

  def package
    expires_in 1.hour, public: true, stale_while_revalidate: 1.hour

    @ecosystem = params[:ecosystem_id]
    @package_name = params[:package_name]
    @registry = Registry.find_by_ecosystem(@ecosystem)
    @package = Package.find_by(ecosystem: @ecosystem, name: @package_name)

    direct_scope = Advisory.not_withdrawn.ecosystem(@ecosystem).package_name(@package_name)

    if @package
      related_ids = @package.related_packages.pluck(:advisory_id)
      @direct_advisory_ids = direct_scope.pluck(:id).to_set
      scope = Advisory.not_withdrawn.where(id: @direct_advisory_ids + related_ids)
    else
      @direct_advisory_ids = Set.new
      scope = direct_scope
    end

    @severities = scope.group(:severity).count.to_a.sort_by{|a| a[1]}.reverse
    scope = scope.severity(params[:severity]) if params[:severity].present?

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

    if @package
      @related_packages_by_advisory = @package.related_packages.index_by(&:advisory_id)
    end
  end
end
