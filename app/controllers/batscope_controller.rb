class BatscopeController < ApplicationController
  def index
    @period = params[:period] || 'month'
    @sort = params[:sort] || 'downloads'
    @critical_only = params[:critical] == 'true'
    @ecosystem = params[:ecosystem]
    
    time_range = case @period
                 when 'week'
                   1.week.ago
                 when 'month' 
                   1.month.ago
                 when 'year'
                   1.year.ago
                 else
                   1.month.ago
                 end
    
    advisories = Advisory.created_after(time_range)
    advisories = advisories.ecosystem(@ecosystem) if @ecosystem.present?
    
    older_advisories = Advisory.where('created_at <= ?', time_range)
    older_advisories = older_advisories.ecosystem(@ecosystem) if @ecosystem.present?
    
    recent_packages = advisories.flat_map(&:packages).map do |pkg|
      [pkg['ecosystem'], pkg['package_name']]
    end
    
    older_packages = older_advisories.flat_map(&:packages).map do |pkg|
      [pkg['ecosystem'], pkg['package_name']]
    end.to_set
    
    new_packages = recent_packages.reject { |pkg| older_packages.include?(pkg) }
                                  .uniq
    
    @packages = Package.none
    
    if new_packages.any?
      conditions = new_packages.map do |ecosystem, name|
        "(ecosystem = #{Package.connection.quote(ecosystem)} AND name = #{Package.connection.quote(name)})"
      end.join(' OR ')
      
      @packages = Package.where(conditions)
      @packages = @packages.where(critical: true) if @critical_only
      
      @packages = case @sort
                  when 'downloads'
                    @packages.order(Arel.sql('downloads DESC NULLS LAST'), name: :asc)
                  when 'dependent_packages_count'
                    @packages.order(Arel.sql('dependent_packages_count DESC NULLS LAST'), name: :asc)
                  when 'dependent_repos_count'
                    @packages.order(Arel.sql('dependent_repos_count DESC NULLS LAST'), name: :asc)
                  else
                    @packages.order(Arel.sql('downloads DESC NULLS LAST'), name: :asc)
                  end
    end
    
    @packages = @packages.limit(50)
  end
end