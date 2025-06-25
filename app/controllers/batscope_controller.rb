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
  
  def owners
    @period = params[:period] || 'month'
    @sort = params[:sort] || 'total_downloads'
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
    
    # Get advisories in the time range
    recent_advisories = Advisory.created_after(time_range)
    recent_advisories = recent_advisories.ecosystem(@ecosystem) if @ecosystem.present?
    
    # Get older advisories
    older_advisories = Advisory.where('created_at <= ?', time_range)
    older_advisories = older_advisories.ecosystem(@ecosystem) if @ecosystem.present?
    
    # Extract package info from recent advisories
    recent_package_info = recent_advisories.flat_map(&:packages).map do |pkg|
      [pkg['ecosystem'], pkg['package_name']]
    end
    
    # Extract package info from older advisories
    older_package_info = older_advisories.flat_map(&:packages).map do |pkg|
      [pkg['ecosystem'], pkg['package_name']]
    end
    
    # Load all packages for recent advisories
    recent_packages = []
    if recent_package_info.any?
      conditions = recent_package_info.uniq.map do |ecosystem, name|
        "(ecosystem = #{Package.connection.quote(ecosystem)} AND name = #{Package.connection.quote(name)})"
      end.join(' OR ')
      recent_packages = Package.where(conditions).where.not(owner: [nil, ''])
    end
    
    # Load all packages for older advisories to get their owners
    older_owners = Set.new
    if older_package_info.any?
      conditions = older_package_info.uniq.map do |ecosystem, name|
        "(ecosystem = #{Package.connection.quote(ecosystem)} AND name = #{Package.connection.quote(name)})"
      end.join(' OR ')
      older_owners = Package.where(conditions).where.not(owner: [nil, '']).pluck(:owner).to_set
    end
    
    # Group recent packages by owner
    owners_data = recent_packages.group_by(&:owner).map do |owner, packages|
      # Sort packages by downloads to get the most significant one first
      sorted_packages = packages.sort_by { |p| -(p.downloads || 0) }
      first_package = sorted_packages.first
      
      [
        owner,
        packages.count,
        packages.sum { |p| p.downloads || 0 },
        packages.sum { |p| p.dependent_packages_count || 0 },
        packages.sum { |p| p.dependent_repos_count || 0 },
        packages.any?(&:critical),
        first_package
      ]
    end
    
    # Filter to owners who had no advisories before this time range
    @owners = owners_data.reject { |owner, _, _, _, _, _, _| older_owners.include?(owner) }
    
    # Filter to owners with only one package affected
    @owners = @owners.select { |_, package_count, _, _, _, _, _| package_count == 1 }
    
    # Apply critical filter if needed
    @owners = @owners.select { |_, _, _, _, _, has_critical, _| has_critical } if @critical_only
    
    # Sort the results
    @owners = case @sort
              when 'package_count'
                @owners.sort_by { |_, count, _, _, _, _, _| -count }
              when 'total_downloads'
                @owners.sort_by { |_, _, downloads, _, _, _, _| -(downloads || 0) }
              when 'total_dependent_packages'
                @owners.sort_by { |_, _, _, dep_pkgs, _, _, _| -(dep_pkgs || 0) }
              when 'total_dependent_repos'
                @owners.sort_by { |_, _, _, _, dep_repos, _, _| -(dep_repos || 0) }
              else
                @owners.sort_by { |_, _, downloads, _, _, _, _| -(downloads || 0) }
              end
    
    @owners = @owners.first(50)
  end
end