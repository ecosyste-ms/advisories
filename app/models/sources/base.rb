require 'cvss_suite'

module Sources
  class Base
    attr_accessor :source

    def initialize(source)
      @source = source
    end

    def self.list
      @sources ||= begin
        Dir[Rails.root.join("app", "models", "sources", "*.rb")].sort.each do |file|
          require file unless file.match(/base\.rb$/)
        end
        Sources.constants
          .reject { |source| source == :Base }
          .map { |sym| "Sources::#{sym}".constantize }
          .sort_by(&:name)
      end
    end

    def self.format_name(source)
      return nil if source.nil?

      find(source).to_s.demodulize
    end

    def self.find(source)
      list.find { |p| p.formatted_name.downcase == source.downcase }
    end

    def self.formatted_name
      to_s.demodulize
    end

    def fetch_advisories
      nil
    end

    def map_advisories(advisories)
      advisories
    end

    def parse_cvss_score(vector)
      return nil unless vector

      cvss = CvssSuite.new(vector)
      return nil unless cvss.valid?

      cvss.overall_score
    end

    def severity_from_score(score)
      return nil unless score

      case score
      when 9.0..10.0 then 'CRITICAL'
      when 7.0...9.0 then 'HIGH'
      when 4.0...7.0 then 'MEDIUM'
      when 0.1...4.0 then 'LOW'
      else nil
      end
    end

    def list_advisories
      map_advisories(fetch_advisories)
    end

    def sync_advisories
      list_advisories.each do |advisory|
        a = source.advisories.find_or_initialize_by(uuid: advisory[:uuid])
        a.assign_attributes(advisory)
        if a.changed?
          a.save!
          a.cache_affected_versions!
          a.cache_related_advisories!
        end
      end
    end
  end
end