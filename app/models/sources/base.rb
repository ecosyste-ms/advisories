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

    def list_advisories
      map_advisories(fetch_advisories)
    end
  end
end