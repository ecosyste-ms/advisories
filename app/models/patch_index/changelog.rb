module PatchIndex
  module Changelog
    # Bullets often name a patch by its packaging path, in full or as d/p/.
    PREFIX = %r{(?:(?:debian|d)/(?:patches|p)/)?}

    # Returns the bullets of the newest entry that name exactly one patch, keyed by that patch.
    def self.items(text, package, version, patches)
      lines = text.lines
      return {} unless lines.shift.to_s.start_with?("#{package} (#{version}) ")
      bullets = lines.take_while { |line| line.start_with?(' ', "\n") && !line.start_with?(' -- ') }.join.split(/^  \* /)
      bullets.each_with_object({}) do |bullet, matches|
        named = patches.select { |path| bullet.match?(/(?<![\w.\/-])#{PREFIX}#{Regexp.escape(path)}(?![\w\/-]|\.\w)/) }
        (matches[named.first] ||= []) << bullet.strip if named.one?
      end
    end
  end
end
