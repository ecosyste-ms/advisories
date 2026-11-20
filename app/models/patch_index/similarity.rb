require 'zlib'

module PatchIndex
  module Similarity
    def self.for_patch(patch)
      matches = index.fetch(patch.sha256, {})
      return [] if matches.empty?

      patches = Patch.declared.where(sha256: matches.keys).preload(patch_occurrences: :patch_release)
      patches.map { |other| [other, matches.fetch(other.sha256)] }.sort_by do |other, evidence|
        shared, total = evidence.fetch('jaccard', [0, 1])
        [evidence['same_hunks'] ? 0 : 1, evidence['same_edits'] ? 0 : 1, -shared.fdiv(total), other.sha256]
      end
    end

    def self.index
      @index ||= load_index(Rails.application.config.x.patch_catalog_directory.join('similarity-pairs.jsonl.gz'))
    end

    def self.load_index(path)
      return {} unless path.file?
      Zlib::GzipReader.open(path) do |stream|
        stream.each_line.each_with_object({}) do |line, pairs|
          row = JSON.parse(line)
          evidence = row.slice('same_hunks', 'same_edits', 'jaccard')
          next if evidence.empty?

          left, right = row.values_at('a', 'b')
          (pairs[left] ||= {})[right] = evidence
          (pairs[right] ||= {})[left] = evidence
        end
      end
    end
  end
end
