require 'open3'
require 'tempfile'

module PatchIndex
  module Comparison
    def self.lines(left, right)
      Tempfile.create('patch-comparison') do |file|
        file.binmode
        file.write(right)
        file.flush
        output, error, status = Open3.capture3({ 'LC_ALL' => 'C' }, 'diff', '-a', '-u', '-', file.path,
          stdin_data: left, binmode: true)
        raise IOError, "diff failed: #{error}" unless [0, 1].include?(status.exitstatus)

        # The first two lines identify stdin and the temporary file.
        output.lines.drop(2)
      end
    end
  end
end
