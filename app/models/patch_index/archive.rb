require 'rubygems/package'
require 'tempfile'
require 'zlib'

module PatchIndex
  class Archive
    LIMIT = 32.megabytes
    attr_reader :files

    def initialize(bytes)
      tar = if bytes.start_with?("\xFD7zXZ\x00".b)
        Tempfile.create('patch-index') do |f|
          f.binmode
          f.write(bytes)
          f.flush
          IO.popen(['xz', '-dc', f.path], 'rb') { |io| io.read(LIMIT + 1) }.tap do
            raise IOError, 'invalid xz patch archive' unless $?.success?
          end
        end
      else
        Zlib::GzipReader.wrap(StringIO.new(bytes)) { |io| io.read(LIMIT + 1) }
      end
      raise IOError, 'archive exceeds size limit' if tar.bytesize > LIMIT
      @files = {}
      Gem::Package::TarReader.new(StringIO.new(tar)).each do |entry|
        next unless entry.file?
        name = entry.full_name.delete_prefix('./')
        body = entry.read
        raise IOError, "conflicting archive members at #{name}" if @files.key?(name) && @files[name] != body
        @files[name] = body
      end
    end
  end
end
