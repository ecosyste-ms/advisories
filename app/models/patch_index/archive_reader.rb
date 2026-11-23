require 'ffi'
require 'tempfile'

module PatchIndex
  class ArchiveReader
    module Native
      extend FFI::Library
      ffi_lib ['archive', 'libarchive.so.13', '/usr/lib/libarchive.dylib']
      attach_function :archive_read_new, [], :pointer
      attach_function :archive_read_support_filter_all, [:pointer], :int
      attach_function :archive_read_support_format_tar, [:pointer], :int
      attach_function :archive_read_support_format_zip, [:pointer], :int
      attach_function :archive_read_open_filename, [:pointer, :string, :size_t], :int
      attach_function :archive_read_next_header, [:pointer, :pointer], :int
      attach_function :archive_read_data, [:pointer, :pointer, :size_t], :ssize_t
      attach_function :archive_read_free, [:pointer], :int
      attach_function :archive_error_string, [:pointer], :string
      attach_function :archive_entry_pathname, [:pointer], :string
      attach_function :archive_entry_symlink, [:pointer], :string
      attach_function :archive_entry_hardlink, [:pointer], :string
      attach_function :archive_entry_size, [:pointer], :int64
      attach_function :archive_entry_filetype, [:pointer], :uint
    end

    CHUNK = 65536
    EOF = 1
    REGULAR_FILE = 0o100000
    attr_reader :name, :size, :symlink, :hardlink

    def self.open(path)
      reader = new(path)
      yield reader
    ensure
      reader&.close
    end

    def self.files(bytes, limit:)
      Tempfile.create('patch-archive', binmode: true) do |file|
        file.write(bytes)
        file.flush
        files = {}
        total = 0
        open(file.path) do |archive|
          archive.each do |entry|
            next unless entry.regular?
            total += entry.size
            raise IOError, 'archive exceeds size limit' if total > limit
            files[entry.name] = entry.read(limit)
          end
        end
        files
      end
    end

    def initialize(path)
      @handle = Native.archive_read_new
      @buffer = FFI::MemoryPointer.new(:char, CHUNK)
      @header = FFI::MemoryPointer.new(:pointer)
      Native.archive_read_support_filter_all(@handle)
      check Native.archive_read_support_format_tar(@handle)
      check Native.archive_read_support_format_zip(@handle)
      check Native.archive_read_open_filename(@handle, path.to_s, CHUNK)
    rescue StandardError
      close
      raise
    end

    def each
      while (status = Native.archive_read_next_header(@handle, @header)) != EOF
        check status
        entry = @header.read_pointer
        @name = text(Native.archive_entry_pathname(entry).to_s).delete_prefix('./')
        @symlink = text(Native.archive_entry_symlink(entry))
        @hardlink = text(Native.archive_entry_hardlink(entry))
        @size = Native.archive_entry_size(entry)
        @regular = Native.archive_entry_filetype(entry) == REGULAR_FILE && !hardlink
        yield self
      end
    end

    # libarchive hands back binary strings, which never equal UTF-8 names read from a series file.
    def text(value)
      value&.dup&.force_encoding('UTF-8')&.scrub
    end

    def regular?
      @regular
    end

    def link?
      !!(symlink || hardlink)
    end

    def read(limit)
      raise IOError, "archive member exceeds size limit: #{name}" if size > limit
      bytes = ''.b
      while (length = Native.archive_read_data(@handle, @buffer, CHUNK)) != 0
        check length
        raise IOError, "archive member exceeds size limit: #{name}" if bytes.bytesize + length > limit
        bytes << @buffer.read_string_length(length)
      end
      raise IOError, "truncated archive member: #{name}" unless bytes.bytesize == size
      bytes
    end

    def check(status)
      raise IOError, Native.archive_error_string(@handle).to_s if status.negative?
    end

    def close
      Native.archive_read_free(@handle)
    end
  end
end
