require 'ffi'

module PatchIndex
  class ArchiveReader
    module Native
      extend FFI::Library
      ffi_lib ['archive', 'libarchive.so.13', '/usr/lib/libarchive.dylib']
      callback :read_block, [:pointer, :pointer, :pointer], :ssize_t
      attach_function :archive_read_new, [], :pointer
      attach_function :archive_read_support_filter_all, [:pointer], :int
      attach_function :archive_read_support_format_tar, [:pointer], :int
      attach_function :archive_read_open, [:pointer, :pointer, :pointer, :read_block, :pointer], :int
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
    attr_reader :name, :size, :symlink, :hardlink

    def self.open(path: nil, remote: nil)
      reader = new
      begin
        reader.open_source(path, remote)
        yield reader
      ensure
        reader.close
      end
    end

    def initialize
      @handle = Native.archive_read_new
      @buffer = FFI::MemoryPointer.new(:char, CHUNK)
      @header = FFI::MemoryPointer.new(:pointer)
    end

    def open_source(path, remote)
      Native.archive_read_support_filter_all(@handle)
      check Native.archive_read_support_format_tar(@handle)
      if remote
        # Exceptions cannot unwind through C callbacks.
        @read = lambda do |_, _, out|
          bytes = remote.read_chunk(CHUNK)
          @input.put_bytes(0, bytes)
          out.write_pointer(@input)
          bytes.bytesize
        rescue StandardError => e
          @error = e
          -1
        end
        @input = FFI::MemoryPointer.new(:char, CHUNK)
        check Native.archive_read_open(@handle, nil, nil, @read, nil)
      else
        check Native.archive_read_open_filename(@handle, path.to_s, CHUNK)
      end
    end

    def each
      while (status = Native.archive_read_next_header(@handle, @header)) != 1
        check status
        entry = @header.read_pointer
        @name = Native.archive_entry_pathname(entry).delete_prefix('./')
        @symlink = Native.archive_entry_symlink(entry)
        @hardlink = Native.archive_entry_hardlink(entry)
        @size = Native.archive_entry_size(entry)
        @regular = Native.archive_entry_filetype(entry) == 0o100000 && !hardlink
        yield self
      end
    end

    def regular?
      @regular
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
      raise @error if @error
      raise IOError, Native.archive_error_string(@handle).to_s if status.negative?
    end

    def close
      Native.archive_read_free(@handle)
    end
  end
end
