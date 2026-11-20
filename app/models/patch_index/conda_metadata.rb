require 'net/http'
require 'tempfile'
require 'zip_kit'

module PatchIndex
  class CondaMetadata
    attr_reader :transferred, :etag, :size
    attr_reader :position
    alias tell position

    class ZipDirectory < ZipKit::FileReader
      # Un-commented ZIPs have a fixed footer. Avoid fetching 64 KB to search for it.
      def get_eocd_offset(io, size)
        if size >= 22
          io.seek(size - 22, IO::SEEK_SET)
          footer = io.read(22)
          return size - 22 if footer.start_with?("PK\x05\x06".b) && footer.end_with?("\0\0".b)
        end
        super
      end
    end

    def initialize(pin, limit)
      @uri = URI(pin.fetch('archive_url'))
      unless @uri.to_s.match?(%r{\Ahttps://conda\.anaconda\.org/conda-forge/[\w-]+/[\w.+!%~-]+\.(?:conda|tar\.bz2)\z})
        raise IOError, 'invalid conda-forge archive URL'
      end
      @size = Integer(pin.fetch('size'))
      @md5 = pin['md5']
      @limit = limit
      @position = @transferred = @start = 0
      @chunk = ''.b
    end

    def seek(offset, whence)
      @position = [0, @position, @size].fetch(whence) + offset
      raise IOError, 'invalid seek' unless @position.between?(0, @size)
      @position
    end

    def read(count)
      length = [count, size - @position].min
      result = ''.b
      while result.bytesize < length
        result << read_chunk(length - result.bytesize)
      end
      result
    end

    def read_chunk(count)
      return ''.b if @position == size
      fetch_range([count, 65536].max) unless (@start...(@start + @chunk.bytesize)).cover?(@position)
      bytes = @chunk.byteslice(@position - @start, count)
      @position += bytes.bytesize
      bytes
    end

    def fetch_range(count)
      length = [count, @size - @position, @limit - transferred].min
      raise IOError, 'metadata transfer budget reached' unless length.positive?
      interval = "#{@position}-#{@position + length - 1}"
      request = Net::HTTP::Get.new(@uri, 'Range' => "bytes=#{interval}", 'Accept-Encoding' => 'identity')
      request['If-Match'] = etag if etag
      bytes = ''.b
      Net::HTTP.start(@uri.host, @uri.port, use_ssl: true, open_timeout: 10, read_timeout: 30, max_retries: 0) do |http|
        http.request(request) do |response|
          unless response.code == '206' && response['content-range'] == "bytes #{interval}/#{@size}"
            raise IOError, 'server did not return the requested byte range'
          end
          tag = response['etag']
          raise IOError, 'missing or inconsistent archive validator' unless tag && !tag.start_with?('W/') && (!etag || etag == tag)
          raise IOError, 'archive ETag differs from catalog MD5' if @md5 && tag.match?(/\A"[a-f0-9]{32}"\z/) && tag != %("#{@md5}")
          @etag = tag
          response.read_body do |part|
            @transferred += part.bytesize
            raise IOError, 'oversized byte range' if bytes.bytesize + part.bytesize > length
            bytes << part.b
          end
        end
      end
      raise IOError, 'truncated byte range' unless bytes.bytesize == length
      @start, @chunk = @position, bytes
    end

    def with_recipe
      if @uri.path.end_with?('.conda')
        stem = File.basename(@uri.path, '.conda')
        Tempfile.create('conda-info', binmode: true) do |file|
          seek([size - [8192, @limit].min, 0].max, IO::SEEK_SET)
          fetch_range(8192)
          zip = ZipDirectory.new
          info = zip.read_zip_structure(io: self, read_local_headers: false).find { |entry| entry.filename == "info-#{stem}.tar.zst" }
          raise IOError, 'missing conda info archive' unless info
          raise IOError, 'info archive exceeds metadata budget' if info.uncompressed_size > @limit
          seek(info.local_file_header_offset, IO::SEEK_SET)
          local = zip.read_local_file_header(io: self)
          raise IOError, 'inconsistent info member' unless local.filename == info.filename
          info.compressed_data_offset = local.compressed_data_offset
          reader = info.extractor_from(self)
          crc = 0
          until reader.eof?
            part = reader.extract(16384)
            raise IOError, 'invalid info archive size' unless part && file.pos + part.bytesize <= info.uncompressed_size
            file.write(part)
            crc = Zlib.crc32(part, crc)
          end
          raise IOError, 'info archive checksum mismatch' unless file.pos == info.uncompressed_size && crc == info.crc32
          file.flush
          ArchiveReader.open(path: file.path) { |tar| yield member_reader(tar) }
        end
      else
        ArchiveReader.open(remote: self) { |tar| yield member_reader(tar) }
      end
    rescue ZipKit::FileReader::ReadError, ZipKit::FileReader::MissingEOCD, ZipKit::FileReader::UnsupportedFeature,
        Zlib::Error, Timeout::Error, SocketError, SystemCallError, EOFError, OpenSSL::SSL::SSLError => e
      raise IOError, e.message
    end

    def member_reader(tar)
      entries = tar.enum_for(:each)
      cache = {}
      remaining = 128.megabytes
      lambda do |*paths|
        first = paths.first
        hit = first if cache.key?(first)
        until hit
          begin
            entry = entries.next
          rescue StopIteration
            hit = paths.find { |path| cache.key?(path) }
            raise IOError, "missing recipe member: #{paths.join(', ')}" unless hit
            break
          end
          path = entry.name
          next unless entry.regular? && (path == 'info/index.json' || path.start_with?('info/recipe/'))
          cache[path] = entry.read(remaining)
          remaining -= entry.size
          hit = path if path == first || (first.end_with?('/rendered_recipe.yaml') && path == paths[1])
        end
        [hit, cache.fetch(hit)]
      end
    end
  end
end
