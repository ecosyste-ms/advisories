module PatchIndex
  class QuiltArchive
    PREFIX = 'debian/patches/'
    METADATA = %w[debian/upstream/metadata debian/copyright debian/control].freeze
    MEMBER_LIMIT = 32.megabytes
    TOTAL_LIMIT = 128.megabytes
    attr_reader :series_path, :changelog, :metadata

    def initialize(path, vendor:)
      @files = {}
      @links = {}
      @metadata = {}
      @changelog = ''
      total = 0
      ArchiveReader.open(path) do |archive|
        archive.each do |entry|
          name = entry.name
          if %w[debian debian/patches].include?(name) && entry.link?
            raise IOError, "unsupported linked packaging directory #{name}"
          end
          next unless name.start_with?(PREFIX) || METADATA.include?(name) || name == 'debian/changelog'
          if entry.link?
            target = entry.hardlink || Pathname(name).dirname.join(entry.symlink)
            @links[name] = Pathname(target).cleanpath.to_s
          elsif entry.regular?
            total += entry.size
            raise IOError, 'packaging members exceed size limit' if total > TOTAL_LIMIT
            bytes = entry.read(MEMBER_LIMIT)
            if name == 'debian/changelog'
              @changelog = text(bytes)
            elsif METADATA.include?(name)
              @metadata[name] = text(bytes)
            else
              @files[name] = bytes
            end
          end
        end
      end
      variant = "#{PREFIX}#{vendor}.series"
      @series_path = @files.key?(variant) || @links.key?(variant) ? variant : "#{PREFIX}series"
    end

    # Returns [name, quilt options, bytes] for each series entry, in order.
    def patches
      series = read(series_path)
      raise IOError, "unresolved series link #{series_path}" if @links.key?(series_path) && !series
      seen = Set.new
      text(series.to_s).each_line.filter_map do |line|
        words = line.split.take_while { |word| !word.start_with?('#') }
        next if words.empty?
        name = words.shift.delete_prefix('./')
        raise IOError, "duplicate series entry #{name}" unless seen.add?(name)
        bytes = read(PREFIX + name)
        raise IOError, "missing patch bytes for #{name}" unless bytes
        [name, words, bytes]
      end
    end

    def read(name)
      seen = Set.new
      while @links.key?(name)
        raise IOError, 'cycle in archive member links' unless seen.add?(name)
        name = @links.fetch(name)
      end
      @files[name]
    end

    def text(bytes)
      bytes.dup.force_encoding('UTF-8').scrub
    end
  end
end
