require 'tempfile'

module PatchIndex
  class QuiltArchive
    PREFIX = 'debian/patches/'
    METADATA = %w[debian/copyright debian/upstream/metadata].freeze

    def initialize(blobs)
      @blobs = Pathname(blobs)
    end

    def extract(path, digest, vendor: nil, names: nil)
      raise IOError, 'archive checksum mismatch' unless Digest::SHA256.file(path).hexdigest == digest
      files, links, repository = {}, {}, {}
      changelog = ''
      total = 0
      ArchiveReader.open(path: path) do |archive|
        archive.each do |entry|
          name = entry.name
          if vendor && %w[debian debian/patches].include?(name) && (entry.hardlink || entry.symlink)
            raise IOError, "unsupported linked packaging directory #{name}"
          end
          next unless name.start_with?(PREFIX) || METADATA.include?(name) || name == 'debian/changelog'
          if entry.symlink || entry.hardlink
            target = entry.hardlink || Pathname(name).dirname.join(entry.symlink)
            links[name] = Pathname(target).cleanpath.to_s
          elsif entry.regular?
            total += entry.size
            raise IOError, 'packaging members exceed sync size limit' if vendor && total > 128.megabytes
            bytes = entry.read(vendor ? 32.megabytes : entry.size)
            if name == 'debian/changelog'
              changelog = bytes.lines.take_while { |line| !line.start_with?(' -- ') }.join.force_encoding('UTF-8').scrub
            elsif METADATA.include?(name)
              lines = bytes.lines
              lines = lines.take_while { |line| !line.strip.empty? } if name == 'debian/copyright'
              value = lines.grep(/\A(?:Source|Repository|Repository-Browse):/).join.force_encoding('UTF-8').scrub
              raise IOError, "conflicting repository fields at #{name}" if repository.key?(name) && repository[name] != value
              repository[name] = value
            else
              sha = Digest::SHA256.hexdigest(bytes)
              raise IOError, "conflicting archive members at #{name}" if files.key?(name) && files[name] != sha
              files[name] = sha
              store(sha, bytes)
            end
          end
        end
      end
      series = PREFIX + 'series'
      variant = "#{PREFIX}#{vendor}.series"
      series = variant if vendor && (files.key?(variant) || links.key?(variant))
      series_sha = resolve(files, links, series)
      raise IOError, "unresolved series link #{series}" if links.key?(series) && !series_sha
      options = {}
      if series_sha
        blob(series_sha).binread.force_encoding('UTF-8').scrub.each_line.with_index(1) do |line, number|
          words = line.split.take_while { |arg| !arg.start_with?('#') }
          next if words.empty?
          key = words.shift.delete_prefix('./')
          raise IOError, "duplicate series entry #{key}" if options.key?(key)
          options[key] = [options.size + 1, words]
          yield key, number if block_given?
        end
      end
      members = (names || options.keys).index_with do |name|
        key = name.delete_prefix('./')
        { 'sha256' => resolve(files, links, PREFIX + key), 'series' => options[key] }
      end
      { 'archive_sha256' => digest, 'series_path' => series, 'members' => members, 'changelog' => changelog, 'repository_files' => repository }
    end

    def resolve(files, links, name)
      seen = Set.new
      while links.key?(name)
        raise IOError, 'cycle in archive member links' unless seen.add?(name)
        name = links.fetch(name)
      end
      files[name]
    end

    def blob(sha)
      @blobs.join(sha[0, 2], sha)
    end

    def store(sha, bytes)
      path = blob(sha)
      return if path.file?
      path.dirname.mkpath
      Tempfile.create('member', path.dirname, binmode: true) do |file|
        file.write(bytes)
        file.close
        File.rename(file.path, path)
      end
    end
  end
end
