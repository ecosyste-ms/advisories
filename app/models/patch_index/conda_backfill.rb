module PatchIndex
  class CondaBackfill
    def initialize(importer = Conda.new)
      @importer = importer
    end

    def run(catalog, budget:, build_limit:, checkpoint: nil)
      raise ArgumentError, 'transfer limits must be positive' unless build_limit.positive? && (!budget || budget.positive?)
      stats = { imported: 0, skipped: 0, failed: 0, bytes: 0, complete: false }
      digest = Digest::SHA256.file(catalog).hexdigest if checkpoint
      offset = 0
      if checkpoint && File.exist?(checkpoint)
        state = JSON.parse(File.read(checkpoint))
        raise ArgumentError, 'checkpoint belongs to a different catalog' unless state.fetch('catalog') == digest
        offset = state.fetch('offset')
      end
      File.open(catalog, 'rb') do |input|
        input.seek(offset)
        while (line = input.gets)
          pin = JSON.parse(line)
          remaining = budget ? budget - stats[:bytes] : build_limit
          break if remaining <= 0
          release = PatchRelease.find_by(distribution: 'conda-forge', package_name: pin.fetch('name'),
            version: pin.fetch('version'), revision: "#{pin.fetch('subdir')}/#{pin.fetch('build')}")
          if already_imported?(release, pin)
            stats[:skipped] += 1
          else
            begin
              raise IOError, 'conflicting archive for previously indexed build' if release
              @importer.import_build(pin, max_bytes: [remaining, build_limit].min)
              stats[:bytes] += @importer.transferred
              stats[:imported] += 1
            rescue IOError, KeyError, TypeError, ArgumentError, Psych::Exception => e
              stats[:bytes] += @importer.transferred.to_i unless release
              warn "#{pin.fetch('archive_url')}: #{e.message}"
              # A run-wide budget must not consume the checkpoint for an unfinished build.
              break if remaining < build_limit && e.message.include?('budget')
              stats[:failed] += 1
              if checkpoint
                File.open("#{checkpoint}.failures.jsonl", 'a') { |f| f.puts(pin.merge(error: e.message).to_json) }
              end
            end
          end
          if checkpoint
            tmp = "#{checkpoint}.#{Process.pid}.tmp"
            File.write(tmp, { catalog: digest, offset: input.pos }.to_json)
            File.rename(tmp, checkpoint)
          end
          stats[:complete] = input.eof?
        end
        stats[:complete] = true if input.size == offset
      end
      stats
    end

    def already_imported?(release, pin)
      return false unless release && release.source_url == pin.fetch('archive_url')
      sha = pin['archive_sha256']
      return [release.metadata['catalog_sha256'], release.metadata['archive_sha256']].include?(sha) if sha.present?
      pin['md5'].present? && release.metadata['catalog_md5'] == pin['md5']
    end
  end
end
