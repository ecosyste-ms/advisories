require 'tempfile'

class IndexedBodies
  def initialize(catalog:, cache:, http: PatchIndex::Http.new)
    @catalog = catalog
    @cache = cache
    @http = http
  end

  def verify(fetch: false, store: false)
    result = { verified: 0, bytes: 0, missing: 0 }
    patches = Patch.select(:id, :sha256)
    patches = patches.where.missing(:patch_body) if store
    patches.find_each do |patch|
      raise IOError, 'invalid patch digest' unless patch.sha256.match?(/\A[0-9a-f]{64}\z/)
      path = @catalog.join(patch.sha256.first(2), patch.sha256)
      path = @cache.join(patch.sha256) unless path.file?
      recover(patch, path) if fetch && !path.file?
      unless path.file?
        result[:missing] += 1
        next
      end
      if store
        PatchBody.store!(patch.sha256, path.binread)
      elsif Digest::SHA256.file(path).hexdigest != patch.sha256
        raise IOError, "wrong bytes in #{path}"
      end
      result[:verified] += 1
      result[:bytes] += path.size
    end
    result
  end

  def recover(patch, path)
    patch.patch_occurrences.each do |occurrence|
      next if occurrence.declaration['member']
      source = @http.get(occurrence.source_url)
      bytes = occurrence.declaration['data'] ? source.split(/^__END__\r?\n/, 2).fetch(1) : source
      raise IOError, "wrong patch bytes for #{occurrence.name}" unless Digest::SHA256.hexdigest(bytes) == patch.sha256
      path.dirname.mkpath
      Tempfile.create('patch-body', path.dirname) do |file|
        file.binmode
        file.write(bytes)
        file.close
        File.rename(file.path, path)
      end
      return
    end
  end
end

if $PROGRAM_NAME == __FILE__
  audit = IndexedBodies.new(catalog: Rails.root.join('tmp/trixie-catalog/patches'), cache: Rails.root.join('tmp/patch-similarity/blobs'))
  result = audit.verify(fetch: ENV['FETCH'] == '1')
  puts JSON.generate(result)
  exit 1 unless result.fetch(:missing).zero?
end
