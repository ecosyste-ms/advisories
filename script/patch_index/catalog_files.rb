require 'digest'
require 'json'
require 'pathname'
require 'fileutils'
require 'uri'
require 'tempfile'

module CatalogFiles
  ROOT = Pathname.new(__dir__).join('../../tmp/trixie-catalog').expand_path
  CACHE = ROOT.join('archives')

  def self.url(row)
    name = row.fetch('source')
    prefix = name.start_with?('lib') ? name[0, 4] : name[0]
    segments = [row.fetch('component'), prefix, name, row.fetch('archive')]
    "https://deb.debian.org/debian/pool/#{segments.map { |s| URI.encode_uri_component(s) }.join('/')}"
  end

  def self.path(row)
    sha = row.fetch('sha256')
    raise 'invalid archive digest' unless sha.match?(/\A[a-f0-9]{64}\z/)
    cached = CACHE.join(sha)
    return cached if cached.file?
    extra = ENV['PATCH_ARCHIVE_DIR']
    existing = Pathname(extra).join(sha) if extra
    existing&.file? ? existing : cached
  end

  def self.archive_members(path, sha256)
    bytes = path.binread
    raise IOError, "archive checksum mismatch: #{path}" unless Digest::SHA256.hexdigest(bytes) == sha256
    PatchIndex::Archive.new(bytes).files
  end

  def self.each_row(&block)
    ROOT.join('catalog.jsonl').each_line { |line| block.call(JSON.parse(line)) }
  end

  def self.fetch
    FileUtils.mkdir_p(CACHE)
    Tempfile.create('curl', ROOT) do |config|
      each_row do |row|
        file = path(row)
        next if file.file? && file.size == row.fetch('size') && Digest::SHA256.file(file).hexdigest == row.fetch('sha256')
        config.puts "url = #{url(row).dump}", "output = #{(CACHE.join(row.fetch('sha256')).to_s + '.part').dump}"
      end
      config.flush
      unless config.size.zero?
        system('curl', '--parallel', '--parallel-max', '8', '--fail', '--silent', '--show-error',
               '--location', '--proto-redir', '=https', '--connect-timeout', '15', '--max-time', '240',
               '--retry', '2', '--config', config.path)
      end
    end
    missing = []
    each_row do |row|
      partial = CACHE.join(row.fetch('sha256') + '.part')
      if partial.file? && partial.size == row.fetch('size') && Digest::SHA256.file(partial).hexdigest == row['sha256']
        File.rename(partial, CACHE.join(row.fetch('sha256')))
      end
      file = path(row)
      missing << row['archive'] unless file.file? && Digest::SHA256.file(file).hexdigest == row['sha256']
    end
    abort "Missing #{missing.size} verified archives: #{missing.first(10).join(', ')}" if missing.any?
  end
end

CatalogFiles.fetch if $PROGRAM_NAME == __FILE__
