require 'digest'
require 'fileutils'
require 'json'
require 'open3'
require 'optparse'
require 'pathname'
require 'tempfile'
require 'uri'

module DistributionArchives
  extend self

  def member(path, name = nil)
    args = name ? ['-xOf', path.to_s, '--', name] : ['-tf', path.to_s]
    out, error, status = Open3.capture3('bsdtar', *args, binmode: true)
    raise IOError, error unless status.success?
    out
  end

  def declarations(path, row)
    case row.fetch('source')
    when 'Fedora'
      names = member(path).lines(chomp: true)
      specs = names.grep(/\.spec\z/)
      raise IOError, 'expected one RPM spec' unless specs.one?
      spec = specs.first
      member(path, spec).each_line.with_index(1) do |line, number|
        raise IOError, "unhandled patchlist in #{spec}" if line.match?(/^\s*%patchlist\b/i)
        match = line.match(/^\s*Patch\d*:\s*(\S+)/i)
        next unless match
        name = File.basename(match[1].gsub('%{name}', row.fetch('package')).split('?').first)
        raise IOError, "missing patch at #{spec}:#{number}" unless names.include?(name)
        yield name, member(path, name), { spec: spec, line: number, declaration: line.strip }
      end
    when 'Ubuntu'
      require_relative '../../config/environment'
      Dir.mktmpdir do |dir|
        reader = PatchIndex::QuiltArchive.new(dir)
        lines = {}
        archive = reader.extract(path, row.fetch('sha256'), vendor: 'ubuntu') { |name, number| lines[name] = number }
        archive.fetch('members').each do |name, entry|
          raise IOError, "missing patch #{name}" unless entry['sha256']
          yield "debian/patches/#{name}", reader.blob(entry['sha256']).binread,
            { series_line: lines.fetch(name), options: entry.fetch('series').last }
        end
      end
    else
      names = member(path).lines(chomp: true)
      row.fetch('members').each do |requested|
        matches = names.select { |n| n == requested || n.partition('/').last == requested }
        raise IOError, "expected one archive member for #{requested}" unless matches.one?
        yield matches.first, member(path, matches.first), { apply: requested }
      end
    end
  end

  def collect(rows, directory, fetch:)
    blobs = directory.join('blobs')
    blobs.mkpath
    rows.map do |row|
      digest = row.fetch('sha256')
      raise ArgumentError, 'invalid archive digest' unless digest.match?(/\A[a-f0-9]{64}\z/)
      catalog = directory.parent.join('trixie-catalog')
      path = [directory.join(digest), catalog.join('external', digest), catalog.join('archives', digest)].find(&:file?)
      unless path
        raise IOError, "missing archive #{digest}" unless fetch
        path = directory.join(digest)
        Tempfile.create('download', directory) do |file|
          ok = system('curl', '-fsSL', '--proto', '=https', '--proto-redir', '=https', '--retry', '2',
            '--max-time', '120', '-o', file.path, '--', row.fetch('url'))
          raise IOError, 'download failed or checksum mismatch' unless ok && Digest::SHA256.file(file.path).hexdigest == digest
          File.rename(file.path, path)
        end
      end
      raise IOError, "archive checksum mismatch: #{path}" unless Digest::SHA256.file(path).hexdigest == digest
      entries = []
      declarations(path, row) do |name, bytes, evidence|
        sha = Digest::SHA256.hexdigest(bytes)
        blobs.join(sha).binwrite(bytes)
        entries << evidence.merge(name: name, sha256: sha)
      end
      row.merge(declarations: entries)
    end
  end
end

if $PROGRAM_NAME == __FILE__
  directory = Pathname(__dir__).join('../../tmp/patch-similarity').expand_path
  fetch = false
  OptionParser.new do |opts|
    opts.on('--fetch') { fetch = true }
    opts.on('--directory PATH') { |path| directory = Pathname(path) }
  end.parse!
  abort 'usage: distribution_archives.rb [--fetch] [--directory PATH] MANIFEST' unless ARGV.one?
  rows = DistributionArchives.collect(JSON.parse(File.read(ARGV.first)), directory, fetch: fetch)
  Tempfile.create('releases', directory) do |file|
    file.write(JSON.pretty_generate(rows))
    file.close
    File.rename(file.path, directory.join('releases.json'))
  end
end
