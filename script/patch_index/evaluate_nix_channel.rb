require 'digest'
require 'fileutils'
require 'json'
require 'open3'
require 'set'
require 'tmpdir'

module PublishedNix
  extend self

  def unpack(command, path)
    out, error, status = Open3.capture3(command, '-dc', path)
    raise IOError, error unless status.success?
    out
  end

  def evaluate(names, dir, command)
    records = names.map do |name|
      parts = name.scan(/"(?:\\.|[^"\\])*"|[^.]+/).map { |part| part.start_with?('"') ? JSON.parse(part) : part }
      { name: name, parts: parts }
    end
    File.write(File.join(dir, 'names.json'), JSON.generate(records))
    output, error, status = Open3.capture3(*command)
    return JSON.parse(output) if status.success?
    raise IOError, error unless status.exitstatus == 1 && error.include?('error:') && !error.match?(/docker (?:API|daemon)|docker\.sock/i)
    return [{ 'attr' => names.first, 'error' => error.chars.last(300).join }] if names.one?
    half = names.size / 2
    evaluate(names.take(half), dir, command) + evaluate(names.drop(half), dir, command)
  end

  def run(root, catalog, store_paths, destination, systems:, packages:)
    root = File.realpath(root)
    revision = File.read(File.join(root, '.git-revision')).strip
    raise ArgumentError, 'invalid Nix release revision' unless revision.match?(/\A[0-9a-f]{40}\z/)
    expression = File.join(__dir__, 'published_patches.nix')
    stamp = Digest::SHA256.new.update(File.binread(expression)).file(store_paths).hexdigest[0, 16]
    published = unpack('xz', store_paths).each_line(chomp: true).to_set
    names = packages || JSON.parse(unpack('brotli', catalog)).fetch('packages').keys
    dest = File.expand_path(File.join(destination, revision, stamp))
    FileUtils.mkdir_p(dest)
    systems.each do |system|
      raise ArgumentError, 'invalid system' unless system.match?(/\A[\w-]+\z/)
      names.sort.each_slice(300) do |batch|
        key = Digest::SHA256.hexdigest('[' + batch.map { |name| JSON.generate(name, ascii_only: true) }.join(', ') + ']')[0, 16]
        result = File.join(dest, "#{system}-#{key}.json")
        next if File.file?(result)
        Dir.mktmpdir('evaluate-', dest) do |dir|
          cmd = ['docker', 'run', '--rm', '--network', 'none', '-v', "#{root}:/release:ro",
            '-v', "#{dir}:/inputs:ro", '-v', "#{expression}:/eval.nix:ro", '--entrypoint',
            'nix-instantiate', 'nixos/nix:latest', '--eval', '--strict', '--json', '--option',
            'allow-import-from-derivation', 'false', '/eval.nix', '--arg', 'release', '/release',
            '--argstr', 'system', system, '--arg', 'namesFile', '/inputs/names.json']
          rows = evaluate(batch, dir, cmd)
          builds = rows.select { |row| published.include?(row['output']) }
          payload = { revision: revision, system: system, examined: batch.size, builds: builds,
            unpublished: rows.count { |r| r.key?('output') && !published.include?(r['output']) },
            errors: rows.filter_map { |r| r['attr'] if r.key?('error') } }
          pending = File.join(dir, 'result')
          File.write(pending, JSON.generate(payload))
          File.rename(pending, result)
          puts "#{system}: examined #{batch.size}, published with patches #{builds.size}"
        end
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  paths = ARGV.shift(4)
  abort 'usage: evaluate_nix_channel.rb RELEASE PACKAGES STORE_PATHS DESTINATION [--systems ...] [--packages ...]' unless paths.size == 4
  options = {}
  until ARGV.empty?
    flag = ARGV.shift
    abort "unexpected option: #{flag}" unless %w[--systems --packages].include?(flag)
    values = ARGV.shift(ARGV.take_while { |item| !item.start_with?('--') }.size)
    abort "expected values for #{flag}" if values.empty?
    options[flag] = values
  end
  PublishedNix.run(*paths, systems: options.fetch('--systems', %w[x86_64-linux aarch64-linux]), packages: options['--packages'])
end
