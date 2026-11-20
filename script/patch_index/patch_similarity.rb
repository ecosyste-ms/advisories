require 'digest'
require 'fileutils'
require 'json'
require 'optparse'
require 'set'
require 'tempfile'
require 'zlib'

module PatchSimilarity
  extend self

  LIMIT = 1024 * 1024
  UNSUPPORTED = /^(?:GIT binary patch|Binary files |old mode |new mode |rename from |copy from |\*\*\* |@@@)/
  HUNK = /\A@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/

  def filename(line)
    path = line.byteslice(4..).split("\t", 2).first
    return if path == '/dev/null'
    raise ArgumentError unless path && !path.empty? && !path.start_with?('"', '/') && !path.split('/').include?('..')
    path.delete_prefix('./')
  end

  def target(old, new_path)
    return ['change', old] if old && old == new_path
    return ['create', new_path.delete_prefix('b/')] if new_path && !old
    return ['delete', old.delete_prefix('a/')] if old && !new_path
    if old && new_path
      a, sep, path = old.partition('/')
      b, _, other = new_path.partition('/')
      if !sep.empty? && path == other && ([a, b] == %w[a b] || a.delete_suffix('.orig') == b.delete_suffix('.orig'))
        return ['change', path]
      end
      return ['change', new_path] if old.delete_suffix('.orig') == new_path
    end
    raise ArgumentError
  end

  def feed(hash, tag, value = '')
    hash << tag << [value.bytesize].pack('N') << value
  end

  def fingerprint(bytes)
    return if bytes.bytesize > LIMIT || bytes.include?("\0") || bytes.match?(UNSUPPORTED)
    strict = Digest::SHA256.new
    edits = Digest::SHA256.new
    tokens = Set.new
    lines = bytes.split("\n", -1)
    index = sections = hunks = changes = git_sections = 0
    operation = path = nil
    while index < lines.size
      line = lines[index]
      index += 1
      git_sections += 1 if line.start_with?('diff --git ')
      if line.start_with?('--- ') && lines[index]&.start_with?('+++ ')
        return if sections.positive? && hunks.zero?
        operation, path = target(filename(line), filename(lines[index]))
        index += 1
        sections += 1
        hunks = 0
        [strict, edits].each { |h| feed(h, 'F', path); feed(h, 'O', operation) }
      elsif line.start_with?('@@ ')
        header = HUNK.match(line)
        return unless path && header
        before, after = header.captures.map { |count| Integer(count || '1', 10) }
        hunks += 1
        feed(strict, 'H')
        until before.zero? && after.zero?
          content = lines[index]
          index += 1
          content = ' ' if content == '' && index < lines.size
          sign = content&.byteslice(0, 1)
          return unless ['+', '-', ' '].include?(sign)
          before -= 1 unless sign == '+'
          after -= 1 unless sign == '-'
          return if before.negative? || after.negative?
          feed(strict, 'L', content)
          unless sign == ' '
            feed(edits, 'L', content)
            changes += 1
            value = content.byteslice(1..).strip
            tokens << Digest::SHA256.digest([operation, path, sign + value].join("\0")) if value.match?(/\A(?:[^A-Za-z0-9]*[A-Za-z0-9]){4}/)
          end
          if lines[index] == '\ No newline at end of file'
            index += 1
            feed(strict, 'N')
            feed(edits, 'N') unless sign == ' '
          end
        end
      end
    end
    return if hunks.zero? || changes.zero? || (git_sections.positive? && git_sections != sections)
    [strict.digest, edits.digest, tokens]
  rescue ArgumentError
    nil
  end

  def near_pairs(features)
    frequency = Hash.new(0)
    features.each_value { |tokens| tokens.each { |token| frequency[token] += 1 } }
    index = Hash.new { |hash, token| hash[token] = [] }
    features.sort_by { |key, tokens| [tokens.size, key] }.each do |key, tokens|
      next if tokens.size < 6
      minimum = (4 * tokens.size + 4) / 5
      # At Jaccard >= 4/5 these frequency-ordered prefixes must intersect.
      prefix = tokens.sort_by { |t| [frequency[t], t] }.take(tokens.size - minimum + 1)
      prefix.flat_map { |t| index[t] }.uniq.each do |other|
        next if features.fetch(other).size < minimum
        common = (tokens & features[other]).size
        union = tokens.size + features[other].size - common
        yield [key, other].sort, [common, union] if common >= 6 && 5 * common >= 4 * union
      end
      prefix.each { |t| index[t] << key }
    end
  end

  def generate(directories, output)
    files = {}
    directories.each do |dir|
      raise ArgumentError, "missing patch directory: #{dir}" unless File.directory?(dir)
      Dir.glob(File.join(dir, '**', '*')).each do |path|
        digest = File.basename(path)
        files[digest] = path if digest.match?(/\A[a-f0-9]{64}\z/) && File.file?(path)
      end
    end
    groups = %w[same_hunks same_edits].to_h { |label| [label, Hash.new { |h, k| h[k] = [] }] }
    features = {}
    files.sort.each do |digest, path|
      next if File.size(path) > LIMIT
      data = File.binread(path)
      raise IOError, "patch checksum mismatch: #{path}" unless Digest::SHA256.hexdigest(data) == digest
      result = fingerprint(data)
      next unless result
      strict, edits, features[digest] = result
      groups['same_hunks'][strict] << digest
      groups['same_edits'][edits] << digest
    end
    pairs = Hash.new { |h, k| h[k] = {} }
    groups.each { |label, hashes| hashes.each_value { |ids| ids.combination(2) { |pair| pairs[pair][label] = true } } }
    near_pairs(features) { |pair, overlap| pairs[pair]['jaccard'] = overlap }
    directory = File.dirname(output)
    FileUtils.mkdir_p(directory)
    Tempfile.create('similarity', directory, binmode: true) do |file|
      writer = Zlib::GzipWriter.new(file)
      pairs.sort.each { |(a, b), evidence| writer.puts(JSON.generate(evidence.merge(a: a, b: b))) }
      writer.finish
      file.flush
      File.rename(file.path, output)
    end
  end
end

if $PROGRAM_NAME == __FILE__
  output = nil
  OptionParser.new { |opts| opts.on('--output PATH') { |path| output = path } }.parse!
  abort 'usage: patch_similarity.rb --output PATH BLOB_DIRECTORY ...' if !output || ARGV.empty?
  PatchSimilarity.generate(ARGV, output)
end
