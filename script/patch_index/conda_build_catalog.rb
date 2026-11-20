require 'json'
require 'open3'

directory = ARGV.shift or abort 'usage: conda_build_catalog.rb REPODATA_DIRECTORY [PACKAGE ...]'
abort "missing directory: #{directory}" unless File.directory?(directory)
Dir.glob(File.join(directory, '*.json.zst')).sort.each do |path|
  json, error, status = Open3.capture3('zstd', '-dc', path)
  raise IOError, "invalid repodata #{path}: #{error}" unless status.success?
  data = JSON.parse(json)
  subdir = data.fetch('info').fetch('subdir')
  raise IOError, "unexpected subdir in #{path}" unless File.basename(path) == "#{subdir}.json.zst"
  %w[packages.conda packages].each do |section|
    data.fetch(section, {}).each do |name, build|
      next unless ARGV.empty? || ARGV.include?(build.fetch('name'))
      row = build.slice('name', 'version', 'build', 'build_number', 'size')
      puts JSON.generate(row.merge(subdir: subdir, archive_sha256: build['sha256'], md5: build['md5'],
        archive_url: "https://conda.anaconda.org/conda-forge/#{subdir}/#{name}"))
    end
  end
end
