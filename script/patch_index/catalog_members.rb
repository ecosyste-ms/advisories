require 'active_support/core_ext/file/atomic'
require_relative 'catalog_files'

root = CatalogFiles::ROOT
out = root.join('members')
out.mkpath
reader = PatchIndex::QuiltArchive.new(root.join('patches'))
missing = 0
errors = []
CatalogFiles.each_row do |row|
  digest = row.fetch('sha256')
  archive = CatalogFiles.path(row)
  path = out.join("#{digest}.json")
  next if path.file? && JSON.parse(path.read).fetch('members').values.all? { |m| m['series'] && m['sha256'] }
  partial = Pathname("#{archive}.part")
  archive = partial if !archive.file? && partial.file?
  unless archive.file? && archive.size == row.fetch('size')
    missing += 1
    next
  end
  result = reader.extract(archive, digest, names: row.fetch('patches').pluck('patch'))
  File.atomic_write(path) { |file| file.write(JSON.generate(result)) }
rescue IOError, SystemCallError, KeyError => e
  errors << [row['source'], e.message]
end
puts JSON.generate(archives_pending: missing, errors: errors)
exit 1 if missing.positive? || errors.any?
