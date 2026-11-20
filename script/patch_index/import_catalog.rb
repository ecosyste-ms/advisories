require_relative 'catalog_files'

importer = PatchIndex::DebianCatalog.new(CatalogFiles::ROOT.join('patches'))
errors = []
pending = 0
ActiveRecord::Base.logger.silence do
  CatalogFiles.each_row do |row|
    path = CatalogFiles::ROOT.join('members', row.fetch('sha256') + '.json')
    unless path.file?
      pending += 1
      next
    end
    importer.import(row, JSON.parse(path.read), archive_url: CatalogFiles.url(row))
  rescue StandardError => error
    errors << [row['source'], error.message.first(400)]
  end
end
puts JSON.pretty_generate(archives_pending: pending, errors: errors)
exit 1 if pending.positive? || errors.any?
