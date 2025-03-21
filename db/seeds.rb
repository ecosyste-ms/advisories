default_sources = [
  {name: 'GitHub Advisory Database', kind: 'github', url: 'https://github.com/advisories'},
]

default_sources.each do |source|
  s = Source.find_or_initialize_by(url: source[:url])
  s.assign_attributes(source)
  s.save
end

Registry.sync_all