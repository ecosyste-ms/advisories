default_sources = [
  {name: 'Github', kind: 'github', url: 'https://github.com/advisories'},
]

default_sources.each do |source|
  s = Source.find_or_initialize_by(url: source[:url])
  s.assign_attributes(source)
  s.save
end