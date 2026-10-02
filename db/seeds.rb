default_sources = [
  {name: 'GitHub Advisory Database', kind: 'github', url: 'https://github.com/advisories'},
  {name: 'Erlang Ecosystem Foundation', kind: 'erlef', url: 'https://cna.erlef.org'},
  {name: 'CPAN Security Advisory Database', kind: 'cpansa', url: 'https://github.com/briandfoy/cpan-security-advisory'},
  {name: 'OSV.dev', kind: 'osv', url: 'https://osv.dev'},
]

default_sources.each do |source|
  s = Source.find_or_initialize_by(url: source[:url])
  s.assign_attributes(source)
  s.save
end

Registry.sync_all