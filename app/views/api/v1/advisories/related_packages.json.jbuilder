json.array! @related_packages do |pkg|
  json.ecosystem pkg.ecosystem
  json.name pkg.name
  json.purl pkg.purl
  json.registry_url pkg.registry_url
end
