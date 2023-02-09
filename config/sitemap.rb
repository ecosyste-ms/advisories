SitemapGenerator::Sitemap.default_host = "https://advisories.ecosyste.ms"
SitemapGenerator::Sitemap.create do
  add root_path, priority: 1, changefreq: 'daily'

  Advisory.all.each do |advisory|
    add advisory_path(advisory), lastmod: advisory.updated_at
  end
end