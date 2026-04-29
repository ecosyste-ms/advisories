xml.instruct! :xml, version: '1.0', encoding: 'UTF-8'
xml.feed xmlns: 'http://www.w3.org/2005/Atom' do
  xml.title @title || 'Security Advisories'
  xml.subtitle 'Security advisories indexed by ecosyste.ms'
  xml.id request.original_url.sub(/\.(rss|atom)(\?|$)/, '\2')
  xml.link href: request.original_url.sub(/\.(rss|atom)(\?|$)/, '\2')
  xml.link href: url_for(request.query_parameters.merge(format: :atom, only_path: false)), rel: 'self', type: 'application/atom+xml'
  xml.updated((@advisories.first&.published_at || Time.current).iso8601)

  @advisories.each do |advisory|
    xml.entry do
      xml.title advisory.title
      xml.id advisory_url(advisory)
      xml.link href: advisory_url(advisory)
      xml.updated((advisory.updated_at || advisory.published_at || Time.current).iso8601)
      xml.summary advisory.uuid
    end
  end
end
