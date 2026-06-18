xml.instruct! :xml, version: '1.0', encoding: 'UTF-8'
xml.rss version: '2.0' do
  xml.channel do
    xml.title @title || 'Security Advisories'
    xml.description 'Security advisories indexed by ecosyste.ms'
    xml.link request.original_url.sub(/\.(rss|atom)(\?|$)/, '\2')
    xml.language 'en'

    @advisories.each do |advisory|
      xml.item do
        xml.title advisory.title
        xml.description advisory.uuid
        xml.link advisory_url(advisory)
        xml.guid advisory_url(advisory), isPermaLink: true
        xml.pubDate advisory.published_at.rfc2822 if advisory.published_at.present?
      end
    end
  end
end
