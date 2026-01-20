module ApplicationHelper
  include Pagy::Frontend

  def severity_class(severity)
    return 'text-bg-secondary' if severity.nil?
    case severity.downcase
    when 'low'
      'bg-success'
    when 'moderate'
      'text-bg-warning'
    when 'high'
      'bg-danger'
    when 'critical'
      'bg-dark'
    else
      'text-bg-info'
    end
  end

  def render_markdown(str)
    return '' if str.nil?
    Commonmarker.to_html(str)
  end

  def meta_title
    [@meta_title, 'Ecosyste.ms: Advisories'].compact.join(' | ')
  end

  def meta_description
    @meta_description || app_description
  end

  def app_name
    "Advisories"
  end

  def app_description
    'An open API service providing security vulnerability metadata for many open source software ecosystems.'
  end

  def bootstrap_icon(symbol, options = {})
    return "" if symbol.nil?
    icon = BootstrapIcons::BootstrapIcon.new(symbol, options)
    content_tag(:svg, icon.path.html_safe, icon.options)
  end

  def source_icon(source, options = {})
    icon_name = source.is_a?(Source) ? source.icon : Source::ICONS[source]
    icon_name ||= 'shield-exclamation'
    bootstrap_icon(icon_name, options.merge(width: 18, height: 18, class: 'me-2'))
  end
end
