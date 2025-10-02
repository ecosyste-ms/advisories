module ApplicationHelper
  include Pagy::Frontend

  def severity_class(severity)
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
end
