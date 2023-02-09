module ApplicationHelper
  include Pagy::Frontend

  def severity_class(severity)
    case severity.downcase
    when 'low'
      'success'
    when 'moderate'
      'warning'
    when 'high'
      'danger'
    when 'critical'
      'dark'
    else
      'info'
    end
  end

  def render_markdown(str)
    CommonMarker.render_html(str, :GITHUB_PRE_LANG, [:tagfilter, :autolink, :table, :strikethrough])
  end

  def meta_title
    [@meta_title, 'Ecosyste.ms: Advisories'].compact.join(' | ')
  end

  def meta_description
    @meta_description || 'An open API service providing security vulnerability metadata for many open source software ecosystems.'
  end
end
