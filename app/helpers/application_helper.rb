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
end
