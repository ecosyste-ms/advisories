module PatchesHelper
  def patch_preview_sections(body)
    lines = body.preview_lines.first(PatchBody::PREVIEW_LINES)
    start = lines.each_index.find do |i|
      lines[i].start_with?('diff --git ', 'Index: ') ||
        (lines[i].start_with?('--- ') && lines[i + 1]&.start_with?('+++ '))
    end
    [lines.take(start || 0), lines.drop(start || 0)]
  end

  def formatted_patch_diff(lines)
    safe_join(lines.map do |line|
      case line
      when /\A(?:diff --git |--- |\+\+\+ )/ then tag.strong(line)
      when /\A@@/ then tag.span(line, class: 'text-primary')
      when /\A\+/ then tag.span(line, class: 'text-success')
      when /\A-/ then tag.span(line, class: 'text-danger')
      else line
      end
    end)
  end

  def patch_release_label(release)
    "#{release.distribution.humanize} / #{release.package_name} #{release.version}"
  end

  def patch_advisory_links(occurrence, advisories)
    roles = occurrence.advisory_roles
    safe_join(occurrence.advisory_ids.map do |id|
      records = advisories.fetch(id, [])
      link = records.empty? ? id : safe_join(records.map { |record| link_to(id, advisory_path(record.uuid)) }, ', ')
      tag.li(safe_join([link, ' ', tag.span(PatchOccurrence::ROLES.fetch(roles.fetch(id)), class: 'text-muted')]))
    end)
  end
end
