module PatchesHelper
  def patch_comparison_line(line)
    marker = line.byteslice(0, 1)
    css = { '+' => 'addition', '-' => 'removal', ' ' => 'context' }[marker]
    content = css ? line.byteslice(1..) : line
    text = content.delete_suffix("\n").force_encoding('UTF-8').scrub { |s| s.bytes.map { |b| format('\\x%02X', b) }.join }
    text = text.gsub(/[\x00-\x08\x0b-\x1f\x7f]/) { |c| format('\\x%02X', c.ord) }
    tag.span(class: "patch-comparison-line #{css || 'annotation'}") do
      safe_join([tag.span(css ? marker : '', class: 'patch-comparison-marker'), text])
    end
  end

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

  def patch_similarity_label(evidence)
    return 'Same hunks and context' if evidence['same_hunks']
    return 'Same ordered edits' if evidence['same_edits']

    shared, total = evidence.fetch('jaccard')
    "#{shared} of #{total} distinct changed-line tokens match"
  end

  def upstream_mapping_message(occurrence)
    status, reason = occurrence.mapping.values_at('status', 'reason')
    if status == 'unresolved' && reason == 'no supported language registry archive'
      return 'The source archive URL does not identify a package in a supported registry.'
    end
    ["Upstream mapping #{status}.", reason].compact.join(' ')
  end
end
