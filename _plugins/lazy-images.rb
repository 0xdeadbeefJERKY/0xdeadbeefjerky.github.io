# frozen_string_literal: true

# Adds loading="lazy" to all <img> tags that don't already have it.
# Wraps bare tables for horizontal scroll without breaking accessibility.

Jekyll::Hooks.register [:pages, :posts], :post_render do |doc|
  if doc.output_ext == '.html'
    doc.output = doc.output.gsub(/<img(?![^>]*\bloading=)([^>]*)>/, '<img\1 loading="lazy">')
    doc.output = doc.output.gsub(%r{<table(?![^>]*role=)([^>]*)>}i, '<div class="table-wrap"><table role="table"\1>')
    doc.output = doc.output.gsub(%r{</table>}i, '</table></div>')
  end
end
