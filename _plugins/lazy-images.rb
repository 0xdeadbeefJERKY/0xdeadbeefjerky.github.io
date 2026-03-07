# frozen_string_literal: true

# Adds loading="lazy" to all <img> tags that don't already have it.

Jekyll::Hooks.register [:pages, :posts], :post_render do |doc|
  if doc.output_ext == '.html'
    doc.output = doc.output.gsub(/<img(?![^>]*\bloading=)([^>]*)>/, '<img\1 loading="lazy">')
  end
end
