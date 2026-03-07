# frozen_string_literal: true

require "open3"

Jekyll::Hooks.register :posts, :post_init do |post|
  commit_num, status = Open3.capture2("git", "rev-list", "--count", "HEAD", post.path)
  next unless status.success? && commit_num.strip.to_i > 1

  lastmod_date, status = Open3.capture2("git", "log", "-1", "--pretty=%ad", "--date=iso", post.path)
  post.data["last_modified_at"] = lastmod_date.strip if status.success?
end
