# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Jekyll blog (jekyll-theme-chirpy v5.5.2) deployed to GitHub Pages at 0xdeadbeefjerky.com. Cybersecurity/offensive security blog by Dominic Spinosa.

## Commands

```bash
# Install dependencies
bundle install

# Local development server
bundle exec jekyll serve

# Build
bundle exec jekyll build -d "_site"

# Test (HTML validation — also runs in CI)
bundle exec htmlproofer _site --disable-external --check-html --allow_hash_href
```

## Architecture

- **Posts**: `_posts/` — Markdown files named `YYYY-MM-DD-slug-title.md`. Permalinked as `/posts/:title/`.
- **Static pages**: `_tabs/` — About, Archives, Tags, Categories.
- **Custom plugin**: `_plugins/posts-lastmod-hook.rb` — auto-sets `last_modified_at` from git history.
- **Data files**: `_data/` — localization, contact/share config.
- **Assets**: `assets/img/` — post images and favicons.

## Post Front Matter

```yaml
---
title: "Post Title"
description: >
    Brief description for SEO/previews.
date: YYYY-MM-DD HH:MM:SS-05:00
categories: [Category1, Category2]
tags: [tag1, tag2, tag3]
toc: true
---
```

Categories and tags use bracketed arrays. TOC defaults to true (set in `_config.yml`) but can be overridden per post. Drafts go in `_drafts/` (comments disabled by default).

## Conventions

- Theme mode is dark (set in `_config.yml`).
- `.editorconfig`: 2-space indentation (4-space for JS), UTF-8, LF line endings.
- CI runs on Ruby 3.1 via GitHub Actions (`.github/workflows/pages-deploy.yml`): builds site, runs htmlproofer, then deploys to Pages.
- Custom domain configured in `CNAME` file.
