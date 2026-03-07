# Blog Feature Additions — Implementation Plan

## Context

The blog (Jekyll + custom cyberpunk dark theme) is missing several features commonly found on tech/security blogs. This plan adds 12 features across 4 phases, prioritized by impact and complexity. Newsletter signup and self-hosted fonts are excluded per user preference. Giscus will be built with placeholder config since GitHub Discussions isn't enabled yet. Search will use a modal overlay (not a dedicated page).

---

## Phase 1: Quick Wins (no dependencies, minimal risk)

### 1.1 — Custom 404 Page ✅ DONE
- **Created** `404.html` at repo root with `layout: default`, `permalink: /404.html`, cyberpunk-themed `0x404` in Orbitron with magenta glow, "Signal Lost" heading, and "Return to Base" link
- **Added** `.error-404` styles to `_sass/_utilities.scss`
- GitHub Pages auto-serves `404.html` for unmatched URLs — no config needed

### 1.2 — robots.txt ✅ DONE
- **Created** `robots.txt` at repo root with Jekyll front matter so `site.url` is interpolated into the Sitemap directive
- GitHub Pages / Jekyll will process the Liquid `{{ site.url }}` at build time

### 1.3 — Open Graph Images per Post
- **Modify** all 6 `_posts/*.md` files — add `image:` front matter
  - Posts with existing images (CloudGoat): reuse `path: /assets/img/cloudgoat.webp`
  - Other posts: use a site-wide fallback
- **Modify** `_config.yml` — add default OG image in `defaults:` block:
  ```yaml
  - scope:
      path: ''
    values:
      image: /assets/img/og-default.png
  ```
- **Create** `assets/img/og-default.png` — 1200×630 cyberpunk-themed site banner
- `jekyll-seo-tag` already reads `page.image` and generates `og:image` / `twitter:image` — no template changes needed

### 1.4 — Lazy Loading Images
- **Create** `_plugins/lazy-images.rb` — Jekyll hook that injects `loading="lazy"` on all `<img>` tags in rendered HTML output:
  ```ruby
  Jekyll::Hooks.register [:pages, :posts], :post_render do |doc|
    if doc.output_ext == '.html'
      doc.output = doc.output.gsub(/<img(?![^>]*\bloading=)([^>]*)>/, '<img\1 loading="lazy">')
    end
  end
  ```

---

## Phase 2: Core Features

### 2.1 — Search Modal Overlay
**Files to create:**
- `search.json` (repo root) — Liquid template generating JSON index of all posts (title, url, date, categories, tags, description)
- `_sass/_search.scss` — modal overlay styles, search input, results list
- `_includes/search.html` — search modal markup

**Files to modify:**
- `_includes/nav.html` — add search icon button after the tab links in `.nav-links`:
  ```html
  <button class="search-toggle" aria-label="Search"><i class="fas fa-search"></i></button>
  ```
- `_layouts/default.html` — add `{% include search.html %}` before the closing `</div>` of `.site-wrapper`, and load Simple-Jekyll-Search from CDN:
  ```html
  <script src="https://unpkg.com/simple-jekyll-search@1.10.0/dest/simple-jekyll-search.min.js"></script>
  ```
- `assets/js/main.js` — add search toggle logic (open/close overlay, Escape key, init SimpleJekyllSearch)
- `assets/css/main.scss` — add `@import "search"`

**Search modal behavior:**
- Full-screen overlay (`position: fixed`, z-index 2000, dark bg with frosted glass)
- Auto-focus input on open, Escape or X button to close
- Results shown as styled list items with title, date, categories
- Cyberpunk styling: cyan border glow on input focus, result items match post-card aesthetic

### 2.2 — Reading Progress Bar
**Files to modify:**
- `_layouts/post.html` — add `<div id="reading-progress" class="reading-progress"></div>` as first child of `.container` (line 5)
- `assets/js/main.js` — append scroll handler inside DOMContentLoaded:
  - Tracks scroll position relative to `.post-content` element
  - Updates bar width as percentage
  - `{ passive: true }` scroll listener
- `_sass/_post.scss` — add `.reading-progress` styles:
  - `position: fixed; top: var(--nav-height); left: 0; height: 3px; z-index: 999`
  - `background: linear-gradient(90deg, var(--accent-cyan), var(--accent-magenta))`
  - `box-shadow: 0 0 8px rgba(0,255,240,0.5)`
  - `@media (prefers-reduced-motion: reduce) { transition: none; }`

### 2.3 — Related Posts
**Files to create:**
- `_includes/related-posts.html` — pure Liquid, scores posts by shared tags (×2) and categories (×1), shows top 3

**Files to modify:**
- `_layouts/post.html` — add `{% include related-posts.html %}` after `.post-tags` div (line 19), before `{% include share.html %}`
- `_sass/_post.scss` — add `.related-posts`, `.related-posts__grid`, `.related-post-card` styles:
  - 3-column grid (1-column on mobile)
  - Cards match post-card aesthetic: dark bg, border, hover lift + cyan border glow

### 2.4 — Giscus Comments (placeholder config)
**Files to create:**
- `_includes/comments.html` — conditional Giscus script tag, reads config from `site.giscus.*`

**Files to modify:**
- `_config.yml` — add:
  ```yaml
  comments:
    active: giscus
  giscus:
    repo: "0xdeadbeefJERKY/0xdeadbeefjerky.github.io"
    repo_id: "REPLACE_ME"          # Get from https://giscus.app
    category: "Announcements"
    category_id: "REPLACE_ME"      # Get from https://giscus.app
    mapping: "pathname"
    reactions_enabled: "1"
    theme: "dark_dimmed"
    lang: "en"
    loading: "lazy"
  ```
- `_config.yml` defaults — add `comments: true` to posts scope
- `_layouts/post.html` — add `{% include comments.html %}` after `</nav>` (post-nav, line 36), before `</article>`

**Setup instructions** (manual, not automated):
1. Enable GitHub Discussions on the repo (Settings → Features → Discussions)
2. Install Giscus GitHub App: https://github.com/apps/giscus
3. Visit https://giscus.app, select repo, get `repo_id` and `category_id`
4. Replace `REPLACE_ME` values in `_config.yml`

---

## Phase 3: Polish Features

### 3.1 — Post Series Navigation
**Files to create:**
- `_includes/series-nav.html` — uses `where_exp` to find posts with matching `series.name`, sorted by `series.part`
- `_sass/_series.scss` — dark card with purple left border accent (matches callout style)

**Files to modify:**
- `assets/css/main.scss` — add `@import "series"`
- `_layouts/post.html` — add `{% if page.series %}{% include series-nav.html %}{% endif %}` after `</header>` (line 11), before `.post-content`
- `_posts/2023-03-03-cloudgoat-lambda-walkthrough.md` — add front matter:
  ```yaml
  series:
    name: "CloudGoat Vulnerable Lambda"
    part: 1
  ```
- `_posts/2023-03-03-cloudgoat-lambda-walkthrough-part-2.md` — add front matter:
  ```yaml
  series:
    name: "CloudGoat Vulnerable Lambda"
    part: 2
  ```

### 3.2 — Breadcrumbs
**Files to create:**
- `_includes/breadcrumbs.html` — `Home / Category / Post Title` with proper links and `aria-label="Breadcrumb"`

**Files to modify:**
- `_layouts/post.html` — add `{% include breadcrumbs.html %}` inside `<article>`, before `<header class="post-header">` (line 8)
- `_sass/_post.scss` — add `.breadcrumbs` styles: font-code, 0.8rem, secondary text color, cyan on hover/current

### 3.3 — Structured Data / JSON-LD
**Files to create:**
- `_includes/structured-data.html` — enriched Article JSON-LD for post pages (wordCount, timeRequired, articleSection, keywords, breadcrumb schema)

**Files to modify:**
- `_includes/head.html` — add `{% include structured-data.html %}` after `{% seo %}` (line 3)

### 3.4 — Print Stylesheet
**Files to modify:**
- `_sass/_utilities.scss` — append `@media print` block at end:
  - Hide: nav, footer, toc, post-nav, share, tags, related posts, comments, progress bar, breadcrumbs, copy buttons
  - Override: white background, black text, 11pt font
  - Show URLs after links: `a::after { content: " (" attr(href) ")"; }`
  - Light code blocks: `border: 1px solid #ccc`, light bg
- Should be done last so all class names from other features are available

---

## Final `_layouts/post.html` Structure

After all modifications, the layout will be (new lines marked with `+`):

```html
<div class="container">
+ <div id="reading-progress" class="reading-progress"></div>
  <div class="post-layout">
    <article>
+     {% include breadcrumbs.html %}
      <header class="post-header">
        <h1 class="post-title">{{ page.title }}</h1>
        {% include post-meta.html %}
      </header>
+     {% if page.series %}{% include series-nav.html %}{% endif %}
      <div class="post-content">{{ content }}</div>
      <div class="post-tags">...</div>
+     {% include related-posts.html %}
      {% include share.html %}
      <nav class="post-nav">...</nav>
+     {% include comments.html %}
    </article>
    {% include toc.html %}
  </div>
</div>
```

---

## Files Summary

### Files to CREATE (14):
| File | Feature |
|------|---------|
| `404.html` | Custom 404 |
| `robots.txt` | robots.txt |
| `assets/img/og-default.png` | OG fallback image |
| `_plugins/lazy-images.rb` | Lazy loading |
| `search.json` | Search index |
| `_includes/search.html` | Search modal |
| `_sass/_search.scss` | Search styles |
| `_includes/comments.html` | Giscus comments |
| `_includes/related-posts.html` | Related posts |
| `_includes/series-nav.html` | Series navigation |
| `_sass/_series.scss` | Series styles |
| `_includes/breadcrumbs.html` | Breadcrumbs |
| `_includes/structured-data.html` | JSON-LD |

### Files to MODIFY (10):
| File | Changes |
|------|---------|
| `_config.yml` | Add `comments:`, `giscus:` blocks; add `comments: true` + OG image default |
| `_layouts/post.html` | Add progress bar, breadcrumbs, series-nav, related-posts, comments includes |
| `_layouts/default.html` | Add search include + Simple-Jekyll-Search script |
| `_includes/head.html` | Add structured-data include |
| `_includes/nav.html` | Add search toggle button |
| `assets/js/main.js` | Add reading progress + search toggle handlers |
| `assets/css/main.scss` | Add `@import "search"` and `@import "series"` |
| `_sass/_post.scss` | Add progress bar, related posts, comments, breadcrumbs styles |
| `_sass/_utilities.scss` | Add 404 styles + print stylesheet |
| `_posts/*.md` (6 files) | Add `image:` front matter; add `series:` to 2 CloudGoat posts |

---

## Verification

1. **Build:** `bundle exec jekyll build -d "_site"` — must succeed with no errors
2. **CI check:** `bundle exec htmlproofer _site --disable-external --check-html --allow_hash_href` — must pass
3. **Local dev:** `bundle exec jekyll serve` then verify:
   - Visit `/nonexistent-page` → custom 404 renders
   - Visit `/sitemap.xml` → exists; `/robots.txt` → has correct sitemap URL
   - View page source on a post → `og:image` meta tag present
   - Post images have `loading="lazy"` attribute in rendered HTML
   - Search icon in nav → opens modal overlay → typing finds posts → clicking result navigates
   - Reading progress bar appears on posts, fills as you scroll
   - Related posts section appears at bottom of posts with shared tags/categories
   - Comments section appears (Giscus will show "config error" until repo_id/category_id are set — expected)
   - CloudGoat posts show series navigation box below header
   - Breadcrumbs show above post title: Home / Category / Title
   - View page source → Article JSON-LD with wordCount, keywords, breadcrumb
   - Print preview (Ctrl+P) → clean output, no nav/footer/sidebar, URLs shown after links
