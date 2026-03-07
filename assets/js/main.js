// Nav toggle
document.addEventListener('DOMContentLoaded', function () {
    function trapFocus(modal) {
        var focusable = modal.querySelectorAll('button, input, a, [tabindex]:not([tabindex="-1"])');
        var first = focusable[0];
        var last = focusable[focusable.length - 1];
        modal.addEventListener('keydown', function (e) {
            if (e.key !== 'Tab') return;
            if (e.shiftKey) {
                if (document.activeElement === first) { e.preventDefault(); last.focus(); }
            } else {
                if (document.activeElement === last) { e.preventDefault(); first.focus(); }
            }
        });
    }

    function onScroll(fn) {
        var ticking = false;
        window.addEventListener('scroll', function () {
            if (!ticking) {
                ticking = true;
                requestAnimationFrame(function () {
                    fn();
                    ticking = false;
                });
            }
        }, { passive: true });
    }

    var toggle = document.querySelector('.nav-toggle');
    var links = document.querySelector('.nav-links');
    if (toggle && links) {
        toggle.addEventListener('click', function () {
            links.classList.toggle('open');
            toggle.setAttribute('aria-expanded', String(links.classList.contains('open')));
        });
        // Close nav when clicking a link (mobile)
        links.querySelectorAll('a').forEach(function (a) {
            a.addEventListener('click', function () {
                links.classList.remove('open');
                toggle.setAttribute('aria-expanded', 'false');
            });
        });
    }

    // Tagline typewriter effect
    var taglineEl = document.getElementById('tagline-text');
    if (taglineEl) {
        var fullText = taglineEl.textContent;
        var deleteStr = taglineEl.getAttribute('data-delete') || '';
        var typeStr = taglineEl.getAttribute('data-type') || '';
        var deleteStart = fullText.lastIndexOf(deleteStr);

        if (deleteStart !== -1) {
            var prefix = fullText.substring(0, deleteStart);
            var deleteLen = deleteStr.length;
            var charIndex = 0;

            var prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            if (prefersReducedMotion) {
                taglineEl.textContent = fullText.substring(0, deleteStart) + typeStr;
            } else {
                setTimeout(function () {
                    // Backspace phase
                    var backspace = setInterval(function () {
                        charIndex++;
                        taglineEl.textContent = fullText.substring(0, fullText.length - charIndex);
                        if (charIndex >= deleteLen) {
                            clearInterval(backspace);
                            // Type phase
                            var typeIndex = 0;
                            var typeInterval = setInterval(function () {
                                typeIndex++;
                                taglineEl.textContent = prefix + typeStr.substring(0, typeIndex);
                                if (typeIndex >= typeStr.length) {
                                    clearInterval(typeInterval);
                                }
                            }, 60);
                        }
                    }, 40);
                }, 1500);
            }
        }
    }

    // Copy buttons on code blocks
    document.querySelectorAll('.highlight').forEach(function (block) {
        var btn = document.createElement('button');
        btn.className = 'copy-btn';
        btn.textContent = 'Copy';
        btn.addEventListener('click', function () {
            var code = block.querySelector('code');
            if (!code) return;
            var text = code.innerText;
            navigator.clipboard.writeText(text).then(function () {
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(function () {
                    btn.textContent = 'Copy';
                    btn.classList.remove('copied');
                }, 2000);
            }).catch(function () {
                btn.textContent = 'Failed';
                setTimeout(function () {
                    btn.textContent = 'Copy';
                }, 2000);
            });
        });
        block.appendChild(btn);
    });

    // ToC generation from headings
    var tocList = document.getElementById('toc-list');
    if (tocList) {
        var content = document.querySelector('.post-content');
        if (content) {
            var headings = content.querySelectorAll('h2, h3');
            if (headings.length > 0) {
                var ul = document.createElement('ul');
                headings.forEach(function (h) {
                    if (!h.id) {
                        h.id = h.textContent.toLowerCase()
                            .replace(/[^a-z0-9]+/g, '-')
                            .replace(/(^-|-$)/g, '');
                    }
                    var li = document.createElement('li');
                    var a = document.createElement('a');
                    a.href = '#' + h.id;
                    a.textContent = h.textContent;
                    li.appendChild(a);
                    if (h.tagName === 'H3') {
                        li.style.paddingLeft = '1rem';
                    }
                    ul.appendChild(li);
                });
                tocList.appendChild(ul);
            }
        }
    }

    // ToC toggle (mobile)
    var tocToggle = document.querySelector('.toc-toggle');
    var tocBody = document.querySelector('.toc-body');
    if (tocToggle && tocBody) {
        tocToggle.addEventListener('click', function () {
            tocBody.classList.toggle('open');
        });
    }

    // ToC scroll spy — highlight active section
    var tocLinks = document.querySelectorAll('#toc-list a');
    if (tocLinks.length > 0) {
        var tocHeadings = [];
        tocLinks.forEach(function (link) {
            var id = link.getAttribute('href').slice(1);
            var el = document.getElementById(id);
            if (el) tocHeadings.push({ el: el, link: link });
        });

        function updateActiveToc() {
            var scrollPos = window.scrollY + 100;
            var active = null;
            for (var i = 0; i < tocHeadings.length; i++) {
                if (tocHeadings[i].el.offsetTop <= scrollPos) {
                    active = tocHeadings[i];
                }
            }
            tocLinks.forEach(function (link) {
                link.classList.remove('active');
            });
            if (active) {
                active.link.classList.add('active');
            }
        }

        onScroll(updateActiveToc);
        updateActiveToc();
    }

    // Reading progress bar
    var progressBar = document.getElementById('reading-progress');
    if (progressBar) {
        var article = document.querySelector('.post-content');
        function updateProgress() {
            if (!article) return;
            var articleTop = article.offsetTop;
            var articleHeight = article.offsetHeight;
            var scrolled = window.scrollY - articleTop;
            var pct = Math.min(Math.max((scrolled / articleHeight) * 100, 0), 100);
            progressBar.style.width = pct + '%';
            progressBar.setAttribute('aria-valuenow', Math.round(pct));
        }
        onScroll(updateProgress);
        updateProgress();
    }

    // Search modal
    var searchOverlay = document.getElementById('search-overlay');
    var searchToggle = document.getElementById('search-toggle');
    var searchClose = document.getElementById('search-close');
    var searchInput = document.getElementById('search-input');

    function openSearch() {
        if (searchOverlay) {
            searchOverlay.classList.add('open');
            if (searchInput) searchInput.focus();
        }
    }

    function closeSearch() {
        if (searchOverlay) {
            searchOverlay.classList.remove('open');
            if (searchInput) searchInput.value = '';
            var results = document.getElementById('search-results');
            if (results) results.innerHTML = '';
        }
        if (searchToggle) searchToggle.focus();
    }

    if (searchToggle) {
        searchToggle.addEventListener('click', openSearch);
    }

    if (searchClose) {
        searchClose.addEventListener('click', closeSearch);
    }

    if (searchOverlay) {
        searchOverlay.addEventListener('click', function (e) {
            if (e.target === searchOverlay) closeSearch();
        });
        var searchModal = searchOverlay.querySelector('.search-modal');
        if (searchModal) trapFocus(searchModal);
    }

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') closeSearch();
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            if (searchOverlay && searchOverlay.classList.contains('open')) {
                closeSearch();
            } else {
                openSearch();
            }
        }
    });

    // Initialize Simple Jekyll Search (loaded externally)
    if (typeof SimpleJekyllSearch !== 'undefined' && searchInput) {
        SimpleJekyllSearch({
            searchInput: searchInput,
            resultsContainer: document.getElementById('search-results'),
            json: '/search.json',
            searchResultTemplate: '<li class="search-result-item"><a href="{url}"><span class="search-result-title">{title}</span><span class="search-result-meta">{date} &middot; {categories}</span></a></li>',
            noResultsText: '<li class="search-no-results">No results found</li>',
            limit: 10,
            fuzzy: false
        });
    }

    // Scroll fade-in animation
    if ('IntersectionObserver' in window) {
        var observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });

        document.querySelectorAll('.fade-in').forEach(function (el) {
            observer.observe(el);
        });
    } else {
        document.querySelectorAll('.fade-in').forEach(function (el) {
            el.classList.add('visible');
        });
    }
});
