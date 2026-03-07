// Nav toggle
document.addEventListener('DOMContentLoaded', function () {
    var toggle = document.querySelector('.nav-toggle');
    var links = document.querySelector('.nav-links');
    if (toggle && links) {
        toggle.addEventListener('click', function () {
            links.classList.toggle('open');
        });
        // Close nav when clicking a link (mobile)
        links.querySelectorAll('a').forEach(function (a) {
            a.addEventListener('click', function () {
                links.classList.remove('open');
            });
        });
    }

    // Tagline typewriter effect
    var taglineEl = document.getElementById('tagline-text');
    if (taglineEl) {
        var fullText = taglineEl.textContent;
        var deleteStr = 'an offensive security engineer';
        var typeStr = 'a detection and response engineer passionate about AI';
        var deleteStart = fullText.lastIndexOf(deleteStr);

        if (deleteStart !== -1) {
            var prefix = fullText.substring(0, deleteStart);
            var deleteLen = deleteStr.length;
            var charIndex = 0;

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

        window.addEventListener('scroll', updateActiveToc, { passive: true });
        updateActiveToc();
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
