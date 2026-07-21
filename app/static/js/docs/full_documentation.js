// ── Copy-to-clipboard for any code blocks we add later ──
  function copyCode(btn) {
    var container = btn.closest('.code-block, .hero-code-block');
    var pre = container ? container.querySelector('pre') : null;
    var text = pre ? pre.innerText : '';
    navigator.clipboard.writeText(text).then(function () {
      var original = btn.innerHTML;
      btn.innerHTML = '<i class="fas fa-check" aria-hidden="true"></i>Copied';
      setTimeout(function () { btn.innerHTML = original; }, 1800);
    }).catch(function () {});
  }

  // ── Mobile sidebar toggle ──
  var menuToggle = document.getElementById('menuToggle');
  var sidebar = document.getElementById('sidebar');
  if (menuToggle && sidebar) {
    menuToggle.addEventListener('click', function () {
      var open = sidebar.classList.toggle('open');
      menuToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }

  // ── Collapsible sidebar parts ──
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.sidebar-part');
    if (!btn) return;
    var expanded = btn.getAttribute('aria-expanded') === 'true';
    btn.setAttribute('aria-expanded', expanded ? 'false' : 'true');
    var links = document.getElementById(btn.getAttribute('aria-controls'));
    if (links) links.classList.toggle('collapsed', expanded);
  });

  // ── Sidebar link clicks close mobile menu + set active + expand parent part ──
  document.addEventListener('click', function (e) {
    var link = e.target.closest('.sidebar-link');
    if (!link) return;
    if (sidebar) sidebar.classList.remove('open');
    if (menuToggle) menuToggle.setAttribute('aria-expanded', 'false');
    document.querySelectorAll('.sidebar-link').forEach(function (l) { l.classList.remove('active'); });
    link.classList.add('active');
    var crumb = document.getElementById('crumbActive');
    if (crumb) crumb.textContent = link.getAttribute('data-title') || link.textContent.trim();
  });

  // ── Active section highlight via IntersectionObserver ──
  (function () {
    var links = document.querySelectorAll('.sidebar-link[data-section]');
    if (!links.length) return;
    var activeId = null;
    function setActive(id) {
      if (id === activeId) return;
      activeId = id;
      links.forEach(function (l) {
        var on = l.dataset.section === id;
        l.classList.toggle('active', on);
        if (on) {
          var crumb = document.getElementById('crumbActive');
          if (crumb) crumb.textContent = l.getAttribute('data-title') || l.textContent.trim();
          // auto-expand the containing part
          var parent = l.closest('.sidebar-part-links');
          if (parent && parent.classList.contains('collapsed')) {
            parent.classList.remove('collapsed');
            var btnId = parent.id;
            var partBtn = document.querySelector('.sidebar-part[aria-controls="' + btnId + '"]');
            if (partBtn) partBtn.setAttribute('aria-expanded', 'true');
          }
        }
      });
    }
    if (links.length > 0) setActive(links[0].dataset.section);
    var sectionIds = Array.from(links).map(function (l) { return l.dataset.section; });
    var sections = sectionIds.map(function (id) { return document.getElementById(id); }).filter(Boolean);
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) { if (entry.isIntersecting) setActive(entry.target.id); });
    }, { rootMargin: '-68px 0px -60% 0px', threshold: 0 });
    sections.forEach(function (s) { observer.observe(s); });
  })();

  // ── Dark mode toggle ──
  // Storage writes are wrapped in try/catch and placed AFTER the visible DOM
  // update: some environments (sandboxed preview iframes, private-browsing
  // modes) throw on localStorage access, and an uncaught exception here would
  // silently abort every script block that follows it on the page — including
  // the export menu wiring further down. Never let persistence failures break
  // functionality.
  (function() {
    var btn = document.getElementById('themeToggle');
    if (!btn) return;
    function applyTheme(t) {
      document.documentElement.setAttribute('data-theme', t);
      try { localStorage.setItem('rz-doc-theme', t); } catch (e) {}
    }
    btn.addEventListener('click', function() {
      applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    });
  })();


  // ── Export menu open/close ──
  (function () {
    var btn = document.getElementById('exportBtn');
    var menu = document.getElementById('exportMenu');
    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      var open = menu.classList.toggle('open');
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    document.addEventListener('click', function (e) {
      if (!menu.contains(e.target) && e.target !== btn) { menu.classList.remove('open'); btn.setAttribute('aria-expanded', 'false'); }
    });
  })();

  // ── Screenshot media: click any captured image to view it full size ──
  (function () {
    var lightbox = document.getElementById('shotLightbox');
    var lightboxImg = document.getElementById('lightboxImg');

    function openLightbox(src) {
      lightboxImg.src = src;
      lightbox.classList.add('open');
      lightbox.setAttribute('aria-hidden', 'false');
    }
    function closeLightbox() {
      lightbox.classList.remove('open');
      lightbox.setAttribute('aria-hidden', 'true');
      lightboxImg.src = '';
    }
    lightbox.addEventListener('click', closeLightbox);
    lightbox.querySelector('.lightbox-close').addEventListener('click', function (e) { e.stopPropagation(); closeLightbox(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeLightbox(); });

    document.querySelectorAll('.shot-media-frame').forEach(function (frame) {
      var img = frame.querySelector('.shot-media-img');
      frame.addEventListener('click', function () { openLightbox(img.src); });
      frame.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); frame.click(); }
      });
    });
  })();

  // ── Export: Print / Save as PDF ──
  function exportPrint() {
    document.getElementById('exportMenu').classList.remove('open');
    window.print();
  }

  // ── Export: Download as Markdown ──
  // Walks every .doc-section in document order and serializes its
  // currently-visible-language content into a flat Markdown report.
  function exportMarkdown() {
    document.getElementById('exportMenu').classList.remove('open');
    var lines = [];
    lines.push('# Rulezet — Full Documentation & Report');
    lines.push('');
    lines.push('_Generated from the Rulezet documentation template._');
    lines.push('');

    function visible() { return true; }
    function textOf(el) {
      var out = '';
      el.childNodes.forEach(function (node) {
        if (node.nodeType === 3) { out += node.textContent; }
        else if (node.nodeType === 1) { out += node.textContent; }
      });
      return out.replace(/\s+/g, ' ').trim();
    }

    document.querySelectorAll('.part-marker').forEach(function (pm) {
      pm.setAttribute('data-md-emitted', 'pending');
    });

    var nodes = document.querySelectorAll('#contentInner .part-marker, #contentInner .doc-section');
    nodes.forEach(function (node) {
      if (node.classList.contains('part-marker')) {
        var t = node.querySelector('.part-marker-title');
        lines.push('');
        lines.push('# ' + (t ? textOf(t) : ''));
        return;
      }
      // doc-section
      var eyebrow = node.querySelector('.eyebrow');
      var title = node.querySelector('.section-title');
      var lead = node.querySelector('.section-lead');
      lines.push('');
      lines.push('## ' + (title ? textOf(title) : ''));
      if (lead) { lines.push(''); lines.push('_' + textOf(lead) + '_'); }
      node.querySelectorAll(':scope > .subsection-title, :scope > .doc-p, :scope > ul.doc-list, :scope > .table-wrap, :scope > .why-panel, :scope > .shot-media, :scope > .flow-steps, :scope > .feature-grid, :scope > .usecase-card, :scope > .callout, :scope > .toc-part').forEach(function (child) {
        if (!visible(child)) return;
        if (child.classList.contains('toc-part')) {
          var pt = child.querySelector('.toc-part-title');
          lines.push(''); lines.push('### ' + (pt ? textOf(pt) : ''));
          child.querySelectorAll('.toc-list li').forEach(function (li) { lines.push('- ' + textOf(li)); });
        } else if (child.classList.contains('subsection-title')) {
          lines.push(''); lines.push('### ' + textOf(child));
        } else if (child.classList.contains('doc-p')) {
          lines.push(''); lines.push(textOf(child));
        } else if (child.tagName === 'UL') {
          lines.push('');
          child.querySelectorAll(':scope > li').forEach(function (li) { if (visible(li)) lines.push('- ' + textOf(li)); });
        } else if (child.classList.contains('table-wrap')) {
          var rows = child.querySelectorAll('tr');
          lines.push('');
          rows.forEach(function (tr, i) {
            var cells = Array.from(tr.children).map(function (c) { return textOf(c); });
            lines.push('| ' + cells.join(' | ') + ' |');
            if (i === 0) lines.push('|' + cells.map(function () { return ' --- '; }).join('|') + '|');
          });
        } else if (child.classList.contains('why-panel')) {
          lines.push(''); lines.push('> **Why:** ' + textOf(child.querySelector('.why-panel-body') || child));
        } else if (child.classList.contains('shot-media')) {
          var mImg = child.querySelector('.shot-media-img');
          // `.src` (the DOM property) resolves to a full absolute URL;
          // `.getAttribute('src')` returns the raw root-relative path
          // (e.g. "/static/image/..."), which breaks once the .md file is
          // downloaded and opened outside this page's origin — that was the
          // "images don't show" bug.
          var mSrc = mImg ? mImg.src : null;
          if (mSrc) { lines.push(''); lines.push('![screenshot](' + mSrc + ')'); }
        } else if (child.classList.contains('flow-steps')) {
          child.querySelectorAll('.flow-step').forEach(function (step, i) {
            var st = step.querySelector('.flow-title'); var sd = step.querySelector('.flow-desc');
            lines.push('');
            lines.push((i + 1) + '. **' + (st ? textOf(st) : '') + '** — ' + (sd ? textOf(sd) : ''));
          });
        } else if (child.classList.contains('feature-grid')) {
          child.querySelectorAll('.feature-card').forEach(function (card) {
            var ct = card.querySelector('.feature-card-title'); var cd = card.querySelector('.feature-card-desc');
            lines.push('- **' + (ct ? textOf(ct) : '') + '** — ' + (cd ? textOf(cd) : ''));
          });
        } else if (child.classList.contains('usecase-card')) {
          var role = child.querySelector('.usecase-role'); var txt = child.querySelector('.usecase-text');
          lines.push('- **' + (role ? textOf(role) : '') + ':** ' + (txt ? textOf(txt) : ''));
        } else if (child.classList.contains('callout')) {
          lines.push(''); lines.push('> ' + textOf(child.querySelector('.callout-body') || child));
        }
      });
    });

    var blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'rulezet-documentation.md';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  // ── Back to top ──
  (function () {
    var btn = document.getElementById('backToTop');
    if (!btn) return;
    function onScroll() {
      btn.classList.toggle('visible', window.scrollY > 400);
    }
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    btn.addEventListener('click', function () {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  })();
