// ── Syntax highlighting ──
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('pre code').forEach(function (block) {
      hljs.highlightElement(block);
    });
  });

  // ── Copy button ──
  function copyCode(btn) {
    var container = btn.closest('.code-block, .hero-code-block');
    var pre = container ? container.querySelector('pre') : null;
    var text = pre ? pre.innerText : '';
    navigator.clipboard.writeText(text).then(function () {
      var original = btn.innerHTML;
      btn.innerHTML = '<i class="fas fa-check" aria-hidden="true"></i>Copied';
      btn.style.color = '#4ade80';
      setTimeout(function () {
        btn.innerHTML = original;
        btn.style.color = '';
      }, 1800);
    }).catch(function () {
      // silent fail on insecure contexts
    });
  }

  // ── Mobile sidebar toggle ──
  var menuToggle = document.getElementById('menuToggle');
  var sidebar = document.getElementById('sidebar');
  if (menuToggle && sidebar) {
    menuToggle.addEventListener('click', function () {
      var open = sidebar.classList.toggle('open');
      menuToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    sidebar.querySelectorAll('.sidebar-link').forEach(function (link) {
      link.addEventListener('click', function () {
        sidebar.classList.remove('open');
        menuToggle.setAttribute('aria-expanded', 'false');
      });
    });
  }

  // ── Active section highlight via IntersectionObserver ──
  (function () {
    var links = document.querySelectorAll('.sidebar-link[data-section]');
    var activeId = null;

    function setActive(id) {
      if (id === activeId) return;
      activeId = id;
      links.forEach(function (l) {
        if (l.dataset.section === id) {
          l.classList.add('active');
          l.setAttribute('aria-current', 'true');
        } else {
          l.classList.remove('active');
          l.removeAttribute('aria-current');
        }
      });
    }

    // Default: first link active
    if (links.length > 0) setActive(links[0].dataset.section);

    var sectionIds = Array.from(links).map(function (l) { return l.dataset.section; });
    var sections = sectionIds.map(function (id) { return document.getElementById(id); }).filter(Boolean);

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          setActive(entry.target.id);
        }
      });
    }, {
      rootMargin: '-68px 0px -60% 0px',
      threshold: 0
    });

    sections.forEach(function (s) { observer.observe(s); });
  })();

  // ── Dark mode toggle ──
  // Storage write is wrapped in try/catch and placed after the visible DOM
  // update: some environments throw on localStorage access, and an uncaught
  // exception here would silently abort any script content that follows it
  // on the page (e.g. the back-to-top wiring below).
  (function() {
    var btn = document.getElementById('themeToggle');
    if (!btn) return;
    function applyTheme(t) {
      document.documentElement.setAttribute('data-theme', t);
      btn.setAttribute('aria-label', t === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
      try { localStorage.setItem('rz-theme', t); } catch (e) {}
    }
    btn.addEventListener('click', function() {
      applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    });
  })();

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
