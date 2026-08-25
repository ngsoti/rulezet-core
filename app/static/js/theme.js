/*
  theme.js — Applied synchronously before CSS to prevent flash.
  Themes: 'system' | 'light' | 'dark' | <custom css_key>

  Strategy:
  - 'system' resolves to light/dark based on OS preference at runtime
  - light/dark: sets body/html class (dark-mode / light-mode) for existing CSS compat
              + data-bs-theme attribute for Bootstrap dark mode
  - named/custom themes: additionally sets data-theme="<css_key>" on <html>
  - DB is source of truth (server injects data-user-theme on <html>)
  - localStorage['theme-pref'] = raw preference (system/light/dark/ocean/…)
  - localStorage['theme']      = resolved theme (for backward compat)
*/

var _DARK_THEMES   = ['dark', 'midnight', 'sunset'];
var _CUSTOM_THEMES = [];
var _NAMED_KEYS    = ['ocean', 'forest', 'midnight', 'sunset'];
var _rawPref       = 'system';
var _BG_COLORS = {
    light:    '#f7f7f7',
    dark:     '#10151f',
    ocean:    '#edf4fb',
    forest:   '#eef5ee',
    midnight: '#080d18',
    sunset:   '#1c1008',
};

// Extend with server-injected custom themes (window.__CUSTOM_THEMES__ set in base.html)
if (window.__CUSTOM_THEMES__) {
    window.__CUSTOM_THEMES__.forEach(function(t) {
        if (t.is_dark && _DARK_THEMES.indexOf(t.css_key) === -1)
            _DARK_THEMES.push(t.css_key);
        if (_CUSTOM_THEMES.indexOf(t.css_key) === -1)
            _CUSTOM_THEMES.push(t.css_key);
        if (t.bg_color)
            _BG_COLORS[t.css_key] = t.bg_color;
    });
}

function _resolveTheme(pref) {
    if (pref === 'system') {
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    return pref;
}

(function () {
    var html        = document.documentElement;
    var serverTheme = html.getAttribute('data-user-theme') || 'system';
    _rawPref = serverTheme;
    localStorage.setItem('theme-pref', serverTheme);
    applyTheme(serverTheme);
})();

function applyTheme(pref) {
    _rawPref = pref;
    localStorage.setItem('theme-pref', pref);

    var theme  = _resolveTheme(pref);
    var html   = document.documentElement;
    var body   = document.body;
    var isDark = _DARK_THEMES.indexOf(theme) !== -1;

    localStorage.setItem('theme', theme);

    // Backward-compat class on <html> and <body>
    var modeClass = isDark ? 'dark-mode' : 'light-mode';
    html.classList.remove('light-mode', 'dark-mode');
    html.classList.add(modeClass);
    if (body) {
        body.classList.remove('light-mode', 'dark-mode');
        body.classList.add(modeClass);
    }

    // Bootstrap dark mode attribute
    html.setAttribute('data-bs-theme', isDark ? 'dark' : 'light');

    // Named theme attribute — set for every theme except light/system
    // so that custom-themes.css can target [data-theme="dark"] too.
    if (theme !== 'light' && theme !== 'system') {
        html.setAttribute('data-theme', theme);
    } else {
        html.removeAttribute('data-theme');
    }

    // Instant background colour — eliminates flash before CSS loads
    html.style.backgroundColor = _BG_COLORS[theme] || _BG_COLORS.light;

    // Sync legacy toggle buttons (if still present anywhere)
    document.querySelectorAll('.theme-toggle__option').forEach(function(opt) {
        opt.classList.toggle('active', opt.dataset.theme === theme || opt.dataset.theme === pref);
    });

    // Sync footer select
    var sel = document.getElementById('footer-theme-select');
    if (sel && sel.value !== pref) sel.value = pref;
}

function toggleTheme() {
    var current = localStorage.getItem('theme') || 'light';
    var next = (_DARK_THEMES.indexOf(current) !== -1) ? 'light' : 'dark';
    applyTheme(next);
    updateThemeIcon(next);
    _saveThemeToDb(next);
}

function updateThemeIcon(theme) {
    var resolved = _resolveTheme(theme);
    var icon = document.getElementById('theme-icon');
    if (!icon) return;
    var isDark = _DARK_THEMES.indexOf(resolved) !== -1;
    icon.className = isDark ? 'fas fa-sun' : 'fas fa-moon';
}

function _saveThemeToDb(pref) {
    var csrf = document.getElementById('csrf_token');
    if (!csrf) return;
    fetch('/config/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf.value },
        body: JSON.stringify({ theme: pref }),
    });
}

function _populateFooterSelect() {
    var sel = document.getElementById('footer-theme-select');
    if (!sel) return;

    var themes  = window.__CUSTOM_THEMES__ || [];
    var named   = themes.filter(function(t) { return _NAMED_KEYS.indexOf(t.css_key) !== -1; });
    var custom  = themes.filter(function(t) { return _NAMED_KEYS.indexOf(t.css_key) === -1; });

    function makeGroup(label, items) {
        var grp = document.createElement('optgroup');
        grp.label = label;
        items.forEach(function(item) {
            var opt = document.createElement('option');
            opt.value = item.value;
            opt.textContent = item.label;
            grp.appendChild(opt);
        });
        return grp;
    }

    sel.innerHTML = '';

    sel.appendChild(makeGroup('Built-in', [
        { value: 'system', label: 'System (auto)' },
        { value: 'light',  label: 'Light' },
        { value: 'dark',   label: 'Dark' },
    ]));

    if (named.length) {
        sel.appendChild(makeGroup('Themes', named.map(function(t) {
            return { value: t.css_key, label: t.name || t.css_key };
        })));
    }

    if (custom.length) {
        sel.appendChild(makeGroup('Custom', custom.map(function(t) {
            return { value: t.css_key, label: t.name || t.css_key };
        })));
    }

    sel.value = _rawPref;

    sel.addEventListener('change', function() {
        var val = sel.value;
        applyTheme(val);
        updateThemeIcon(val);
        _saveThemeToDb(val);
    });
}

document.addEventListener('DOMContentLoaded', function () {
    var pref = localStorage.getItem('theme-pref') || _rawPref;
    updateThemeIcon(pref);
    _populateFooterSelect();
});
