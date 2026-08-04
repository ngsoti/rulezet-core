/**
 * GlobalSearch — main-nav search box with a leboncoin-style results panel:
 * quick page shortcuts, live rule/bundle/user matches (highlighted), recent
 * searches, and "see all results in X" links. Replaces the old offcanvas
 * that used to mount a full <rule-list>.
 *
 * Props:
 *   pages            (Array)   — [{ label, url, icon, keywords }], already
 *                                 filtered server-side by auth/admin rights.
 *   is-authenticated (Boolean)
 *   is-admin         (Boolean)
 *
 * Backend: GET /global_search?q=... — see app/home_core.py. Rules are
 * always public; bundles/users are filtered server-side by visibility, this
 * component never assumes anything about what it's allowed to see.
 *
 * Usage (Vue template):
 *   <global-search :pages="NAV_PAGES" :is-authenticated="isAuthenticated" :is-admin="isAdmin" />
 */

const { defineComponent, ref, computed, onMounted, onBeforeUnmount, nextTick } = Vue;

const RECENT_KEY = 'rz-recent-searches';
const MAX_RECENT = 5;
const DEBOUNCE_MS = 300;

function loadRecent() {
    try {
        const raw = JSON.parse(localStorage.getItem(RECENT_KEY) || '[]');
        return Array.isArray(raw) ? raw.filter(x => typeof x === 'string') : [];
    } catch { return []; }
}

function saveRecent(list) {
    try { localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, MAX_RECENT))); } catch {}
}

function escapeHtml(str) {
    return String(str ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
}

// Escapes first, then wraps the match in <mark> — the ONLY literal HTML tag
// in the result is one we wrote ourselves, so this is safe to bind with
// v-html even though the source text (rule title, username, ...) is
// attacker-controlled.
function highlight(label, query) {
    const safeLabel = escapeHtml(label);
    const q = (query || '').trim();
    if (!q) return safeLabel;
    const safeQuery = escapeHtml(q);
    const idx = safeLabel.toLowerCase().indexOf(safeQuery.toLowerCase());
    if (idx === -1) return safeLabel;
    return safeLabel.slice(0, idx)
        + '<mark class="gs-match">' + safeLabel.slice(idx, idx + safeQuery.length) + '</mark>'
        + safeLabel.slice(idx + safeQuery.length);
}

const GlobalSearch = defineComponent({
    name: 'GlobalSearch',
    delimiters: ['[[', ']]'],
    props: {
        pages:           { type: Array, default: () => [] },
        isAuthenticated: { type: Boolean, default: false },
        isAdmin:         { type: Boolean, default: false },
    },

    setup(props) {
        const rootEl   = ref(null);
        const inputEl  = ref(null);
        const query    = ref('');
        const isOpen   = ref(false);
        const loading  = ref(false);
        const results  = ref({ rules: [], bundles: [], users: [] });
        const recentSearches  = ref(loadRecent());
        const highlightedIndex = ref(-1);

        let debounceTimer = null;
        let abortCtrl = null;

        const matchedPages = computed(() => {
            const q = query.value.trim().toLowerCase();
            if (!q) return [];
            return props.pages.filter(p =>
                p.label.toLowerCase().includes(q)
                || (p.keywords || []).some(k => k.toLowerCase().includes(q))
            ).slice(0, 5);
        });

        const sectionOrder = computed(() => query.value.trim() ? ['page', 'rule', 'bundle', 'user', 'shortcut'] : ['recent']);

        const sectionItems = computed(() => ({
            recent: recentSearches.value.map(label => ({ label })),
            page:   matchedPages.value,
            rule:   results.value.rules.map(r => ({ label: r.title, meta: r.format, url: `/rule/detail_rule/${r.id}` })),
            bundle: results.value.bundles.map(b => ({ label: b.name, meta: b.access ? null : 'Private', url: `/bundle/detail_bundle/${b.id}` })),
            user:   results.value.users.map(u => ({ label: u.username, avatar: u.avatar, url: `/account/detail_user/${u.id}` })),
            shortcut: query.value.trim() ? [
                { label: `See all results for “${query.value.trim()}” in`, strong: 'Rules', url: `/rule/rules_list?search=${encodeURIComponent(query.value.trim())}` },
                { label: `See all results for “${query.value.trim()}” in`, strong: 'Bundles', url: `/bundle/list?search=${encodeURIComponent(query.value.trim())}` },
            ] : [],
        }));

        const sectionTitles = {
            recent: 'Recent searches', page: 'Pages', rule: 'Rules',
            bundle: 'Bundles', user: 'Users', shortcut: '',
        };

        const flatCount = computed(() => sectionOrder.value.reduce((sum, s) => sum + sectionItems.value[s].length, 0));

        const isEmpty = computed(() =>
            query.value.trim() && !loading.value
            && matchedPages.value.length === 0
            && results.value.rules.length === 0
            && results.value.bundles.length === 0
            && results.value.users.length === 0
        );

        function offsetFor(section) {
            let sum = 0;
            for (const s of sectionOrder.value) {
                if (s === section) break;
                sum += sectionItems.value[s].length;
            }
            return sum;
        }
        function isActive(section, idx) { return highlightedIndex.value === offsetFor(section) + idx; }

        function itemAtFlatIndex(i) {
            let remaining = i;
            for (const s of sectionOrder.value) {
                const items = sectionItems.value[s];
                if (remaining < items.length) return { section: s, item: items[remaining] };
                remaining -= items.length;
            }
            return null;
        }

        function open() { isOpen.value = true; }
        function close() { isOpen.value = false; highlightedIndex.value = -1; }

        function fetchResults() {
            const q = query.value.trim();
            if (!q) { results.value = { rules: [], bundles: [], users: [] }; loading.value = false; return; }
            if (abortCtrl) abortCtrl.abort();
            abortCtrl = new AbortController();
            loading.value = true;
            fetch(`/global_search?q=${encodeURIComponent(q)}`, { signal: abortCtrl.signal })
                .then(r => r.ok ? r.json() : { rules: [], bundles: [], users: [] })
                .then(data => { results.value = data; })
                .catch(err => { if (err.name !== 'AbortError') results.value = { rules: [], bundles: [], users: [] }; })
                .finally(() => { loading.value = false; });
        }

        function onInput() {
            highlightedIndex.value = -1;
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(fetchResults, DEBOUNCE_MS);
        }

        function onFocus() { open(); }

        function recordSearch() {
            const q = query.value.trim();
            if (!q) return;
            const next = [q, ...recentSearches.value.filter(x => x.toLowerCase() !== q.toLowerCase())].slice(0, MAX_RECENT);
            recentSearches.value = next;
            saveRecent(next);
        }

        function removeRecent(idx) {
            const next = recentSearches.value.filter((_, i) => i !== idx);
            recentSearches.value = next;
            saveRecent(next);
        }

        function runRecent(label) {
            query.value = label;
            highlightedIndex.value = -1;
            fetchResults();
            nextTick(() => inputEl.value && inputEl.value.focus());
        }

        function goTo(url) {
            recordSearch();
            window.location.href = url;
        }

        function moveHighlight(delta) {
            if (!flatCount.value) return;
            open();
            let next = highlightedIndex.value + delta;
            if (next < 0) next = flatCount.value - 1;
            if (next >= flatCount.value) next = 0;
            highlightedIndex.value = next;
        }

        function onEnter() {
            if (highlightedIndex.value === -1) {
                if (!query.value.trim()) return;
                goTo(`/rule/rules_list?search=${encodeURIComponent(query.value.trim())}`);
                return;
            }
            const hit = itemAtFlatIndex(highlightedIndex.value);
            if (!hit) return;
            if (hit.section === 'recent') { runRecent(hit.item.label); return; }
            goTo(hit.item.url);
        }

        function clearQuery() {
            query.value = '';
            results.value = { rules: [], bundles: [], users: [] };
            highlightedIndex.value = -1;
            nextTick(() => inputEl.value && inputEl.value.focus());
        }

        function onClickOutside(e) {
            if (rootEl.value && !rootEl.value.contains(e.target)) close();
        }

        onMounted(() => document.addEventListener('mousedown', onClickOutside));
        onBeforeUnmount(() => document.removeEventListener('mousedown', onClickOutside));

        return {
            rootEl, inputEl, query, isOpen, loading, results,
            matchedPages, sectionOrder, sectionItems, sectionTitles,
            isEmpty, isActive,
            open, close, onInput, onFocus, onEnter, moveHighlight, clearQuery,
            goTo, runRecent, removeRecent,
            highlight,
        };
    },

    template: `
<div class="gs-wrap" ref="rootEl">
  <div class="gs-input-group" :class="{ 'gs-input-group--open': isOpen }">
    <i class="fa-solid fa-magnifying-glass gs-icon"></i>
    <input
      ref="inputEl"
      type="text"
      class="gs-input"
      placeholder="Search rules, bundles, users, pages…"
      v-model="query"
      @focus="onFocus"
      @input="onInput"
      @keydown.down.prevent="moveHighlight(1)"
      @keydown.up.prevent="moveHighlight(-1)"
      @keydown.enter.prevent="onEnter"
      @keydown.esc="close"
      aria-label="Search"
    />
    <button v-if="query" type="button" class="gs-clear" @click="clearQuery" aria-label="Clear search">
      <i class="fa-solid fa-xmark"></i>
    </button>
  </div>

  <div v-if="isOpen" class="gs-panel" v-cloak>

    <template v-if="!query.trim()">
      <div v-if="sectionItems.recent.length" class="gs-section">
        <div class="gs-section-title">[[ sectionTitles.recent ]]</div>
        <div v-for="(it, idx) in sectionItems.recent" :key="'recent-'+idx"
             class="gs-item" :class="{ 'gs-item--active': isActive('recent', idx) }"
             @click="runRecent(it.label)">
          <i class="fa-solid fa-clock-rotate-left gs-item-icon"></i>
          <span class="gs-item-label">[[ it.label ]]</span>
          <button type="button" class="gs-item-remove" @click.stop="removeRecent(idx)" aria-label="Remove">
            <i class="fa-solid fa-xmark"></i>
          </button>
        </div>
      </div>
      <div v-else class="gs-empty">Start typing to search rules, bundles, users and pages.</div>
    </template>

    <template v-else>
      <div v-if="loading" class="gs-loading"><span class="spinner-border spinner-border-sm"></span> Searching…</div>

      <div v-if="sectionItems.page.length" class="gs-section">
        <div class="gs-section-title">[[ sectionTitles.page ]]</div>
        <div v-for="(it, idx) in sectionItems.page" :key="'page-'+idx"
             class="gs-item" :class="{ 'gs-item--active': isActive('page', idx) }"
             @click="goTo(it.url)">
          <i :class="['fa-solid', it.icon || 'fa-arrow-right', 'gs-item-icon']"></i>
          <span class="gs-item-label" v-html="highlight(it.label, query)"></span>
        </div>
      </div>

      <div v-if="sectionItems.rule.length" class="gs-section">
        <div class="gs-section-title">[[ sectionTitles.rule ]]</div>
        <div v-for="(it, idx) in sectionItems.rule" :key="'rule-'+idx"
             class="gs-item" :class="{ 'gs-item--active': isActive('rule', idx) }"
             @click="goTo(it.url)">
          <i class="fa-solid fa-shield-halved gs-item-icon"></i>
          <span class="gs-item-label" v-html="highlight(it.label, query)"></span>
          <span v-if="it.meta" class="gs-item-meta">[[ it.meta ]]</span>
        </div>
      </div>

      <div v-if="sectionItems.bundle.length" class="gs-section">
        <div class="gs-section-title">[[ sectionTitles.bundle ]]</div>
        <div v-for="(it, idx) in sectionItems.bundle" :key="'bundle-'+idx"
             class="gs-item" :class="{ 'gs-item--active': isActive('bundle', idx) }"
             @click="goTo(it.url)">
          <i class="fa-solid fa-box gs-item-icon"></i>
          <span class="gs-item-label" v-html="highlight(it.label, query)"></span>
          <span v-if="it.meta" class="gs-item-meta gs-item-meta--private">[[ it.meta ]]</span>
        </div>
      </div>

      <div v-if="sectionItems.user.length" class="gs-section">
        <div class="gs-section-title">[[ sectionTitles.user ]]</div>
        <div v-for="(it, idx) in sectionItems.user" :key="'user-'+idx"
             class="gs-item" :class="{ 'gs-item--active': isActive('user', idx) }"
             @click="goTo(it.url)">
          <span class="gs-item-avatar">
            <img v-if="it.avatar" :src="it.avatar" alt="" />
            <template v-else>[[ (it.label || '?').charAt(0).toUpperCase() ]]</template>
          </span>
          <span class="gs-item-label" v-html="highlight(it.label, query)"></span>
        </div>
      </div>

      <div v-if="isEmpty" class="gs-empty">No matches for “[[ query.trim() ]]”.</div>

      <div v-if="sectionItems.shortcut.length" class="gs-section gs-section--shortcuts">
        <div v-for="(it, idx) in sectionItems.shortcut" :key="'shortcut-'+idx"
             class="gs-item gs-item--shortcut" :class="{ 'gs-item--active': isActive('shortcut', idx) }"
             @click="goTo(it.url)">
          <i class="fa-solid fa-arrow-right gs-item-icon"></i>
          <span class="gs-item-label">[[ it.label ]] <strong>[[ it.strong ]]</strong></span>
        </div>
      </div>
    </template>
  </div>
</div>
`,
});

export default GlobalSearch;
