/*
  BadRuleList.js — RuleList's sibling for invalid/bad rules (InvalidRuleModel).

  Props:
    fetchUrl        (String)  — paginated+filtered endpoint, default
                                 '/rule/get_bads_rules_page_filter'
    deleteAllUrl    (String)  — default '/rule/bad_rule/delete_all_bad_rule'
    deleteListUrl   (String)  — bulk-delete-by-id endpoint for the selection
                                 bulk bar, default '/rule/bad_rule/delete_list'
    source          (String)  — locked source filter (e.g. the GitHub repo url
                                 this page is scoped to) — hidden from the UI,
                                 always sent as `sources`.
    ruleTypeFilter  (String)  — externally-driven format filter (e.g. set by a
                                 parent page's per-format KPI card) — watched;
                                 changing it resets to page 1 and refetches.
    csrfToken       (String)
    currentUserId   (Number)
    currentUserIsAdmin (Boolean)
    deletable       (Boolean) — show per-row Delete + toolbar "Delete all",
                                 default true.
    mode            (String)  — 'read' | 'manage'. 'manage' adds row/page
                                 checkboxes and the selection bulk bar, same
                                 convention as RuleList's mode prop.
                                 Default 'read' (no change vs. before).
    syncUrl         (Boolean) — mirror search/filters/sort/page/view into the
                                 URL query string (history.replaceState, no
                                 reload), same convention as RuleList's
                                 syncUrl. Default false — opt in for a page
                                 where this list IS the page (e.g.
                                 bad_rules_summary.html); leave off when
                                 embedded inside a larger page (e.g. the
                                 GitHub import report).
    bulkActions     (Array)   — [{key,label,icon?,variant?}], shown in the
                                 bulk bar. Default just a Delete action.
                                 Non-'delete' keys are re-emitted as
                                 'bulk-action' for the parent to handle.

  Emits:
    count-loaded (total)      — fired after every fetch, so a parent tab/badge
                                 can show how many bad rules exist for this scope.
    bulk-action ({action, ids, count}) — a bulkActions entry other than the
                                 built-in 'delete' was clicked.
*/

import PaginationComponent from '/static/js/rule/paginationComponent.js'
import CodeViewer from '/static/js/components/code-viewer.js'
import UserChip from '/static/js/components/UserChip.js'
import { create_message } from '/static/js/toaster.js'

const { ref, reactive, computed, onMounted, watch } = Vue

export default {
    name: 'BadRuleList',
    components: { PaginationComponent, CodeViewer, 'user-chip': UserChip },
    props: {
        fetchUrl:        { type: String,  default: '/rule/get_bads_rules_page_filter' },
        deleteAllUrl:    { type: String,  default: '/rule/bad_rule/delete_all_bad_rule' },
        deleteListUrl:   { type: String,  default: '/rule/bad_rule/delete_list' },
        source:          { type: String,  default: null },
        ruleTypeFilter:  { type: String,  default: '' },
        csrfToken:       { type: String,  default: '' },
        currentUserId:   { type: Number,  default: null },
        currentUserIsAdmin: { type: Boolean, default: false },
        deletable:       { type: Boolean, default: true },
        mode:            { type: String,  default: 'read' },
        syncUrl:         { type: Boolean, default: false },
        bulkActions:     { type: Array,   default: () => [{ key: 'delete', label: 'Delete selected', icon: 'fa-trash-can', variant: 'danger' }] },
    },
    emits: ['count-loaded', 'bulk-action'],
    setup(props, { emit }) {
        // ── URL param helpers (only consulted when props.syncUrl is on) ──
        const _url = new URLSearchParams(window.location.search)
        const _p   = (key, fallback = '') => _url.get(key) ?? fallback

        const items       = ref([])
        const loading     = ref(true)
        const currentPage = ref(props.syncUrl ? (Number(_p('page', '1')) || 1) : 1)
        const totalPages  = ref(1)
        const totalRules  = ref(0)
        const viewMode    = ref(props.syncUrl ? _p('view', 'table') : 'table')
        const expandedIds = ref(new Set())
        const filtersOpen = ref(props.syncUrl && ['rule_type', 'search_field', 'user_id'].some(k => _url.has(k)))
        const perPage     = ref(props.syncUrl ? (Number(_p('per_page', '20')) || 20) : 20)

        const search      = ref(props.syncUrl ? _p('search', '') : '')
        const searchField = ref(props.syncUrl ? _p('search_field', 'all') : 'all')
        const formatFilter = ref(props.ruleTypeFilter || (props.syncUrl ? _p('rule_type', '') : ''))
        const userFilter  = ref(props.syncUrl ? _p('user_id', '') : '')
        let searchTimer = null

        // ── Selection (mode='manage' only) ──────────────────────────────
        const selectedIds  = reactive(new Set())
        const isSelectable = computed(() => props.mode === 'manage')

        function isSelected(rule) { return selectedIds.has(rule.id) }
        function toggleItem(rule) {
            if (selectedIds.has(rule.id)) selectedIds.delete(rule.id)
            else selectedIds.add(rule.id)
        }
        const allOnPageSelected = computed(() =>
            isSelectable.value && items.value.length > 0 && items.value.every(r => selectedIds.has(r.id))
        )
        const someOnPageSelected = computed(() => {
            if (!isSelectable.value) return false
            const n = items.value.filter(r => selectedIds.has(r.id)).length
            return n > 0 && n < items.value.length
        })
        function togglePageSelection() {
            if (allOnPageSelected.value) items.value.forEach(r => selectedIds.delete(r.id))
            else items.value.forEach(r => selectedIds.add(r.id))
        }
        function clearSelection() { selectedIds.clear() }
        const selectionCount = computed(() => selectedIds.size)
        const showBulkBar = computed(() => isSelectable.value && selectedIds.size > 0)

        // ── Editor (user) filter — single-select, scoped to the same
        // source/format the list itself is scoped to, refetched whenever
        // either changes so the picker never offers a user with 0 rules
        // in the current view.
        const userList = ref([])
        async function fetchUserList() {
            try {
                const params = new URLSearchParams()
                if (props.source)       params.set('sources', props.source)
                if (formatFilter.value) params.set('rule_types', formatFilter.value)
                const res = await fetch('/rule/get_bad_rules_users_usage?' + params.toString())
                if (res.ok) userList.value = await res.json()
            } catch {
                userList.value = []
            }
        }
        // Only admins can filter by other users (the backend returns [] and
        // ignores user_id entirely for anyone else — see get_bad_rules_users_usage).
        if (props.currentUserIsAdmin) watch(formatFilter, fetchUserList)

        // ── Sort — server-side, same setSort/sortIcon convention as RuleList ──
        const sortKey = ref(props.syncUrl ? _p('sort', 'created_at') : 'created_at')
        const sortDir = ref(props.syncUrl ? _p('dir', 'desc') : 'desc')
        function setSort(key) {
            if (sortKey.value === key) {
                sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
            } else {
                sortKey.value = key
                sortDir.value = 'asc'
            }
            fetchData(1)
        }
        function sortIcon(key) {
            if (sortKey.value !== key) return 'fa-sort'
            return sortDir.value === 'asc' ? 'fa-sort-up' : 'fa-sort-down'
        }

        // ── Column visibility (table mode) — same picker pattern as RuleList ──
        const TOGGLEABLE_COLS = [
            { key: 'format', label: 'Format' },
            { key: 'editor', label: 'Editor' },
            { key: 'error',  label: 'Error message' },
            { key: 'path',   label: 'Path' },
            { key: 'date',   label: 'Date' },
        ]
        const colVisible = reactive(Object.fromEntries(TOGGLEABLE_COLS.map(c => [c.key, true])))
        function toggleColumn(key) { colVisible[key] = !colVisible[key] }

        // File + Actions columns are always shown (+1 more when the selection
        // checkbox column is on) — colspan for the expand row must track
        // however many toggleable columns are currently visible.
        const tableColspan = computed(() =>
            2 + (isSelectable.value ? 1 : 0) + TOGGLEABLE_COLS.filter(c => colVisible[c.key]).length
        )

        const allExpanded = computed(() => items.value.length > 0 && items.value.every(r => expandedIds.value.has(r.id)))
        function expandAll()   { expandedIds.value = new Set(items.value.map(r => r.id)) }
        function collapseAll() { expandedIds.value = new Set() }

        watch(() => props.ruleTypeFilter, (val) => {
            formatFilter.value = val || ''
            filtersOpen.value = true
            fetchData(1)
        })

        watch(perPage, () => fetchData(1))

        function isOwner(rule) {
            return props.currentUserId != null && rule.user_id === props.currentUserId
        }
        function canManage(rule) {
            return props.deletable && (props.currentUserIsAdmin || isOwner(rule))
        }

        // ── URL sync — mirrors RuleList's syncToUrl() convention ──────────
        // Starts from the current params so external ones are preserved.
        function syncToUrl() {
            if (!props.syncUrl) return
            const p = new URLSearchParams(window.location.search)
            const _upd = (key, val) => val ? p.set(key, val) : p.delete(key)

            _upd('search',       search.value.trim() || null)
            _upd('search_field', searchField.value !== 'all' ? searchField.value : null)
            _upd('rule_type',    formatFilter.value || null)
            _upd('user_id',      userFilter.value || null)
            _upd('page',         currentPage.value > 1 ? currentPage.value : null)
            _upd('per_page',     perPage.value !== 20 ? perPage.value : null)
            _upd('view',         viewMode.value !== 'table' ? viewMode.value : null)
            if (sortKey.value !== 'created_at' || sortDir.value !== 'desc') {
                p.set('sort', sortKey.value); p.set('dir', sortDir.value)
            } else {
                p.delete('sort'); p.delete('dir')
            }

            const qs = p.toString()
            history.replaceState(null, '', qs ? `?${qs}` : window.location.pathname)
        }

        watch(viewMode, syncToUrl)

        async function fetchData(page) {
            loading.value = true
            try {
                const params = new URLSearchParams({
                    page: page || currentPage.value, per_page: perPage.value,
                    sort: sortKey.value, dir: sortDir.value,
                })
                if (search.value.trim())      params.set('search', search.value.trim())
                if (search.value.trim())      params.set('search_field', searchField.value)
                if (props.source)             params.set('sources', props.source)
                if (formatFilter.value)       params.set('rule_types', formatFilter.value)
                if (userFilter.value)         params.set('user_id', userFilter.value)

                const res = await fetch(props.fetchUrl + '?' + params.toString())
                if (res.status === 200) {
                    const data = await res.json()
                    items.value       = data.rule || []
                    totalPages.value  = data.total_pages || 1
                    totalRules.value  = data.total_rules || 0
                    currentPage.value = page || 1
                    emit('count-loaded', totalRules.value)
                    syncToUrl()
                } else {
                    items.value = []
                    totalRules.value = 0
                    emit('count-loaded', 0)
                }
            } catch {
                items.value = []
            } finally {
                loading.value = false
            }
        }

        function onFilterChange() { fetchData(1) }

        function onSearchInput() {
            clearTimeout(searchTimer)
            searchTimer = setTimeout(() => fetchData(1), 360)
        }

        function clearSearch() {
            search.value = ''
            fetchData(1)
        }

        function resetFilters() {
            search.value = ''
            searchField.value = 'all'
            formatFilter.value = ''
            userFilter.value = ''
            fetchData(1)
        }

        const hasActiveFilters = computed(() => !!(search.value.trim() || formatFilter.value || userFilter.value))

        function toggleExpand(id) {
            const next = new Set(expandedIds.value)
            next.has(id) ? next.delete(id) : next.add(id)
            expandedIds.value = next
        }

        function fixRule(rule) {
            window.location.href = `/rule/bad_rule/${rule.id}/edit`
        }

        async function deleteRule(rule) {
            if (!confirm(`Delete this invalid rule (${rule.file_name})? This cannot be undone.`)) return
            try {
                const res = await fetch(`/rule/bad_rule/${rule.id}/delete`, {
                    method: 'POST',
                    headers: { 'X-CSRFToken': props.csrfToken },
                })
                if (res.ok) {
                    create_message('Invalid rule deleted.', 'success-subtle')
                    fetchData(currentPage.value)
                } else {
                    create_message('Could not delete this rule.', 'danger-subtle')
                }
            } catch {
                create_message('Could not delete this rule.', 'danger-subtle')
            }
        }

        async function deleteAll() {
            const label = formatFilter.value ? ` (${formatFilter.value.toUpperCase()} only)` : ''
            if (!confirm(`Delete all ${totalRules.value} invalid rule(s) in this list${label}? This cannot be undone.`)) return
            try {
                const params = new URLSearchParams()
                if (props.source)       params.set('sources', props.source)
                if (formatFilter.value) params.set('rule_types', formatFilter.value)
                const res = await fetch(props.deleteAllUrl + '?' + params.toString(), {
                    method: 'POST',
                    headers: { 'X-CSRFToken': props.csrfToken },
                })
                if (res.ok) {
                    create_message('Invalid rules deleted.', 'success-subtle')
                    fetchData(1)
                } else {
                    create_message('Could not delete these rules.', 'danger-subtle')
                }
            } catch {
                create_message('Could not delete these rules.', 'danger-subtle')
            }
        }

        // ── Bulk delete (selection-based, complements deleteAll's filter-based one) ──
        async function _bulkDelete(ids) {
            try {
                const res = await fetch(props.deleteListUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body: JSON.stringify({ ids }),
                })
                const data = await res.json()
                create_message(data.message, data.toast_class)
                if (res.ok) { clearSelection(); fetchData(1) }
            } catch {
                create_message('Could not delete the selected rules.', 'danger-subtle')
            }
        }

        function emitBulkAction(actionKey) {
            const ids   = Array.from(selectedIds)
            const count = selectionCount.value
            if (actionKey === 'delete') {
                if (confirm(`Delete ${count} selected invalid rule(s)? This cannot be undone.`)) _bulkDelete(ids)
            } else {
                emit('bulk-action', { action: actionKey, ids, count })
                clearSelection()
            }
        }

        onMounted(() => {
            fetchData(1)
            if (props.currentUserIsAdmin) fetchUserList()
        })

        return {
            items, loading, currentPage, totalPages, totalRules, viewMode, expandedIds,
            filtersOpen, perPage,
            isSelectable, selectedIds, isSelected, toggleItem, allOnPageSelected, someOnPageSelected,
            togglePageSelection, clearSelection, selectionCount, showBulkBar, emitBulkAction,
            search, searchField, formatFilter, userFilter, userList, hasActiveFilters,
            TOGGLEABLE_COLS, colVisible, toggleColumn, tableColspan,
            allExpanded, expandAll, collapseAll,
            sortKey, sortDir, setSort, sortIcon,
            fetchData, onFilterChange, onSearchInput, clearSearch, resetFilters, toggleExpand,
            isOwner, canManage, fixRule, deleteRule, deleteAll,
        }
    },

    template: `
<div class="brl-root">

    <!-- Toolbar: search + view toggle + filters — matches RuleList's rl-toolbar exactly -->
    <div class="rl-toolbar">
        <div class="rl-toolbar-left">
            <div class="dt-search">
                <i class="fas fa-search dt-search-icon"></i>
                <input class="dt-search-input" type="text" placeholder="Search file name or error…"
                       v-model="search" @input="onSearchInput" aria-label="Search invalid rules" />
                <button v-if="search" class="dt-search-clear" @click="clearSearch" aria-label="Clear search">
                    <i class="fas fa-xmark"></i>
                </button>
            </div>
            <span v-if="!loading" class="text-muted small ms-2 text-nowrap">
                <strong>{{ totalRules }}</strong> invalid rule<span v-if="totalRules!==1">s</span>
            </span>
        </div>

        <div class="rl-toolbar-right">
            <!-- View toggle -->
            <div class="dt-view-toggle" title="Switch view">
                <button class="dt-view-btn" :class="{ 'dt-view-btn--active': viewMode === 'card' }"
                        @click="viewMode = 'card'" aria-label="Card view">
                    <i class="fas fa-rectangle-list"></i>
                </button>
                <button class="dt-view-btn" :class="{ 'dt-view-btn--active': viewMode === 'table' }"
                        @click="viewMode = 'table'" aria-label="Table view">
                    <i class="fas fa-table-cells-large"></i>
                </button>
            </div>

            <!-- Column picker (table mode) -->
            <div v-if="viewMode === 'table'" class="dropdown">
                <button class="dt-toolbar-btn dropdown-toggle" data-bs-toggle="dropdown"
                        aria-expanded="false" aria-label="Toggle columns">
                    <i class="fas fa-table-columns"></i>
                    <span>Columns</span>
                </button>
                <ul class="dropdown-menu dropdown-menu-end shadow border-0 py-2"
                    style="border-radius:12px;min-width:165px;" @click.stop>
                    <li v-for="col in TOGGLEABLE_COLS" :key="col.key">
                        <label class="dropdown-item rounded-2 d-flex align-items-center gap-2"
                               style="cursor:pointer;font-size:.84rem;user-select:none;">
                            <input type="checkbox" :checked="colVisible[col.key]" @change="toggleColumn(col.key)" />
                            {{ col.label }}
                        </label>
                    </li>
                </ul>
            </div>

            <!-- Expand / collapse all -->
            <button class="dt-toolbar-btn" :class="{ 'dt-toolbar-btn--active': allExpanded }"
                    :title="allExpanded ? 'Collapse all' : 'Expand all'"
                    @click="allExpanded ? collapseAll() : expandAll()">
                <i :class="allExpanded ? 'fas fa-compress-alt' : 'fas fa-expand-alt'"></i>
                <span>{{ allExpanded ? 'Collapse' : 'Expand' }}</span>
            </button>

            <!-- Filters toggle -->
            <button class="dt-toolbar-btn" :class="{ 'dt-toolbar-btn--active': filtersOpen }"
                    @click="filtersOpen = !filtersOpen" :aria-expanded="filtersOpen">
                <i class="fa-solid fa-filter"></i>
                <span>Filters</span>
                <span v-if="hasActiveFilters" class="rl-filter-badge ms-1">{{ (search.trim()?1:0) + (formatFilter?1:0) }}</span>
            </button>

            <!-- Delete all -->
            <button v-if="deletable && totalRules > 0" class="dt-toolbar-btn" style="color:#dc3545;border-color:#dc3545;"
                    @click="deleteAll">
                <i class="fas fa-trash-can"></i>
                <span>Delete all<span v-if="hasActiveFilters"> (filtered)</span></span>
            </button>

            <!-- Rows per page (table mode) -->
            <div v-if="viewMode === 'table'" class="rl-per-page">
                <span>Rows</span>
                <select v-model.number="perPage" aria-label="Rows per page">
                    <option v-for="n in [10, 25, 50, 100]" :key="n" :value="n">{{ n }}</option>
                </select>
            </div>
        </div>
    </div>

    <!-- Filter panel — same rl-fmt-badge overlay control RuleList uses for format -->
    <div v-show="filtersOpen" class="rl-filter-panel">
        <div class="rl-fp-row">
            <div class="rl-fp-item rl-fp-fmt-wrap">
                <div class="rl-fmt-badge" :class="{ 'rl-fmt-badge--set': formatFilter }">
                    <span v-if="formatFilter" class="rl-fmt-badge__label">{{ formatFilter.toUpperCase() }}</span>
                    <span v-else class="rl-fmt-badge__placeholder">
                        <i class="fa-solid fa-file-code me-1" style="font-size:.7rem;opacity:.5;"></i>Format
                    </span>
                    <i class="fa-solid fa-chevron-down" style="font-size:.6rem;opacity:.5;flex-shrink:0;"></i>
                </div>
                <select class="rl-fmt-select-overlay" v-model="formatFilter" @change="onFilterChange" aria-label="Format">
                    <option value="">All formats</option>
                    <option value="yara">YARA</option>
                    <option value="sigma">Sigma</option>
                    <option value="suricata">Suricata</option>
                    <option value="zeek">Zeek</option>
                    <option value="wazuh">Wazuh</option>
                    <option value="nse">NSE</option>
                    <option value="crs">CRS</option>
                    <option value="nova">NOVA</option>
                </select>
            </div>

            <div class="rl-fp-item">
                <select v-model="searchField" class="rl-fp-select" @change="onFilterChange" aria-label="Search in">
                    <option value="all">All fields</option>
                    <option value="file_name">File name only</option>
                    <option value="error_message">Error message only</option>
                </select>
            </div>

            <div v-if="currentUserIsAdmin" class="rl-fp-item">
                <select v-model="userFilter" class="rl-fp-select" @change="onFilterChange" aria-label="Editor">
                    <option value="">All editors</option>
                    <option v-for="u in userList" :key="u.id" :value="u.id">{{ u.name }} ({{ u.count }})</option>
                </select>
            </div>

            <button v-if="hasActiveFilters" class="rl-fp-reset" @click="resetFilters">
                <i class="fas fa-rotate-left"></i> Reset
            </button>
        </div>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="d-flex justify-content-center py-5">
        <span class="spinner-border text-primary"></span>
    </div>

    <!-- Empty -->
    <div v-else-if="items.length === 0" class="rl-empty">
        <div class="rl-empty-icon"><i class="fas fa-circle-check"></i></div>
        <p class="mb-0">No invalid rules found.</p>
    </div>

    <!-- Card view -->
    <div v-else-if="viewMode === 'card'" class="rl-cards">
        <div class="card h-100 shadow-sm border-0 mb-4 rl-rule-card" v-for="rule in items" :key="rule.id">
            <div class="premium-accent-line premium-accent-line--danger"></div>
            <div class="position-absolute top-0 end-0 mt-3 me-3 d-flex gap-2" style="z-index:2;">
                <span class="badge rounded-pill bg-dark pt-1 shadow-sm">{{ (rule.rule_type||'?').toUpperCase() }}</span>
            </div>
            <div class="card-body d-flex flex-column p-4" style="z-index:1;">
                <!-- Selection row -->
                <div v-if="isSelectable"
                     class="rl-card-check-row mb-3"
                     :class="{ 'rl-card-check-row--on': isSelected(rule) }"
                     @click.stop="toggleItem(rule)">
                    <input type="checkbox" class="rl-card-check-input"
                           :checked="isSelected(rule)"
                           @click.stop="toggleItem(rule)"
                           :aria-label="'Select ' + rule.file_name" />
                    <span class="rl-card-check-text">
                        {{ isSelected(rule) ? 'Selected' : 'Select this rule' }}
                    </span>
                    <i v-if="isSelected(rule)" class="fas fa-check ms-auto text-primary" style="font-size:.78rem;"></i>
                </div>
                <div class="mb-3 pe-5">
                    <h5 class="fw-bold mb-1 border-start border-danger border-4 ps-3">{{ rule.file_name }}</h5>
                    <div class="d-flex align-items-center gap-2 mt-2">
                        <user-chip v-if="colVisible.editor" :user-id="rule.user_id" :username="rule.editor_name" :avatar="rule.editor_avatar" size="xs"></user-chip>
                        <span v-if="colVisible.editor" class="text-muted opacity-50">|</span>
                        <small class="text-muted">{{ rule.created_at }}</small>
                    </div>
                </div>
                <p class="rl-card-desc mb-2 text-danger" style="-webkit-line-clamp:3;-webkit-box-orient:vertical;display:-webkit-box;overflow:hidden;">
                    <i class="fas fa-triangle-exclamation me-1"></i>{{ rule.error_message }}
                </p>
                <div class="rl-card-meta mb-3">
                    <span class="rl-meta-item rl-meta-item--source" :title="rule.url">
                        <i class="fas fa-link"></i><span>{{ rule.url || '—' }}</span>
                    </span>
                    <span v-if="rule.github_path" class="rl-meta-item" :title="rule.github_path">
                        <i class="fa-brands fa-github"></i><span>{{ rule.github_path }}</span>
                    </span>
                </div>
                <div class="d-flex justify-content-between align-items-center pt-3 border-top mt-auto">
                    <button class="btn btn-sm btn-outline-secondary rounded-pill" @click="toggleExpand(rule.id)">
                        <i class="fas fa-code me-1"></i>{{ expandedIds.has(rule.id) ? 'Hide' : 'View' }} content
                    </button>
                    <div class="d-flex gap-2" v-if="canManage(rule)">
                        <button class="btn btn-sm btn-primary rounded-pill" @click="fixRule(rule)">
                            <i class="fas fa-wrench me-1"></i>Fix
                        </button>
                        <button class="btn btn-sm btn-outline-danger rounded-pill" @click="deleteRule(rule)">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
                <code-viewer v-if="expandedIds.has(rule.id)" class="mt-3"
                    :code="rule.raw_content || ''" :language="rule.rule_type || 'text'"
                    :title="rule.file_name" max-height="320px">
                </code-viewer>
            </div>
        </div>
    </div>

    <!-- Table view -->
    <div v-else class="dt-table-wrap rl-table-wrap">
        <table class="dt-table" role="grid">
            <thead class="dt-thead">
                <tr>
                    <th v-if="isSelectable" class="dt-th dt-th--checkbox">
                        <input type="checkbox" class="dt-checkbox"
                               :checked="allOnPageSelected"
                               :indeterminate="someOnPageSelected"
                               @change="togglePageSelection"
                               aria-label="Select all on page" />
                    </th>
                    <th v-if="colVisible.format" class="dt-th dt-th--sortable" style="width:90px;" @click="setSort('rule_type')">
                        <div class="dt-th-inner">Format <i class="fas dt-sort-icon" :class="sortIcon('rule_type')"></i></div>
                    </th>
                    <th class="dt-th dt-th--sortable" @click="setSort('file_name')">
                        <div class="dt-th-inner">File <i class="fas dt-sort-icon" :class="sortIcon('file_name')"></i></div>
                    </th>
                    <th v-if="colVisible.editor" class="dt-th" style="width:160px;">Editor</th>
                    <th v-if="colVisible.error" class="dt-th dt-th--sortable" @click="setSort('error_message')">
                        <div class="dt-th-inner">Error message <i class="fas dt-sort-icon" :class="sortIcon('error_message')"></i></div>
                    </th>
                    <th v-if="colVisible.path" class="dt-th dt-th--sortable" style="width:180px;" @click="setSort('github_path')">
                        <div class="dt-th-inner">Path <i class="fas dt-sort-icon" :class="sortIcon('github_path')"></i></div>
                    </th>
                    <th v-if="colVisible.date" class="dt-th dt-th--sortable" style="width:140px;" @click="setSort('created_at')">
                        <div class="dt-th-inner">Date <i class="fas dt-sort-icon" :class="sortIcon('created_at')"></i></div>
                    </th>
                    <th class="dt-th dt-th--actions" style="width:130px;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <template v-for="rule in items" :key="rule.id">
                    <tr class="dt-row" :class="{ 'dt-row--selected': isSelected(rule) }">
                        <td v-if="isSelectable" class="dt-td dt-td--checkbox">
                            <input type="checkbox" class="dt-checkbox"
                                   :checked="isSelected(rule)"
                                   @change="toggleItem(rule)"
                                   :aria-label="'Select ' + rule.file_name" />
                        </td>
                        <td v-if="colVisible.format" class="dt-td"><span class="badge rounded-pill bg-dark pt-1 shadow-sm">{{ (rule.rule_type||'?').toUpperCase() }}</span></td>
                        <td class="dt-td" style="max-width:220px;word-break:break-word;">{{ rule.file_name }}</td>
                        <td v-if="colVisible.editor" class="dt-td"><user-chip :user-id="rule.user_id" :username="rule.editor_name" :avatar="rule.editor_avatar" size="xs"></user-chip></td>
                        <td v-if="colVisible.error" class="dt-td dt-td--truncate text-danger" style="font-size:.8rem;">{{ rule.error_message }}</td>
                        <td v-if="colVisible.path" class="dt-td" style="font-size:.78rem;color:var(--subtle-text-color);">{{ rule.github_path || '—' }}</td>
                        <td v-if="colVisible.date" class="dt-td" style="font-size:.78rem;">{{ rule.created_at }}</td>
                        <td class="dt-td dt-td--actions">
                            <div class="dt-actions">
                                <button class="dt-action-btn dt-action-btn--expand" :class="{'is-expanded': expandedIds.has(rule.id)}"
                                        title="View content" @click="toggleExpand(rule.id)">
                                    <i class="fas fa-chevron-down dt-expand-chevron" style="font-size:.65rem;"></i>
                                </button>
                                <template v-if="canManage(rule)">
                                    <button class="dt-action-btn" style="color:#0d6efd;" @click="fixRule(rule)" title="Fix"><i class="fas fa-wrench"></i></button>
                                    <button class="dt-action-btn" style="color:#dc3545;" @click="deleteRule(rule)" title="Delete"><i class="fas fa-trash"></i></button>
                                </template>
                            </div>
                        </td>
                    </tr>
                    <tr v-if="expandedIds.has(rule.id)" :key="'exp-'+rule.id" class="dt-row-expand">
                        <td :colspan="tableColspan" class="dt-expand-cell p-0">
                            <div class="rl-expand-wrap p-3">
                                <code-viewer :code="rule.raw_content || ''" :language="rule.rule_type || 'text'"
                                    :title="rule.file_name" max-height="320px">
                                </code-viewer>
                            </div>
                        </td>
                    </tr>
                </template>
            </tbody>
        </table>
    </div>

    <pagination-component v-if="!loading && items.length" :current-page="currentPage" :total-pages="totalPages"
        @change-page="fetchData">
    </pagination-component>

    <!-- ── Bulk bar (sticky bottom, mode='manage' only) ── -->
    <transition name="rl-bulk-slide">
        <div v-if="showBulkBar" class="rl-bulk-bar">
            <span class="rl-bulk-count">
                {{ selectionCount }} {{ selectionCount === 1 ? 'rule' : 'rules' }} selected
            </span>
            <div class="rl-bulk-actions">
                <button v-for="action in bulkActions" :key="action.key"
                        class="rl-bulk-btn"
                        :class="{ 'rl-bulk-btn--danger': action.variant === 'danger' }"
                        @click="emitBulkAction(action.key)">
                    <i v-if="action.icon" :class="'fas ' + action.icon"></i>
                    {{ action.label }}
                </button>
            </div>
            <button class="rl-bulk-clear" @click="clearSelection">
                <i class="fas fa-xmark"></i> Clear
            </button>
        </div>
    </transition>
</div>
    `,
}
