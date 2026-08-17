/**
 * log-table.js — Specialised table component for activity logs.
 *
 * Props:
 *   fetchUrl     String  (required) — API endpoint, e.g. "/admin/get_logs_page"
 *   canDelete    Boolean (default: false) — show delete / bulk-delete controls
 *   canModerate  Boolean (default: false) — show the Visibility column (per-row
 *                public/admin-only toggle) and bulk visibility actions
 *   csrfToken    String  (default: '') — CSRF token for state-changing requests
 *
 * Events:
 *   delete(log)                          — single-row delete requested
 *   bulk-delete(uuids[])                 — bulk delete requested
 *   edit(log)                            — edit icon clicked
 *   toggle-visibility(log)               — per-row visibility toggle clicked
 *   bulk-set-visibility(uuids[], isPublic) — bulk "set public/admin only" requested
 *
 * Exposed:
 *   fetchData()            — re-fetch current page
 */

import PaginationComponent from '/static/js/rule/paginationComponent.js'
import CodeViewer         from '/static/js/components/code-viewer.js'

const { ref, computed, onMounted } = Vue

// ── Static data ───────────────────────────────────────────────────────────────

const CATEGORIES = [
    { value: '',          label: 'All',       icon: 'fa-list'          },
    { value: 'rule',      label: 'Rule',      icon: 'fa-file-shield'   },
    { value: 'bundle',    label: 'Bundle',    icon: 'fa-box'           },
    { value: 'user',      label: 'User',      icon: 'fa-user'          },
    { value: 'admin',     label: 'Admin',     icon: 'fa-crown'         },
    { value: 'tag',       label: 'Tag',       icon: 'fa-tag'           },
    { value: 'job',       label: 'Job',       icon: 'fa-gears'         },
    { value: 'github',    label: 'GitHub',    icon: 'fa-brands fa-github' },
    { value: 'connector', label: 'Connector', icon: 'fa-plug'          },
    { value: 'comment',   label: 'Comment',   icon: 'fa-comment'       },
    { value: 'api',       label: 'API',       icon: 'fa-code'          },
    { value: 'system',    label: 'System',    icon: 'fa-gear'          },
]

const LEVELS = [
    { value: '',        label: 'All'     },
    { value: 'info',    label: 'Info'    },
    { value: 'success', label: 'Success' },
    { value: 'warning', label: 'Warning' },
    { value: 'error',   label: 'Error'   },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function getCategoryIcon(cat) {
    const found = CATEGORIES.find(c => c.value === cat)
    return found ? found.icon : 'fa-circle'
}

function getInitials(name) {
    if (!name || name === 'System') return '?'
    const parts = name.trim().split(/\s+/)
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase()
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase()
}

function formatRelative(val) {
    if (!val) return '—'
    const diff = Math.floor((Date.now() - new Date(val).getTime()) / 1000)
    if (diff < 60)    return `${diff}s ago`
    if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
    return `${Math.floor(diff / 86400)}d ago`
}

function formatFull(val) {
    if (!val) return ''
    return new Date(val).toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
}

// ── Component ─────────────────────────────────────────────────────────────────

export default {
    name: 'LogTable',
    components: { 'pagination-component': PaginationComponent, 'code-viewer': CodeViewer },

    props: {
        fetchUrl:    { type: String,  required: true },
        canDelete:   { type: Boolean, default: false },
        canModerate: { type: Boolean, default: false },
        csrfToken:   { type: String,  default: '' },
    },

    emits: ['delete', 'bulk-delete', 'edit', 'toggle-visibility', 'bulk-set-visibility'],

    setup(props, { emit, expose }) {

        // ── State ─────────────────────────────────────────────────────────────
        const items        = ref([])
        const total        = ref(0)
        const total_pages  = ref(1)
        const loading      = ref(false)
        const page         = ref(1)
        const per_page     = ref(25)
        const sort_key     = ref('created_at')
        const sort_dir     = ref('desc')
        const search       = ref('')
        const active_cat   = ref('')
        const active_level = ref('')
        const date_from    = ref('')
        const date_to      = ref('')
        const expanded_id  = ref(null)
        const selected     = ref(new Set())
        const togglingUuid = ref(null)

        const colCount = computed(() =>
            (props.canDelete ? 8 : 7) + (props.canModerate ? 1 : 0)
        )

        // ── Fetch ─────────────────────────────────────────────────────────────
        async function fetchData() {
            loading.value = true
            try {
                const params = new URLSearchParams({
                    page:     page.value,
                    per_page: per_page.value,
                    sort:     sort_key.value,
                    dir:      sort_dir.value,
                })
                if (search.value)       params.set('search',    search.value)
                if (active_cat.value)   params.set('category',  active_cat.value)
                if (active_level.value) params.set('level',     active_level.value)
                if (date_from.value)    params.set('date_from', date_from.value)
                if (date_to.value)      params.set('date_to',   date_to.value)

                const res  = await fetch(`${props.fetchUrl}?${params}`)
                const data = await res.json()

                items.value       = data.items || data.logs || []
                total.value       = data.total       || 0
                total_pages.value = data.total_pages || 1

                const currentUuids = new Set(items.value.map(i => i.uuid))
                for (const uuid of [...selected.value]) {
                    if (!currentUuids.has(uuid)) selected.value.delete(uuid)
                }
                selected.value = new Set(selected.value)
            } catch (e) {
                console.error('[LogTable] fetch error:', e)
            } finally {
                loading.value = false
                togglingUuid.value = null
            }
        }

        // ── Sort ──────────────────────────────────────────────────────────────
        function toggleSort(key) {
            if (sort_key.value === key) {
                sort_dir.value = sort_dir.value === 'asc' ? 'desc' : 'asc'
            } else {
                sort_key.value = key
                sort_dir.value = 'desc'
            }
            page.value = 1
            fetchData()
        }

        function sortIcon(key) {
            if (sort_key.value !== key) return 'fa-sort'
            return sort_dir.value === 'asc' ? 'fa-sort-up' : 'fa-sort-down'
        }

        // ── Filters ───────────────────────────────────────────────────────────
        let _searchTimer = null
        function onSearch() {
            clearTimeout(_searchTimer)
            _searchTimer = setTimeout(() => { page.value = 1; fetchData() }, 300)
        }

        function clearSearch() { search.value = ''; page.value = 1; fetchData() }

        function setCategory(val) { active_cat.value = val; page.value = 1; fetchData() }

        function setLevel(val) { active_level.value = val; page.value = 1; fetchData() }

        function onDateChange() { page.value = 1; fetchData() }

        function clearDates() { date_from.value = ''; date_to.value = ''; page.value = 1; fetchData() }

        function onPerPageChange() { page.value = 1; fetchData() }

        // ── Pagination ────────────────────────────────────────────────────────
        function handlePageChange(p) { page.value = p; fetchData() }

        // ── Expand row ────────────────────────────────────────────────────────
        function toggleExpand(uuid) {
            expanded_id.value = expanded_id.value === uuid ? null : uuid
        }

        // ── Selection ─────────────────────────────────────────────────────────
        const all_page_selected = computed(() => {
            if (!items.value.length) return false
            return items.value.every(i => selected.value.has(i.uuid))
        })

        function toggleAll() {
            if (all_page_selected.value) {
                items.value.forEach(i => selected.value.delete(i.uuid))
            } else {
                items.value.forEach(i => selected.value.add(i.uuid))
            }
            selected.value = new Set(selected.value)
        }

        function toggleOne(uuid) {
            if (selected.value.has(uuid)) selected.value.delete(uuid)
            else selected.value.add(uuid)
            selected.value = new Set(selected.value)
        }

        function clearSelection() { selected.value = new Set() }

        // ── Emit events ───────────────────────────────────────────────────────
        function requestDelete(log) { emit('delete', log) }
        function requestBulkDelete() { emit('bulk-delete', [...selected.value]) }
        function requestEdit(log) { emit('edit', log) }
        function requestToggleVisibility(log) {
            togglingUuid.value = log.uuid
            emit('toggle-visibility', log)
        }
        function requestBulkVisibility(isPublic) { emit('bulk-set-visibility', [...selected.value], isPublic) }

        // ── Lifecycle ─────────────────────────────────────────────────────────
        onMounted(() => fetchData())
        expose({ fetchData })

        return {
            items, total, total_pages, loading, page, per_page,
            sort_key, sort_dir, search, active_cat, active_level,
            date_from, date_to,
            expanded_id, selected, all_page_selected, togglingUuid, colCount,
            CATEGORIES, LEVELS,
            getCategoryIcon, getInitials, formatRelative, formatFull,
            fetchData, toggleSort, sortIcon,
            onSearch, clearSearch, setCategory, setLevel, onPerPageChange,
            onDateChange, clearDates,
            handlePageChange, toggleExpand,
            toggleAll, toggleOne, clearSelection,
            requestDelete, requestBulkDelete, requestEdit,
            requestToggleVisibility, requestBulkVisibility,
        }
    },

    template: `
<div class="lt-wrapper">

    <!-- Loading overlay -->
    <div v-if="loading" class="lt-loading-overlay">
        <div class="lt-spinner"></div>
    </div>

    <!-- Filters bar -->
    <div class="lt-filters">

        <!-- Search -->
        <div class="lt-search">
            <i class="fas fa-magnifying-glass lt-search-icon"></i>
            <input
                class="lt-search-input"
                type="text"
                placeholder="Search title, action, description…"
                v-model="search"
                @input="onSearch"
            />
            <button v-if="search" class="lt-search-clear" @click="clearSearch" title="Clear search">
                <i class="fas fa-xmark"></i>
            </button>
        </div>

        <div class="lt-filter-sep d-none d-sm-block"></div>

        <!-- Category pills -->
        <div class="lt-filter-group">
            <button
                v-for="cat in CATEGORIES"
                :key="cat.value"
                class="lt-pill"
                :class="{ active: active_cat === cat.value }"
                @click="setCategory(cat.value)">
                <i :class="['fas', cat.icon]" style="font-size:.65rem;"></i>
                {{ cat.label }}
            </button>
        </div>

        <div class="lt-filter-sep d-none d-sm-block"></div>

        <!-- Level pills -->
        <div class="lt-filter-group">
            <button
                v-for="lv in LEVELS"
                :key="lv.value"
                class="lt-level-pill"
                :class="['lt-level-pill--' + (lv.value || 'all'), { active: active_level === lv.value }]"
                @click="setLevel(lv.value)">
                {{ lv.label }}
            </button>
        </div>

        <div class="lt-filter-sep d-none d-sm-block"></div>

        <!-- Date range -->
        <div class="lt-date-range">
            <i class="fas fa-calendar-days lt-date-icon"></i>
            <input
                type="date"
                class="lt-date-input"
                v-model="date_from"
                @change="onDateChange"
                title="From date"
            />
            <span class="lt-date-sep">→</span>
            <input
                type="date"
                class="lt-date-input"
                v-model="date_to"
                @change="onDateChange"
                title="To date"
            />
            <button v-if="date_from || date_to" class="lt-date-clear" @click="clearDates" title="Clear dates">
                <i class="fas fa-xmark"></i>
            </button>
        </div>

    </div>

    <!-- Bulk action bar -->
    <div v-if="selected.size > 0" class="lt-bulk-bar">
        <span class="lt-bulk-bar-count">{{ selected.size }} selected</span>
        <div class="lt-bulk-bar-actions">
            <button v-if="canModerate" class="lt-bulk-btn" @click="requestBulkVisibility(true)">
                <i class="fa-solid fa-eye"></i> Set public
            </button>
            <button v-if="canModerate" class="lt-bulk-btn" @click="requestBulkVisibility(false)">
                <i class="fa-solid fa-eye-slash"></i> Set admin only
            </button>
            <button v-if="canDelete" class="lt-bulk-btn lt-bulk-btn--danger" @click="requestBulkDelete">
                <i class="fas fa-trash-can"></i> Delete selected
            </button>
            <button class="lt-bulk-btn lt-bulk-btn--clear" @click="clearSelection">
                <i class="fas fa-xmark"></i> Clear
            </button>
        </div>
    </div>

    <!-- Table -->
    <div class="lt-table-wrap">
        <table class="lt-table">
            <thead class="lt-thead">
                <tr>
                    <th class="lt-th lt-th--check" v-if="canDelete">
                        <input type="checkbox" class="lt-checkbox"
                               :checked="all_page_selected"
                               @change="toggleAll" />
                    </th>
                    <th class="lt-th lt-th--level"></th>
                    <th class="lt-th lt-th--cat lt-th--sortable"
                        :class="{ 'lt-th--sorted': sort_key === 'category' }"
                        @click="toggleSort('category')">
                        <span class="lt-th-inner">
                            Category
                            <i :class="['fas', sortIcon('category'), 'lt-th-sort-icon']"></i>
                        </span>
                    </th>
                    <th class="lt-th lt-th--event lt-th--sortable"
                        :class="{ 'lt-th--sorted': sort_key === 'action' }"
                        @click="toggleSort('action')">
                        <span class="lt-th-inner">
                            Event
                            <i :class="['fas', sortIcon('action'), 'lt-th-sort-icon']"></i>
                        </span>
                    </th>
                    <th class="lt-th lt-th--actor">Actor</th>
                    <th class="lt-th lt-th--visibility" v-if="canModerate">Visibility</th>
                    <th class="lt-th lt-th--date lt-th--sortable"
                        :class="{ 'lt-th--sorted': sort_key === 'created_at' }"
                        @click="toggleSort('created_at')">
                        <span class="lt-th-inner">
                            Date
                            <i :class="['fas', sortIcon('created_at'), 'lt-th-sort-icon']"></i>
                        </span>
                    </th>
                    <th class="lt-th lt-th--ua lt-td--ua">Agent</th>
                    <th class="lt-th lt-th--expand"></th>
                </tr>
            </thead>

            <tbody>

                <!-- Empty state -->
                <tr v-if="!items.length && !loading">
                    <td :colspan="colCount" class="lt-empty">
                        <i class="fas fa-scroll lt-empty-icon"></i>
                        <div class="lt-empty-text">No logs found</div>
                    </td>
                </tr>

                <template v-for="log in items" :key="log.uuid">

                    <!-- Main row -->
                    <tr class="lt-row"
                        :class="{
                            'lt-row--selected': selected.has(log.uuid),
                            'lt-row--error':    log.level === 'error',
                            'lt-row--warning':  log.level === 'warning',
                        }">

                        <!-- Checkbox -->
                        <td class="lt-td lt-td--check" v-if="canDelete">
                            <input type="checkbox" class="lt-checkbox"
                                   :checked="selected.has(log.uuid)"
                                   @change="toggleOne(log.uuid)" />
                        </td>

                        <!-- Level bar -->
                        <td class="lt-td lt-td--level" style="padding:0;width:4px;">
                            <span :class="['lt-level-bar', 'lt-level-bar--' + log.level]"></span>
                        </td>

                        <!-- Category -->
                        <td class="lt-td">
                            <span :class="['lt-category-badge', 'lt-category-badge--' + log.category]">
                                <i :class="['fas', getCategoryIcon(log.category)]" style="font-size:.6rem;"></i>
                                {{ log.category }}
                            </span>
                        </td>

                        <!-- Event: title + action -->
                        <td class="lt-td">
                            <span class="lt-event-title" :title="log.title || log.description">{{ log.title || log.action }}</span>
                            <span class="lt-event-action">{{ log.action }}</span>
                        </td>

                        <!-- Actor -->
                        <td class="lt-td lt-td--actor">
                            <a v-if="log.actor_name && log.actor_name !== 'System' && log.user_id"
                               :href="'/account/detail_user/' + log.user_id"
                               class="lt-actor lt-actor--link"
                               target="_blank">
                                <div class="lt-actor-avatar">{{ getInitials(log.actor_name) }}</div>
                                <span class="lt-actor-name" :title="log.actor_name">{{ log.actor_name }}</span>
                            </a>
                            <span v-else class="lt-actor-none">System</span>
                        </td>

                        <!-- Visibility -->
                        <td class="lt-td lt-td--visibility" v-if="canModerate">
                            <button type="button"
                                    class="lt-vis-btn"
                                    :class="log.is_public ? 'lt-vis-btn--public' : 'lt-vis-btn--private'"
                                    :disabled="togglingUuid === log.uuid"
                                    :title="log.is_public ? 'Click to make admin-only' : 'Click to make public'"
                                    @click="requestToggleVisibility(log)">
                                <i :class="log.is_public ? 'fa-solid fa-eye' : 'fa-solid fa-eye-slash'"></i>
                                {{ log.is_public ? 'Public' : 'Private' }}
                            </button>
                        </td>

                        <!-- Date -->
                        <td class="lt-td lt-td--date" :title="formatFull(log.created_at)">
                            {{ formatRelative(log.created_at) }}
                        </td>

                        <!-- User agent -->
                        <td class="lt-td lt-td--ua">
                            <span class="lt-ua-text" :title="log.user_agent">
                                {{ log.user_agent || '—' }}
                            </span>
                        </td>

                        <!-- Expand / edit / delete -->
                        <td class="lt-td" style="text-align:center;padding:.4rem .3rem;white-space:nowrap;">
                            <button class="lt-edit-btn" @click.stop="requestEdit(log)" title="Edit">
                                <i class="fas fa-pen"></i>
                            </button>
                            <button v-if="canDelete"
                                    class="lt-delete-btn"
                                    @click.stop="requestDelete(log)"
                                    title="Delete">
                                <i class="fas fa-trash-can"></i>
                            </button>
                            <button class="lt-expand-btn"
                                    :class="{ active: expanded_id === log.uuid }"
                                    @click="toggleExpand(log.uuid)"
                                    :title="expanded_id === log.uuid ? 'Collapse' : 'Expand'">
                                <i class="fas fa-chevron-right"></i>
                            </button>
                        </td>

                    </tr>

                    <!-- Expanded detail row -->
                    <tr v-if="expanded_id === log.uuid" class="lt-row-expand">
                        <td :colspan="colCount" class="lt-expand-cell">
                            <div class="lt-expand-content">

                                <div class="lt-expand-grid">
                                    <div class="lt-expand-field">
                                        <span class="lt-expand-label">UUID</span>
                                        <span class="lt-expand-value lt-mono">{{ log.uuid }}</span>
                                    </div>
                                    <div class="lt-expand-field" v-if="log.target_type">
                                        <span class="lt-expand-label">Target type</span>
                                        <span class="lt-expand-value lt-mono">{{ log.target_type }}</span>
                                    </div>
                                    <div class="lt-expand-field" v-if="log.target_id">
                                        <span class="lt-expand-label">Target ID</span>
                                        <span class="lt-expand-value lt-mono">{{ log.target_id }}</span>
                                    </div>
                                    <div class="lt-expand-field" v-if="log.ip_address">
                                        <span class="lt-expand-label">IP Address</span>
                                        <span class="lt-expand-value lt-mono">{{ log.ip_address }}</span>
                                    </div>
                                    <div class="lt-expand-field">
                                        <span class="lt-expand-label">Level</span>
                                        <span class="lt-expand-value" style="text-transform:capitalize;">{{ log.level }}</span>
                                    </div>
                                    <div class="lt-expand-field">
                                        <span class="lt-expand-label">Visibility</span>
                                        <span class="lt-expand-value">{{ log.is_public ? 'Public' : 'Admin only' }}</span>
                                    </div>
                                    <div class="lt-expand-field">
                                        <span class="lt-expand-label">Method</span>
                                        <span class="lt-expand-value lt-mono">{{ log.method || '—' }}</span>
                                    </div>
                                    <div class="lt-expand-field">
                                        <span class="lt-expand-label">Created at</span>
                                        <span class="lt-expand-value lt-mono">{{ formatFull(log.created_at) }}</span>
                                    </div>
                                </div>

                                <div v-if="log.description" class="lt-expand-field">
                                    <span class="lt-expand-label">Description</span>
                                    <p class="lt-expand-desc">{{ log.description }}</p>
                                </div>

                                <div v-if="log.url" class="lt-expand-field">
                                    <span class="lt-expand-label">URL</span>
                                    <p class="lt-expand-desc lt-mono" style="font-size:.72rem;">{{ log.method }} {{ log.url }}</p>
                                </div>

                                <div v-if="log.user_agent" class="lt-expand-field">
                                    <span class="lt-expand-label">User agent</span>
                                    <p class="lt-expand-desc lt-mono" style="font-size:.72rem;">{{ log.user_agent }}</p>
                                </div>

                                <div v-if="log.extra" class="lt-expand-field">
                                    <span class="lt-expand-label">Extra data</span>
                                    <code-viewer
                                        :code="JSON.stringify(log.extra, null, 2)"
                                        language="json"
                                        max-height="320px"
                                        :show-lines="false">
                                    </code-viewer>
                                </div>

                            </div>
                        </td>
                    </tr>

                </template>

            </tbody>
        </table>
    </div>

    <!-- Footer -->
    <div class="lt-footer">
        <span class="lt-info">
            {{ total }} log{{ total !== 1 ? 's' : '' }}
            <template v-if="total > per_page">
                — page {{ page }} / {{ total_pages }}
            </template>
        </span>
        <div class="lt-footer-right">
            <div class="lt-per-page">
                <span>Per page</span>
                <select class="lt-per-page-select" v-model.number="per_page" @change="onPerPageChange">
                    <option>10</option>
                    <option>25</option>
                    <option>50</option>
                    <option>100</option>
                </select>
            </div>
            <pagination-component
                :current-page="page"
                :total-pages="total_pages"
                @change-page="handlePageChange">
            </pagination-component>
        </div>
    </div>

</div>
    `,
}
