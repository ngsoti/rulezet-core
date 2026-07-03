/**
 * data-table.js — Generic data table component
 *
 * Props:
 *   fetchUrl        String  (required) — URL for paginated data
 *   mode            String  'read' | 'select' | 'manage'   (default: 'manage')
 *   columns         Array   (required) — column definitions
 *   canCreate       Boolean (default: false)
 *   canEdit         Boolean (default: false)
 *   canDelete       Boolean (default: false)
 *   canView         Boolean (default: false)
 *   bulkActions     Array   [{key, label, icon?, variant?}]
 *   defaultView     String  'table' | 'card'               (default: 'table')
 *   initialPerPage  Number  (default: 10)
 *   sendUrl         String  — used when mode='select'
 *
 * Column definition:
 *   { key, label, sortable, truncate, type, width }
 *   type: 'text' | 'date' | 'boolean' | 'badge' | 'avatar'
 *
 * Events emitted:
 *   create        — create button clicked
 *   edit(item)    — edit clicked
 *   delete(item)  — delete clicked
 *   view(item)    — view clicked
 *   bulk-action({ action, ids })
 *   send(ids)     — mode='select' confirm
 *
 * Slots:
 *   #cell-{key}="{ item, value, search, highlight }"  — custom cell render
 *   #card-title="{ item, search, highlight }"         — custom card header title
 *   #card-body="{ item, search, highlight }"          — custom card body
 *   #expand="{ item }"             — content of expanded row
 *   #toolbar-start                 — extra controls, left of the view toggle
 *   #below-toolbar                 — extra content spanning below the toolbar row
 *
 * Exposed method:
 *   fetchData()   — re-fetch current page (call via template ref)
 */

import { apiFetch }      from '/static/js/constants.js'
import Pagination from '/static/js/rule/paginationComponent.js'

const { ref, reactive, computed, watch, onMounted, onUnmounted, nextTick } = Vue

export default {
    name: 'DataTable',
    components: { Pagination },

    props: {
        fetchUrl:       { type: String,  required: true },
        mode:           { type: String,  default: 'manage' },   // 'read' | 'select' | 'manage'
        columns:        { type: Array,   required: true },
        canCreate:      { type: Boolean, default: false },
        canEdit:        { type: Boolean, default: false },
        canDelete:      { type: Boolean, default: false },
        canView:        { type: Boolean, default: false },
        bulkActions:    { type: Array,   default: () => [] },
        defaultView:    { type: String,  default: 'table' },
        initialPerPage: { type: Number,  default: 10 },
        initialSort:    { type: String,  default: '' },
        initialDir:     { type: String,  default: 'asc' },
        sendUrl:        { type: String,  default: null },
    },

    emits: ['create', 'edit', 'delete', 'view', 'bulk-action', 'send'],

    expose: ['fetchData'],

    template: `
        <div class="dt-wrapper" :class="{ 'dt-wrapper--bulk-open': showBulkBar }">

            <!-- Loading overlay -->
            <div v-if="loading" class="dt-loading-overlay" aria-live="polite">
                <div class="dt-spinner"></div>
            </div>

            <!-- Toolbar -->
            <div class="dt-toolbar">
                <div class="dt-toolbar-left">
                    <!-- Search -->
                    <div class="dt-search">
                        <i class="fas fa-search dt-search-icon"></i>
                        <input
                            class="dt-search-input"
                            type="text"
                            placeholder="Search…"
                            v-model="search"
                            @input="onSearchInput"
                            aria-label="Search" />
                        <button
                            v-if="search"
                            class="dt-search-clear"
                            @click="clearSearch"
                            aria-label="Clear search">
                            <i class="fas fa-xmark"></i>
                        </button>
                    </div>
                </div>

                <div class="dt-toolbar-right">
                    <slot name="toolbar-start"></slot>

                    <!-- View toggle -->
                    <div class="dt-view-toggle" title="Switch view">
                        <button
                            class="dt-view-btn"
                            :class="{ 'dt-view-btn--active': view_mode === 'table' }"
                            @click="view_mode = 'table'"
                            aria-label="Table view">
                            <i class="fas fa-table-cells-large"></i>
                        </button>
                        <button
                            class="dt-view-btn"
                            :class="{ 'dt-view-btn--active': view_mode === 'card' }"
                            @click="view_mode = 'card'"
                            aria-label="Card view">
                            <i class="fas fa-grip"></i>
                        </button>
                    </div>

                    <!-- Column picker (table mode only) -->
                    <div v-if="view_mode === 'table'" class="dt-col-picker-wrap" ref="colPickerRef">
                        <button
                            class="dt-toolbar-btn"
                            :class="{ 'dt-toolbar-btn--active': show_col_picker }"
                            @click="show_col_picker = !show_col_picker"
                            title="Show/hide columns">
                            <i class="fas fa-sliders"></i>
                        </button>
                        <div v-if="show_col_picker" class="dt-col-picker-dropdown">
                            <label
                                v-for="col in columns"
                                :key="col.key"
                                class="dt-col-picker-item">
                                <input
                                    type="checkbox"
                                    :checked="!hidden_columns.has(col.key)"
                                    @change="toggleColumn(col.key)" />
                                {{ col.label || col.key }}
                            </label>
                        </div>
                    </div>

                    <!-- Create button -->
                    <button
                        v-if="canCreate"
                        class="dt-toolbar-btn dt-toolbar-btn--primary"
                        @click="$emit('create')">
                        <i class="fas fa-plus"></i>
                        <span>New</span>
                    </button>

                    <!-- Select / Send button (mode='select') -->
                    <button
                        v-if="mode === 'select'"
                        class="dt-toolbar-btn dt-toolbar-btn--primary"
                        :disabled="selected_ids.size === 0 && !all_pages_selected"
                        @click="emitSend">
                        <i class="fas fa-check"></i>
                        <span>Select {{ selectionCount > 0 ? '(' + selectionCount + ')' : '' }}</span>
                    </button>
                </div>
            </div>

            <!-- Extra content below the toolbar, e.g. a collapsible filter panel -->
            <slot name="below-toolbar"></slot>

            <!-- Select-all-pages banner -->
            <div v-if="showSelectAllBanner" class="dt-select-all-banner">
                <span v-if="!all_pages_selected">
                    All {{ items.length }} items on this page are selected.
                </span>
                <span v-else>
                    All {{ total }} items are selected.
                </span>
                <button
                    v-if="!all_pages_selected"
                    class="dt-select-all-btn"
                    @click="selectAllPages">
                    Select all {{ total }} items
                </button>
                <button class="dt-select-all-btn" @click="clearSelection">
                    Clear selection
                </button>
            </div>

            <!-- ── TABLE VIEW ── -->
            <div v-if="view_mode === 'table'" class="dt-table-wrap">
                <table class="dt-table" role="grid">
                    <thead class="dt-thead">
                        <tr>
                            <!-- Select checkbox -->
                            <th v-if="isSelectable" class="dt-th dt-th--checkbox">
                                <input
                                    type="checkbox"
                                    class="dt-checkbox"
                                    :checked="all_on_page_selected"
                                    :indeterminate="some_on_page_selected"
                                    @change="togglePageSelection"
                                    aria-label="Select all on page" />
                            </th>

                            <!-- Columns -->
                            <th
                                v-for="col in visible_columns"
                                :key="col.key"
                                class="dt-th"
                                :class="{
                                    'dt-th--sortable': col.sortable,
                                    'dt-th--sorted': sort_key === col.key,
                                }"
                                :style="col.width ? { width: col.width } : {}"
                                @click="col.sortable ? setSort(col.key) : null">
                                <div class="dt-th-inner">
                                    <span class="text-truncate">{{ col.label }}</span>
                                    <i
                                        v-if="col.sortable"
                                        class="fas dt-sort-icon"
                                        :class="sortIcon(col.key)"></i>
                                </div>
                            </th>

                            <!-- Actions column -->
                            <th v-if="hasActions" class="dt-th dt-th--actions" style="width:120px;">
                                Actions
                            </th>
                        </tr>
                    </thead>

                    <tbody>
                        <!-- Empty state -->
                        <tr v-if="!loading && items.length === 0">
                            <td :colspan="colSpan">
                                <div class="dt-empty">
                                    <div class="dt-empty-icon">
                                        <i class="fas fa-table"></i>
                                    </div>
                                    <p class="dt-empty-text">No results found</p>
                                </div>
                            </td>
                        </tr>

                        <template v-for="item in items" :key="item.id">
                            <!-- Data row -->
                            <tr
                                class="dt-row"
                                :class="{
                                    'dt-row--selected': isSelected(item),
                                    'dt-row--expanded': expanded_id === item.id,
                                }">

                                <!-- Checkbox -->
                                <td v-if="isSelectable" class="dt-td dt-td--checkbox">
                                    <input
                                        type="checkbox"
                                        class="dt-checkbox"
                                        :checked="isSelected(item)"
                                        @change="toggleItem(item)"
                                        :aria-label="'Select row ' + item.id" />
                                </td>

                                <!-- Cells -->
                                <td
                                    v-for="col in visible_columns"
                                    :key="col.key"
                                    class="dt-td"
                                    :class="{ 'dt-td--truncate': col.truncate }"
                                    :style="col.width ? { width: col.width } : {}">
                                    <!-- Custom slot per column -->
                                    <slot
                                        v-if="$slots['cell-' + col.key]"
                                        :name="'cell-' + col.key"
                                        :item="item"
                                        :value="item[col.key]"
                                        :search="search"
                                        :highlight="highlight">
                                    </slot>
                                    <!-- Default rendering -->
                                    <template v-else>
                                        <span v-if="col.type === 'boolean'">
                                            <i
                                                :class="item[col.key]
                                                    ? 'fas fa-circle-check text-success'
                                                    : 'fas fa-circle-xmark text-danger'"
                                                style="font-size:.85rem;"></i>
                                        </span>
                                        <span v-else-if="col.type === 'date'">
                                            {{ formatDate(item[col.key]) }}
                                        </span>
                                        <span v-else :title="String(item[col.key] ?? '')"
                                            v-html="highlight(item[col.key] ?? '—')">
                                        </span>
                                    </template>
                                </td>

                                <!-- Actions -->
                                <td v-if="hasActions" class="dt-td dt-td--actions">
                                    <div class="dt-actions">
                                        <button
                                            v-if="canView"
                                            class="dt-action-btn"
                                            title="View"
                                            @click="$emit('view', item)">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                        <button
                                            v-if="canEdit"
                                            class="dt-action-btn"
                                            title="Edit"
                                            @click="$emit('edit', item)">
                                            <i class="fas fa-pencil"></i>
                                        </button>
                                        <button
                                            v-if="canDelete"
                                            class="dt-action-btn dt-action-btn--danger"
                                            title="Delete"
                                            @click="$emit('delete', item)">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                        <!-- Expand chevron -->
                                        <button
                                            class="dt-action-btn dt-action-btn--expand"
                                            :class="{ 'is-expanded': expanded_id === item.id }"
                                            title="Details"
                                            @click="toggleExpand(item)">
                                            <i class="fas fa-chevron-down dt-expand-chevron" style="font-size:.65rem;"></i>
                                        </button>
                                    </div>
                                </td>
                            </tr>

                            <!-- Expanded row -->
                            <tr
                                v-if="expanded_id === item.id"
                                class="dt-row-expand"
                                :key="'expand-' + item.id">
                                <td :colspan="colSpan" class="dt-expand-cell">
                                    <slot name="expand" :item="item">
                                        <!-- Default expand: show all column values in a grid -->
                                        <div class="dt-expand-grid">
                                            <div
                                                v-for="col in columns"
                                                :key="col.key"
                                                class="dt-expand-field">
                                                <label>{{ col.label || col.key }}</label>
                                                <span>{{ item[col.key] ?? '—' }}</span>
                                            </div>
                                        </div>
                                    </slot>
                                </td>
                            </tr>
                        </template>
                    </tbody>
                </table>
            </div>

            <!-- ── CARD VIEW ── -->
            <div v-else class="dt-card-grid">
                <!-- Empty state -->
                <div v-if="!loading && items.length === 0" style="grid-column: 1 / -1;">
                    <div class="dt-empty">
                        <div class="dt-empty-icon"><i class="fas fa-grip"></i></div>
                        <p class="dt-empty-text">No results found</p>
                    </div>
                </div>

                <div
                    v-for="item in items"
                    :key="item.id"
                    class="dt-card"
                    :class="{ 'dt-card--selected': isSelected(item) }">

                    <div class="dt-card-header">
                        <input
                            v-if="isSelectable"
                            type="checkbox"
                            class="dt-checkbox dt-card-checkbox"
                            :checked="isSelected(item)"
                            @change="toggleItem(item)" />
                        <slot name="card-title" :item="item" :search="search" :highlight="highlight">
                            <span class="dt-card-title" v-html="highlight(item[columns[0]?.key] ?? item.id)"></span>
                        </slot>
                    </div>

                    <div class="dt-card-body">
                        <slot name="card-body" :item="item" :search="search" :highlight="highlight">
                            <!-- Default: show first 3 non-first columns -->
                            <div
                                v-for="col in columns.slice(1, 4)"
                                :key="col.key"
                                style="font-size:.8rem;color:var(--text-secondary);">
                                <span style="color:var(--text-muted);font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;">{{ col.label }}</span>
                                <span style="display:block;color:var(--text-main);">{{ item[col.key] ?? '—' }}</span>
                            </div>
                        </slot>
                    </div>

                    <div class="dt-card-footer">
                        <button
                            v-if="canView"
                            class="dt-action-btn"
                            title="View"
                            @click="$emit('view', item)">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button
                            v-if="canEdit"
                            class="dt-action-btn"
                            title="Edit"
                            @click="$emit('edit', item)">
                            <i class="fas fa-pencil"></i>
                        </button>
                        <button
                            v-if="canDelete"
                            class="dt-action-btn dt-action-btn--danger"
                            title="Delete"
                            @click="$emit('delete', item)">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
            </div>

            <!-- Footer: per-page + pagination + info -->
            <div class="dt-footer">
                <div class="dt-per-page">
                    <span>Rows</span>
                    <select v-model="per_page_model" aria-label="Rows per page">
                        <option v-for="n in [10, 25, 50, 100]" :key="n" :value="n">{{ n }}</option>
                    </select>
                </div>

                <div class="dt-footer-center">
                    <pagination
                        :current-page="page"
                        :total-pages="total_pages"
                        @change-page="goToPage" />
                </div>

                <div class="dt-footer-info">
                    {{ footerInfo }}
                </div>
            </div>

            <!-- Bulk bar (sticky bottom) -->
            <transition name="dt-bulk-slide">
                <div v-if="showBulkBar" class="dt-bulk-bar">
                    <span class="dt-bulk-count">
                        {{ all_pages_selected ? total : selected_ids.size }}
                        {{ (all_pages_selected ? total : selected_ids.size) === 1 ? 'item' : 'items' }} selected
                    </span>
                    <div class="dt-bulk-actions">
                        <button
                            v-for="action in bulkActions"
                            :key="action.key"
                            class="dt-bulk-btn"
                            :class="action.variant === 'danger' ? 'dt-bulk-btn--danger' : ''"
                            @click="emitBulkAction(action.key)">
                            <i v-if="action.icon" :class="'fas ' + action.icon"></i>
                            {{ action.label }}
                        </button>
                    </div>
                    <button class="dt-bulk-clear" @click="clearSelection">
                        <i class="fas fa-xmark"></i> Clear
                    </button>
                </div>
            </transition>

        </div>
    `,

    setup(props, { emit }) {

        // ── State ────────────────────────────────────────────────────────
        const items         = ref([])
        const total         = ref(0)
        const total_pages   = ref(1)
        const loading       = ref(false)

        const page          = ref(1)
        const per_page      = ref(props.initialPerPage)
        const sort_key      = ref(props.initialSort)
        const sort_dir      = ref(props.initialDir)
        const search        = ref('')

        const selected_ids      = reactive(new Set())
        const all_pages_selected = ref(false)
        const view_mode         = ref(props.defaultView)
        const hidden_columns    = reactive(new Set())
        const show_col_picker   = ref(false)
        const expanded_id       = ref(null)

        let search_timer = null

        // ── Per-page as v-model wrapper ──────────────────────────────────
        const per_page_model = computed({
            get: () => per_page.value,
            set: (val) => {
                per_page.value = Number(val)
                page.value = 1
                fetchData()
            }
        })

        // ── Computed ─────────────────────────────────────────────────────
        const visible_columns = computed(() =>
            props.columns.filter(c => !hidden_columns.has(c.key))
        )

        const isSelectable = computed(() =>
            props.mode !== 'read' && (props.bulkActions.length > 0 || props.mode === 'select')
        )

        const hasActions = computed(() =>
            props.canEdit || props.canDelete || props.canView || props.mode !== 'read'
        )

        const colSpan = computed(() => {
            let n = visible_columns.value.length
            if (isSelectable.value) n++
            if (hasActions.value)   n++
            return n
        })

        const all_on_page_selected = computed(() => {
            if (!isSelectable.value || items.value.length === 0) return false
            return items.value.every(item => selected_ids.has(item.id))
        })

        const some_on_page_selected = computed(() => {
            if (!isSelectable.value) return false
            const count = items.value.filter(i => selected_ids.has(i.id)).length
            return count > 0 && count < items.value.length
        })

        const showSelectAllBanner = computed(() =>
            isSelectable.value && all_on_page_selected.value && total.value > items.value.length
        )

        const showBulkBar = computed(() =>
            isSelectable.value && (selected_ids.size > 0 || all_pages_selected.value)
        )

        const selectionCount = computed(() =>
            all_pages_selected.value ? total.value : selected_ids.size
        )

        const footerInfo = computed(() => {
            if (total.value === 0) return 'No results'
            const start = (page.value - 1) * per_page.value + 1
            const end   = Math.min(page.value * per_page.value, total.value)
            return `${start}–${end} of ${total.value}`
        })

        // ── Fetch ─────────────────────────────────────────────────────────
        async function fetchData() {
            loading.value = true
            try {
                const params = new URLSearchParams({
                    page:     page.value,
                    per_page: per_page.value,
                    search:   search.value,
                    sort:     sort_key.value,
                    dir:      sort_dir.value,
                })
                const sep = props.fetchUrl.includes('?') ? '&' : '?'
                const res = await apiFetch(`${props.fetchUrl}${sep}${params}`)
                if (!res.ok) {
                    loading.value = false
                    return
                }
                const data     = await res.json()
                items.value    = data.items      ?? []
                total.value    = data.total      ?? 0
                total_pages.value = data.total_pages ?? 1
                if (page.value > total_pages.value && total_pages.value > 0) {
                    page.value = total_pages.value
                }
            } finally {
                loading.value = false
            }
        }

        // ── Sorting ──────────────────────────────────────────────────────
        function setSort(key) {
            if (sort_key.value === key) {
                sort_dir.value = sort_dir.value === 'asc' ? 'desc' : 'asc'
            } else {
                sort_key.value = key
                sort_dir.value = 'asc'
            }
            page.value = 1
            fetchData()
        }

        function sortIcon(key) {
            if (sort_key.value !== key) return 'fa-sort'
            return sort_dir.value === 'asc' ? 'fa-sort-up' : 'fa-sort-down'
        }

        // ── Search ───────────────────────────────────────────────────────
        function onSearchInput() {
            clearTimeout(search_timer)
            search_timer = setTimeout(() => {
                page.value = 1
                fetchData()
            }, 350)
        }

        function clearSearch() {
            search.value = ''
            page.value = 1
            fetchData()
        }

        // ── Pagination ───────────────────────────────────────────────────
        function goToPage(p) {
            page.value = p
            fetchData()
        }

        // ── Selection ────────────────────────────────────────────────────
        function isSelected(item) {
            return all_pages_selected.value || selected_ids.has(item.id)
        }

        function toggleItem(item) {
            if (all_pages_selected.value) {
                all_pages_selected.value = false
                items.value.forEach(i => { if (i.id !== item.id) selected_ids.add(i.id) })
                return
            }
            if (selected_ids.has(item.id)) {
                selected_ids.delete(item.id)
            } else {
                selected_ids.add(item.id)
            }
        }

        function togglePageSelection() {
            if (all_pages_selected.value) {
                clearSelection()
                return
            }
            if (all_on_page_selected.value) {
                items.value.forEach(i => selected_ids.delete(i.id))
            } else {
                items.value.forEach(i => selected_ids.add(i.id))
            }
        }

        function selectAllPages() {
            all_pages_selected.value = true
        }

        function clearSelection() {
            selected_ids.clear()
            all_pages_selected.value = false
        }

        // ── Expand ───────────────────────────────────────────────────────
        function toggleExpand(item) {
            expanded_id.value = expanded_id.value === item.id ? null : item.id
        }

        // ── Column picker ────────────────────────────────────────────────
        function toggleColumn(key) {
            if (hidden_columns.has(key)) {
                hidden_columns.delete(key)
            } else {
                hidden_columns.add(key)
            }
        }

        const colPickerRef = ref(null)
        function handleOutsideClick(e) {
            if (colPickerRef.value && !colPickerRef.value.contains(e.target)) {
                show_col_picker.value = false
            }
        }

        onMounted(() => {
            fetchData()
            document.addEventListener('click', handleOutsideClick)
        })

        onUnmounted(() => {
            document.removeEventListener('click', handleOutsideClick)
            clearTimeout(search_timer)
        })

        // ── Bulk actions ─────────────────────────────────────────────────
        function emitBulkAction(action) {
            const ids = all_pages_selected.value ? 'ALL' : Array.from(selected_ids)
            emit('bulk-action', { action, ids })
        }

        function emitSend() {
            const ids = all_pages_selected.value ? 'ALL' : Array.from(selected_ids)
            emit('send', ids)
        }

        // ── Formatting ────────────────────────────────────────────────────
        function formatDate(val) {
            if (!val) return '—'
            try {
                return new Date(val).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
            } catch {
                return val
            }
        }

        // ── Search highlight ──────────────────────────────────────────────
        function escapeHtml(str) {
            return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
        }

        function escapeRegex(str) {
            return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
        }

        function highlight(text) {
            const str = String(text ?? '')
            if (!search.value || !str) return escapeHtml(str)
            try {
                const parts = str.split(new RegExp(`(${escapeRegex(search.value)})`, 'gi'))
                const term_lower = search.value.toLowerCase()
                return parts.map(part =>
                    part.toLowerCase() === term_lower
                        ? `<mark class="dt-highlight">${escapeHtml(part)}</mark>`
                        : escapeHtml(part)
                ).join('')
            } catch {
                return escapeHtml(str)
            }
        }

        return {
            items, total, total_pages, loading,
            page, per_page, per_page_model, sort_key, sort_dir, search,
            selected_ids, all_pages_selected,
            view_mode, hidden_columns, show_col_picker, expanded_id,
            colPickerRef,
            visible_columns, isSelectable, hasActions, colSpan,
            all_on_page_selected, some_on_page_selected,
            showSelectAllBanner, showBulkBar, selectionCount, footerInfo,
            fetchData, setSort, sortIcon,
            onSearchInput, clearSearch,
            goToPage,
            isSelected, toggleItem, togglePageSelection, selectAllPages, clearSelection,
            toggleExpand,
            toggleColumn,
            emitBulkAction, emitSend,
            formatDate, highlight,
        }
    }
}
