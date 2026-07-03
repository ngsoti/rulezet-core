/**
 * logDefinitionManager.js — Admin manager for activity-log action display metadata.
 * Card + table view, search, category filter, edit modal (icon/title/visibility), reset-to-default.
 * Modeled after formatList.js. No external imports beyond PaginationComponent.
 *
 * Expose: fetchData()
 */
import PaginationComponent from '/static/js/rule/paginationComponent.js'

const { ref, computed, onMounted } = Vue

const CATEGORIES = ['rule', 'bundle', 'comment', 'user', 'tag', 'job', 'github', 'admin', 'connector', 'api', 'system']

const LEVEL_BADGE = { info: 'bg-info text-dark', success: 'bg-success', warning: 'bg-warning text-dark', error: 'bg-danger' }

export default {
    name: 'LogDefinitionManager',
    components: { PaginationComponent },
    expose: ['fetchData'],

    props: {
        csrfToken: { type: String, default: '' },
    },

    template: `
    <div class="ld-wrapper">

        <!-- ── Toolbar ── -->
        <div class="ld-toolbar">
            <div class="ld-toolbar-left">
                <div class="dt-search">
                    <i class="fas fa-search dt-search-icon"></i>
                    <input class="dt-search-input" type="text" v-model="search"
                           placeholder="Search actions…" @input="onSearchInput" />
                    <button v-if="search" class="dt-search-clear" @click="clearSearch">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>
                <select class="form-select form-select-sm ld-cat-select" v-model="category" @change="onFilterChange">
                    <option value="">All categories</option>
                    <option v-for="c in categories" :key="c" :value="c">{{ c }}</option>
                </select>
                <span v-if="!loading" class="text-muted small ms-1 text-nowrap">
                    <strong>{{ total }}</strong> action<span v-if="total !== 1">s</span>
                </span>
            </div>
            <div class="ld-toolbar-right">
                <div class="dt-view-toggle">
                    <button class="dt-view-btn" :class="{ 'dt-view-btn--active': viewMode === 'card' }"
                            @click="viewMode = 'card'">
                        <i class="fas fa-grip"></i>
                    </button>
                    <button class="dt-view-btn" :class="{ 'dt-view-btn--active': viewMode === 'table' }"
                            @click="viewMode = 'table'">
                        <i class="fas fa-table-cells-large"></i>
                    </button>
                </div>
                <div v-if="viewMode === 'table'" class="rl-per-page">
                    <span>Rows</span>
                    <select v-model="perPageModel">
                        <option v-for="n in [10, 20, 50]" :key="n" :value="n">{{ n }}</option>
                    </select>
                </div>
            </div>
        </div>

        <!-- ── Loading ── -->
        <div v-if="loading" class="rl-loading">
            <div class="spinner-border text-primary"></div>
        </div>

        <!-- ── Empty ── -->
        <div v-else-if="items.length === 0" class="rl-empty">
            <div class="rl-empty-icon"><i class="fas fa-scroll"></i></div>
            <p class="mb-0">No actions found.</p>
        </div>

        <!-- ═══════ CARD VIEW ═══════ -->
        <div v-else-if="viewMode === 'card'" class="ld-cards">
            <div v-for="a in items" :key="a.action_key" class="ld-card">
                <div class="ld-card-accent"></div>
                <div class="ld-card-top">
                    <div class="ld-card-icon"><i :class="a.icon"></i></div>
                    <div class="ld-card-badges">
                        <span class="badge rounded-pill ld-cat-badge">{{ a.category }}</span>
                        <span v-if="a.is_custom" class="badge rounded-pill ld-custom-badge">
                            <i class="fas fa-pen me-1"></i>Custom
                        </span>
                    </div>
                </div>
                <div class="ld-card-name">{{ a.title }}</div>
                <div class="ld-card-key">{{ a.action_key }}</div>
                <div class="ld-card-meta">
                    <span class="fl-meta-item">
                        <i class="fas fa-chart-simple"></i>
                        {{ a.usage_count }} log<span v-if="a.usage_count !== 1">s</span>
                    </span>
                    <span class="fl-meta-item">
                        <i :class="a.is_public ? 'fas fa-eye' : 'fas fa-eye-slash'"></i>
                        {{ a.is_public ? 'Public' : 'Admin only' }}
                    </span>
                    <span :class="['badge', levelBadge(a.level)]" style="width:fit-content;font-size:.65rem;">{{ a.level }}</span>
                </div>
                <div class="ld-card-actions">
                    <button class="btn btn-sm btn-outline-primary rounded-pill px-3" @click="openEdit(a)">
                        <i class="fas fa-pen me-1"></i>Edit
                    </button>
                </div>
            </div>
        </div>

        <!-- ═══════ TABLE VIEW ═══════ -->
        <div v-else class="dt-table-wrap">
            <table class="dt-table">
                <thead class="dt-thead">
                    <tr>
                        <th class="dt-th" style="width:34px;"></th>
                        <th class="dt-th">
                            <div class="dt-th-inner dt-th--sortable"
                                 :class="{'dt-th--sorted': sortKey==='action_key'}" @click="setSort('action_key')">
                                Action <i class="fas dt-sort-icon" :class="sortIcon('action_key')"></i>
                            </div>
                        </th>
                        <th class="dt-th">
                            <div class="dt-th-inner dt-th--sortable"
                                 :class="{'dt-th--sorted': sortKey==='title'}" @click="setSort('title')">
                                Title <i class="fas dt-sort-icon" :class="sortIcon('title')"></i>
                            </div>
                        </th>
                        <th class="dt-th" style="width:110px;">
                            <div class="dt-th-inner dt-th--sortable"
                                 :class="{'dt-th--sorted': sortKey==='category'}" @click="setSort('category')">
                                Category <i class="fas dt-sort-icon" :class="sortIcon('category')"></i>
                            </div>
                        </th>
                        <th class="dt-th" style="width:90px;">Visibility</th>
                        <th class="dt-th" style="width:90px;">
                            <div class="dt-th-inner dt-th--sortable"
                                 :class="{'dt-th--sorted': sortKey==='usage_count'}" @click="setSort('usage_count')">
                                Uses <i class="fas dt-sort-icon" :class="sortIcon('usage_count')"></i>
                            </div>
                        </th>
                        <th class="dt-th dt-th--actions" style="width:80px;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <tr v-for="a in items" :key="a.action_key" class="dt-row">
                        <td class="dt-td"><i :class="a.icon" style="color:var(--subtle-text-color);"></i></td>
                        <td class="dt-td">
                            <span class="fw-600" style="font-size:.82rem;font-family:var(--font-mono);">{{ a.action_key }}</span>
                            <span v-if="a.is_custom" class="badge rounded-pill ld-custom-badge ms-1">Custom</span>
                        </td>
                        <td class="dt-td" style="font-size:.87rem;">{{ a.title }}</td>
                        <td class="dt-td"><span class="badge rounded-pill ld-cat-badge">{{ a.category }}</span></td>
                        <td class="dt-td">
                            <i :class="a.is_public ? 'fas fa-eye text-success' : 'fas fa-eye-slash text-muted'"
                               :title="a.is_public ? 'Public' : 'Admin only'"></i>
                        </td>
                        <td class="dt-td" style="font-weight:600;font-size:.85rem;">{{ a.usage_count }}</td>
                        <td class="dt-td dt-td--actions">
                            <div class="dt-actions">
                                <button class="dt-action-btn" title="Edit" @click="openEdit(a)">
                                    <i class="fas fa-pen"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- ── Footer ── -->
        <div v-if="!loading && items.length > 0" class="rl-footer">
            <div v-if="viewMode === 'card'" class="rl-per-page">
                <span>Per page</span>
                <select v-model="perPageModel">
                    <option v-for="n in [8, 16, 32]" :key="n" :value="n">{{ n }}</option>
                </select>
            </div>
            <div v-else style="width:1px;"></div>
            <div style="flex-grow:1;display:flex;justify-content:center;">
                <pagination-component :current-page="page" :total-pages="totalPages"
                                      @change-page="goToPage"></pagination-component>
            </div>
            <div class="rl-footer-info">{{ footerInfo }}</div>
        </div>

        <!-- ═══════ EDIT MODAL ═══════ -->
        <div v-if="editItem" class="modal fade show d-block" style="background:rgba(0,0,0,.5);" @click.self="editItem=null">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content border-0 shadow-lg rounded-4">
                    <div class="modal-header border-0 pb-0">
                        <h5 class="modal-title fw-bold">
                            <i class="fa-solid fa-pen me-2 text-primary"></i>Edit Log Action
                        </h5>
                        <button class="btn-close" @click="editItem=null"></button>
                    </div>
                    <div class="modal-body pt-2">
                        <div class="ld-modal-key">{{ editItem.action_key }}</div>

                        <div class="mb-3">
                            <label class="form-label small fw-semibold">Title</label>
                            <input v-model="editForm.title" class="form-control form-control-sm"
                                   :placeholder="editItem.default_title">
                        </div>
                        <div class="mb-3">
                            <label class="form-label small fw-semibold">Icon <span class="text-muted fw-normal">(FontAwesome class)</span></label>
                            <div class="input-group input-group-sm">
                                <span class="input-group-text"><i :class="editForm.icon || editItem.default_icon"></i></span>
                                <input v-model="editForm.icon" class="form-control" :placeholder="editItem.default_icon">
                            </div>
                        </div>
                        <div class="form-check form-switch mb-2">
                            <input class="form-check-input" type="checkbox" v-model="editForm.is_public" id="ldEditPublic">
                            <label class="form-check-label small" for="ldEditPublic">
                                <span v-if="editForm.is_public" class="text-success fw-semibold">
                                    <i class="fa-solid fa-eye me-1"></i>Public — visible in the activity feed
                                </span>
                                <span v-else class="text-muted">
                                    <i class="fa-solid fa-eye-slash me-1"></i>Private — admin only
                                </span>
                            </label>
                        </div>
                        <div class="text-muted small">
                            Category <span class="badge rounded-pill ld-cat-badge">{{ editItem.category }}</span>
                            &middot; used <strong>{{ editItem.usage_count }}</strong> time<span v-if="editItem.usage_count !== 1">s</span>
                        </div>
                    </div>
                    <div class="modal-footer border-0 pt-0 justify-content-between">
                        <button v-if="editItem.is_custom" @click="doReset" class="btn btn-sm btn-outline-secondary rounded-pill px-3">
                            <i class="fas fa-rotate-left me-1"></i>Reset to default
                        </button>
                        <div v-else></div>
                        <div class="d-flex gap-2">
                            <button @click="editItem=null" class="btn btn-sm btn-light border rounded-pill px-4">Cancel</button>
                            <button @click="doSave" class="btn btn-sm btn-primary rounded-pill px-4">Save</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

    </div>
    `,

    setup(props) {
        const items      = ref([])
        const total      = ref(0)
        const totalPages = ref(1)
        const loading    = ref(false)
        const viewMode   = ref('table')
        const page       = ref(1)
        const sortKey    = ref('action_key')
        const sortDir    = ref('asc')
        const cardPP     = ref(16)
        const tablePP    = ref(20)
        const perPage    = computed(() => viewMode.value === 'table' ? tablePP.value : cardPP.value)
        const perPageModel = computed({
            get: () => perPage.value,
            set: val => {
                if (viewMode.value === 'table') tablePP.value = Number(val)
                else                            cardPP.value  = Number(val)
                page.value = 1; fetchData()
            },
        })
        const search   = ref('')
        const category = ref('')
        const categories = CATEGORIES

        const footerInfo = computed(() => {
            if (total.value === 0) return ''
            const s = (page.value - 1) * perPage.value + 1
            const e = Math.min(page.value * perPage.value, total.value)
            return `${s}–${e} of ${total.value}`
        })

        function levelBadge(level) { return LEVEL_BADGE[level] || 'bg-secondary' }

        async function fetchData() {
            loading.value = true
            try {
                const p = new URLSearchParams({
                    page: page.value, per_page: perPage.value,
                    sort: sortKey.value, dir: sortDir.value,
                })
                if (search.value)   p.set('search', search.value)
                if (category.value) p.set('category', category.value)
                const res  = await fetch(`/admin/log_definitions_data?${p}`)
                const data = await res.json()
                items.value      = data.items      ?? []
                total.value      = data.total      ?? 0
                totalPages.value = data.total_pages ?? 1
                if (page.value > totalPages.value && totalPages.value > 0)
                    page.value = totalPages.value
            } finally {
                loading.value = false
            }
        }

        let _st = null
        function onSearchInput()  { clearTimeout(_st); _st = setTimeout(() => { page.value = 1; fetchData() }, 340) }
        function clearSearch()    { search.value = ''; page.value = 1; fetchData() }
        function onFilterChange() { page.value = 1; fetchData() }
        function setSort(key) {
            if (sortKey.value === key) sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
            else { sortKey.value = key; sortDir.value = 'asc' }
            page.value = 1; fetchData()
        }
        function sortIcon(key) {
            if (sortKey.value !== key) return 'fa-sort'
            return sortDir.value === 'asc' ? 'fa-sort-up' : 'fa-sort-down'
        }
        function goToPage(p) { page.value = p; fetchData() }

        // ── Edit ──────────────────────────────────────────────────────────
        const editItem = ref(null)
        const editForm = ref({ icon: '', title: '', is_public: false })

        function openEdit(a) {
            editItem.value = a
            editForm.value = {
                icon:      a.is_custom ? a.icon  : '',
                title:     a.is_custom ? a.title : '',
                is_public: !!a.is_public,
            }
        }

        async function doSave() {
            if (!editItem.value) return
            try {
                const res  = await fetch('/admin/log_definitions/save', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body:    JSON.stringify({ action_key: editItem.value.action_key, ...editForm.value }),
                })
                const data = await res.json()
                if (data.success) {
                    editItem.value = null
                    fetchData()
                    if (window.create_message) window.create_message('Log action updated', 'success-subtle')
                } else if (window.create_message) {
                    window.create_message(data.message || 'Failed', 'danger-subtle')
                }
            } catch (e) { if (window.create_message) window.create_message('Error: ' + e, 'danger-subtle') }
        }

        async function doReset() {
            if (!editItem.value) return
            try {
                const res  = await fetch('/admin/log_definitions/reset', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body:    JSON.stringify({ action_key: editItem.value.action_key }),
                })
                const data = await res.json()
                if (data.success) {
                    editItem.value = null
                    fetchData()
                    if (window.create_message) window.create_message('Reset to default', 'success-subtle')
                }
            } catch (e) { if (window.create_message) window.create_message('Error: ' + e, 'danger-subtle') }
        }

        onMounted(fetchData)

        return {
            items, total, totalPages, loading, viewMode, page,
            perPage, perPageModel, search, category, categories, footerInfo,
            sortKey, sortDir, onSearchInput, clearSearch, onFilterChange, setSort, sortIcon, goToPage,
            levelBadge, editItem, editForm, openEdit, doSave, doReset,
            fetchData,
        }
    },
}
