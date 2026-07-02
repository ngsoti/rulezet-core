/**
 * BundleRuleSelector.js
 *
 * Rule picker panel for the bundle editor.
 * Identical to ruleList.js in terms of filters and views,
 * but tailored for selecting / dragging rules into a bundle:
 *   - No vote / favorite / edit / delete / export
 *   - Checkbox multi-select per card / row
 *   - "Add to bundle" button on each rule
 *   - "Add selected (N)" sticky bar
 *   - Drag-and-drop: dragging a rule emits HTML5 DnD with
 *     application/rulezet-rule data (picked up by BundleStructureEditor)
 *   - syncUrl is always false (embedded component)
 *
 * Props:
 *   fetchUrl        String   default '/rule/data_table'
 *   showFilters     Boolean  default true
 *   initialPerPage  Number   default 12
 *   hiddenFilters   Array    default []
 *   pinnedIds       Array    default null — when set, the pool is locked to
 *                            exactly these rule ids (e.g. the set that
 *                            matched the filters/selection at the moment the
 *                            user chose "Add to Bundle"); the filter bar can
 *                            still narrow WITHIN that pool but never fetches
 *                            outside of it.
 *
 * Emits:
 *   add-rules(rules[])  — array of full rule objects to add
 *   preview-rule(rule)  — user wants to preview a rule in the editor panel
 */

import PaginationComponent       from '/static/js/rule/paginationComponent.js'
import MultiVulnerabilityFilter  from '/static/js/vulnerability/multiVulnerabilityFilter.js'
import MultiSourceFilter         from '/static/js/rule/multiSourceFilter.js'
import MultiLicenseFilter        from '/static/js/rule/multiLicenseFilter.js'
import MultiPersonFilter         from '/static/js/rule/multiPersonFilter.js'
import MultiTagFilter            from '/static/js/tags/multiTagFIlter.js'
import MultiAttackFilter         from '/static/js/attack/multiAttackFilter.js'
import AttackDisplayList         from '/static/js/attack/attackDisplayList.js'
import TagsDisplaysList          from '/static/js/tags/tagsDisplaysList.js'
import VulnerabilityDisplaysList from '/static/js/vulnerability/vulnerabilityDisplayList.js'
import UserChip                  from '/static/js/components/UserChip.js'

const { ref, reactive, computed, watch, onMounted, onUnmounted } = Vue

export default {
    name: 'BundleRuleSelector',

    components: {
        PaginationComponent,
        MultiVulnerabilityFilter,
        MultiSourceFilter,
        MultiLicenseFilter,
        MultiTagFilter,
        MultiAttackFilter,
        AttackDisplayList,
        MultiPersonFilter,
        TagsDisplaysList,
        VulnerabilityDisplaysList,
        UserChip,
    },

    props: {
        fetchUrl:       { type: String,  default: '/rule/data_table' },
        showFilters:    { type: Boolean, default: true },
        initialPerPage: { type: Number,  default: 12 },
        hiddenFilters:  { type: Array,   default: () => [] },
        currentUserId:  { type: Number,  default: null },
        excludeIds:     { type: Object,  default: null },  // Set of rule IDs already in the bundle
        pinnedIds:      { type: Array,   default: null },
    },

    emits: ['add-rules', 'preview-rule'],

    template: `
    <div class="brs-wrapper">

        <!-- ── Header ── -->
        <div class="brs-header">
            <div class="brs-header-top">
                <div>
                    <div class="brs-title"><i class="fas fa-database me-2"></i>Rule Library</div>
                    <div class="brs-subtitle">
                        <i class="fas fa-hand-pointer me-1"></i>Click to preview &amp; select ·
                        <i class="fas fa-grip-vertical me-1"></i>Drag to a folder ·
                        <i class="fas fa-plus me-1"></i>Add directly
                    </div>
                </div>
                <div class="d-flex gap-2 align-items-center">
                    <!-- View toggle -->
                    <div class="brs-view-toggle">
                        <button class="brs-view-btn" :class="{ 'brs-view-btn--active': viewMode === 'card' }"
                                @click="setView('card')" title="Card view">
                            <i class="fas fa-rectangle-list"></i>
                        </button>
                        <button class="brs-view-btn" :class="{ 'brs-view-btn--active': viewMode === 'table' }"
                                @click="setView('table')" title="Table view">
                            <i class="fas fa-table-cells-large"></i>
                        </button>
                    </div>
                </div>
            </div>

            <!-- Toolbar row -->
            <div class="brs-toolbar">
                <!-- Search -->
                <div class="brs-search">
                    <i class="brs-search-icon fas fa-search"></i>
                    <input class="brs-search-input" type="text" placeholder="Search rules…"
                           v-model="search" @input="onSearchInput" />
                    <button v-if="search" class="brs-search-clear" @click="clearSearch">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>

                <!-- Format -->
                <select class="brs-select" v-model="ruleType" @change="onFilterChange">
                    <option value="">All formats</option>
                    <option v-for="f in rulesFormats" :key="f.id" :value="f.name">
                        {{ f.name.toUpperCase() }}
                    </option>
                </select>

                <!-- Mine only -->
                <button v-if="currentUserId" class="brs-btn"
                        :class="{ 'brs-btn--active': mineOnly }"
                        @click="mineOnly = !mineOnly; onFilterChange()"
                        title="Show only my rules">
                    <i class="fas fa-user"></i>
                    Mine only
                </button>

                <!-- Filters toggle -->
                <button v-if="showFilters" class="brs-btn"
                        :class="{ 'brs-btn--active': filtersOpen }"
                        @click="filtersOpen = !filtersOpen">
                    <i class="fas fa-sliders"></i>
                    <span v-if="activeFilterCount > 0" class="brs-filter-badge">{{ activeFilterCount }}</span>
                    Filters
                </button>

                <!-- Column picker (table mode only) -->
                <div v-if="viewMode === 'table'" class="brs-col-picker" @click.stop>
                    <button class="brs-btn" @click.stop="colPickerOpen = !colPickerOpen" title="Choose columns">
                        <i class="fas fa-table-columns"></i>
                    </button>
                    <div v-if="colPickerOpen" class="brs-col-dropdown">
                        <div class="brs-col-dropdown-title">Columns</div>
                        <label v-for="col in allColumns" :key="col.key" class="brs-col-option">
                            <input type="checkbox"
                                   :checked="visibleCols.has(col.key)"
                                   @change="toggleCol(col.key)" />
                            {{ col.label }}
                        </label>
                    </div>
                </div>

                <span class="text-muted small ms-1" v-if="!loading">
                    <strong>{{ displayTotal }}</strong> rule<span v-if="displayTotal !== 1">s</span>
                </span>
            </div>
        </div>

        <!-- ── Filter panel ── -->
        <div v-if="showFilters && filtersOpen" class="brs-filter-panel">
            <div class="brs-fp-row">
                <select class="brs-fp-select" v-model="searchField" @change="onFilterChange">
                    <option value="all">All fields</option>
                    <option value="title">Title only</option>
                    <option value="content">Content only</option>
                </select>
                <label class="d-flex align-items-center gap-1 small" style="cursor:pointer;">
                    <input type="checkbox" v-model="exactMatch" @change="onFilterChange">
                    Exact match
                </label>
                <button v-if="activeFilterCount > 0" class="brs-fp-reset" @click="resetFilters">
                    <i class="fas fa-rotate-left"></i> Reset
                </button>
            </div>
            <div class="brs-fp-row brs-fp-multi">
                <div v-if="!isHidden('sources')" class="brs-fp-multi-item">
                    <multi-source-filter v-model="selectedSources"
                        api-endpoint="/rule/get_rules_sources_usage"
                        placeholder="Sources…"
                        :filter-context="filterContext"
                        @change="onFilterChange" />
                </div>
                <div v-if="!isHidden('vulnerabilities')" class="brs-fp-multi-item">
                    <multi-vulnerability-filter v-model="selectedVulns"
                        api-endpoint="/rule/get_all_rules_vulnerabilities_usage"
                        placeholder="CVE…"
                        :filter-context="filterContext"
                        @change="onFilterChange" />
                </div>
                <div v-if="!isHidden('licenses')" class="brs-fp-multi-item">
                    <multi-license-filter v-model="selectedLicenses"
                        api-endpoint="/rule/get_rules_licenses_usage"
                        placeholder="Licenses…"
                        :filter-context="filterContext"
                        @change="onFilterChange" />
                </div>
                <div v-if="!isHidden('tags')" class="brs-fp-multi-item">
                    <multi-tag-filter v-model="selectedTags"
                        api-endpoint="/rule/get_all_tags_usage"
                        placeholder="Tags…"
                        target-type="rule"
                        :filter-context="filterContext"
                        @change="onFilterChange" />
                </div>
                <div v-if="!isHidden('attacks')" class="brs-fp-multi-item">
                    <multi-attack-filter v-model="selectedAttacks"
                        placeholder="T1059, Command…"
                        :filter-context="filterContext"
                        @change="onFilterChange" />
                </div>
                <div v-if="!isHidden('person')" class="brs-fp-multi-item">
                    <multi-person-filter v-model="personFilter"
                        @change="p => { personFilter = p; onFilterChange() }" />
                </div>
            </div>
        </div>

        <!-- ── Body ── -->
        <div class="brs-body">

            <!-- Loading -->
            <div v-if="loading" class="brs-loading">
                <div class="spinner-border text-primary spinner-border-sm me-2"></div>
                Loading rules…
            </div>

            <!-- Empty -->
            <div v-else-if="items.length === 0" class="brs-empty">
                <i class="fas fa-search fa-2x opacity-25"></i>
                <span class="small">No rules found.</span>
            </div>

            <!-- ══ CARD VIEW ══ -->
            <template v-else-if="viewMode === 'card'">
                <div
                    v-for="rule in items" :key="rule.id"
                    class="brs-rule-card"
                    :class="{ 'brs-rule-card--selected': isSelected(rule.id), 'brs-rule-card--dragging': draggingId === rule.id }"
                    draggable="true"
                    @dragstart="onDragStart($event, rule)"
                    @dragend="onDragEnd"
                    @click="onCardClick(rule)"
                    style="cursor:pointer;"
                >
                    <div class="brs-rule-card-accent"></div>
                    <div class="brs-rule-card-body">
                        <!-- Drag handle -->
                        <span class="brs-rule-drag-handle" title="Glisser vers un dossier">
                            <i class="fas fa-grip-vertical"></i>
                        </span>

                        <!-- Checkbox -->
                        <input type="checkbox" class="brs-rule-card-check"
                               :checked="isSelected(rule.id)"
                               @change.stop="toggleSelect(rule)"
                               @click.stop title="Select" />

                        <!-- Content -->
                        <div class="brs-rule-card-content">
                            <span class="brs-rule-title">{{ rule.title }}</span>
                            <div class="brs-rule-meta">
                                <span class="brs-rule-format">{{ (rule.format || '?').toUpperCase() }}</span>
                                <span class="brs-rule-editor">
                                    <i class="fas fa-user fa-xs me-1"></i>{{ rule.editor || '—' }}
                                </span>
                                <span class="text-muted" style="font-size:.68rem;">{{ fromNow(rule.last_modif) }}</span>
                            </div>
                            <div class="brs-rule-desc" v-if="rule.description">{{ rule.description }}</div>

                            <!-- Tags (compact) -->
                            <div class="mt-1" @click.stop>
                                <tags-displays-list object-type="rule" :object-id="rule.id" :max-visible="2" />
                            </div>
                        </div>

                        <!-- Actions -->
                        <div class="brs-rule-card-actions" @click.stop>
                            <button class="brs-add-btn" title="Add to bundle"
                                    @click.stop="addSingleRule(rule)">
                                <i class="fas fa-plus"></i>
                            </button>
                            <a :href="'/rule/detail_rule/' + rule.id" target="_blank"
                               class="brs-preview-btn" title="Open rule" @click.stop>
                                <i class="fas fa-arrow-up-right-from-square"></i>
                            </a>
                        </div>
                    </div>
                </div>
            </template>

            <!-- ══ TABLE VIEW ══ -->
            <template v-else>
                <div class="brs-table-wrap">
                    <table class="brs-table">
                        <thead>
                            <tr>
                                <th style="width:28px;" title="Drag to a folder">
                                    <i class="fas fa-grip-vertical" style="opacity:.35;font-size:.75rem;"></i>
                                </th>
                                <th style="width:32px;">
                                    <input type="checkbox" class="form-check-input"
                                           :checked="allOnPageSelected"
                                           @change="togglePageSelection" />
                                </th>
                                <th class="brs-sortable-th" @click="toggleSort('title')">
                                    Title <i :class="sortIcon('title')" class="brs-sort-icon"></i>
                                </th>
                                <th v-if="visibleCols.has('format')" class="brs-sortable-th" style="width:80px;" @click="toggleSort('format')">
                                    Format <i :class="sortIcon('format')" class="brs-sort-icon"></i>
                                </th>
                                <th v-if="visibleCols.has('editor')" style="width:120px;">Editor</th>
                                <th v-if="visibleCols.has('creation_date')" class="brs-sortable-th" style="width:100px;" @click="toggleSort('creation_date')">
                                    Created <i :class="sortIcon('creation_date')" class="brs-sort-icon"></i>
                                </th>
                                <th v-if="visibleCols.has('tags')" style="width:140px;">Tags</th>
                                <th v-if="visibleCols.has('cves')" style="width:110px;">CVEs</th>
                                <th v-if="visibleCols.has('attacks')" style="width:140px;">ATT&amp;CK</th>
                                <th style="width:80px;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="rule in items" :key="rule.id"
                                class="brs-rule-row"
                                :class="{ 'brs-row--selected': isSelected(rule.id), 'brs-row--dragging': draggingId === rule.id }"
                                draggable="true"
                                style="cursor:pointer;"
                                @dragstart="onDragStart($event, rule)"
                                @dragend="onDragEnd"
                                @click="onCardClick(rule)">
                                <td @click.stop class="brs-drag-cell" title="Drag to a folder">
                                    <i class="fas fa-grip-vertical brs-drag-icon"></i>
                                    <span v-if="isSelected(rule.id) && selectedIds.size > 1"
                                          class="brs-drag-badge">{{ selectedIds.size }}</span>
                                </td>
                                <td @click.stop>
                                    <input type="checkbox" class="form-check-input"
                                           :checked="isSelected(rule.id)"
                                           @change.stop="toggleSelect(rule)" />
                                </td>
                                <td>
                                    <span class="brs-rule-title fw-semibold"
                                          style="font-size:.8rem;">{{ rule.title }}</span>
                                </td>
                                <td v-if="visibleCols.has('format')">
                                    <span v-if="rule.format" class="brs-rule-format">
                                        {{ rule.format.toUpperCase() }}
                                    </span>
                                </td>
                                <td v-if="visibleCols.has('editor')" @click.stop>
                                    <user-chip :user-id="rule.user_id" :username="rule.editor"
                                               :avatar="rule.editor_avatar" size="xs" />
                                </td>
                                <td v-if="visibleCols.has('creation_date')" style="font-size:.72rem;white-space:nowrap;color:var(--subtle-text-color);">
                                    {{ formatDate(rule.creation_date) }}
                                </td>
                                <td v-if="visibleCols.has('tags')" @click.stop style="max-width:140px;">
                                    <tags-displays-list object-type="rule" :object-id="rule.id" :max-visible="2" />
                                </td>
                                <td v-if="visibleCols.has('cves')" @click.stop style="max-width:110px;">
                                    <div v-if="rule.cves && rule.cves.length" class="d-flex flex-wrap gap-1">
                                        <span v-for="cve in rule.cves.slice(0,3)" :key="cve"
                                              class="brs-cve-badge" :title="cve">{{ cve }}</span>
                                        <span v-if="rule.cves.length > 3" class="brs-cve-more">
                                            +{{ rule.cves.length - 3 }}
                                        </span>
                                    </div>
                                    <span v-else class="text-muted" style="font-size:.65rem;">—</span>
                                </td>
                                <td v-if="visibleCols.has('attacks')" @click.stop style="max-width:140px;">
                                    <attack-display-list :initial-attacks="rule.attacks" :max-visible="2" />
                                </td>
                                <td @click.stop>
                                    <div class="d-flex gap-1">
                                        <button class="brs-add-btn" title="Add to bundle"
                                                @click.stop="addSingleRule(rule)">
                                            <i class="fas fa-plus"></i>
                                        </button>
                                        <a :href="'/rule/detail_rule/' + rule.id" target="_blank"
                                           class="brs-preview-btn" title="Open rule" @click.stop>
                                            <i class="fas fa-arrow-up-right-from-square"></i>
                                        </a>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </template>

        </div>

        <!-- ── Footer ── -->
        <div class="brs-footer">
            <div class="brs-per-page">
                Per page
                <select v-model="perPageModel">
                    <option v-for="n in [10, 20, 50]" :key="n" :value="n">{{ n }}</option>
                </select>
            </div>
            <pagination-component :current-page="page" :total-pages="displayTotalPages" @change-page="goToPage" />
            <div class="brs-footer-info">{{ footerInfo }}</div>
        </div>

        <!-- ── Add-selected bar ── -->
        <transition name="brs-bar">
            <div v-if="selectedIds.size > 0" class="brs-add-bar">
                <span class="brs-add-bar-count">
                    <i class="fas fa-check-square me-1"></i>
                    {{ selectedIds.size }} rule{{ selectedIds.size !== 1 ? 's' : '' }} selected
                </span>
                <button class="brs-add-bar-btn" @click="addSelected">
                    <i class="fas fa-plus me-1"></i>
                    Add {{ selectedIds.size === 1 ? '1 rule' : selectedIds.size + ' rules' }} to bundle
                </button>
                <button class="brs-add-bar-clear" @click="clearSelection" title="Clear selection">
                    <i class="fas fa-xmark"></i>
                </button>
            </div>
        </transition>

    </div>
    `,

    setup(props, { emit }) {

        // ── Data ──────────────────────────────────────────────────
        const items      = ref([])
        const total      = ref(0)
        const totalPages = ref(1)
        const loading    = ref(false)
        const viewMode   = ref('table')
        const draggingId = ref(null)

        // ── Pagination ────────────────────────────────────────────
        const page     = ref(1)
        const cardPP   = ref(props.initialPerPage)
        const tablePP  = ref(20)

        const perPage = computed(() => viewMode.value === 'table' ? tablePP.value : cardPP.value)
        const perPageModel = computed({
            get: () => perPage.value,
            set: val => {
                if (viewMode.value === 'table') tablePP.value = Number(val)
                else cardPP.value = Number(val)
                page.value = 1
                fetchData()
            },
        })

        // ── Filters ───────────────────────────────────────────────
        const search          = ref('')
        const searchField     = ref('all')
        const exactMatch      = ref(false)
        const ruleType        = ref('')
        const selectedTags    = ref([])
        const selectedSources = ref([])
        const selectedLicenses = ref([])
        const selectedVulns   = ref([])
        const selectedAttacks = ref([])
        const personFilter    = ref({ mode: 'author', values: [] })
        const rulesFormats    = ref([])
        const filtersOpen     = ref(false)
        const mineOnly        = ref(false)

        // Every OTHER active filter, as a query string — passed to each
        // multi-filter component so its counts stay scoped to what's
        // actually reachable (same faceted-filter system as ruleList.js).
        // When pinnedIds is set, it's folded in too so facet counts never
        // include rules outside the locked pool.
        const filterContext = computed(() => {
            const p = new URLSearchParams()
            if (ruleType.value)                p.set('rule_type', ruleType.value)
            if (search.value.trim())           p.set('search', search.value.trim())
            if (searchField.value !== 'all')   p.set('search_field', searchField.value)
            if (exactMatch.value)              p.set('exact_match', 'true')
            if (selectedTags.value.length)     p.set('tags', selectedTags.value.join(','))
            if (selectedSources.value.length)  p.set('sources', selectedSources.value.join(','))
            if (selectedLicenses.value.length) p.set('licenses', selectedLicenses.value.join(','))
            if (selectedVulns.value.length)    p.set('vulnerabilities', selectedVulns.value.join(','))
            if (selectedAttacks.value.length)  p.set('attacks', selectedAttacks.value.join(','))
            if (personFilter.value.values.length) {
                const pKey = personFilter.value.mode === 'editor' ? 'editors' : 'authors'
                p.set(pKey, personFilter.value.values.join(','))
            }
            if (props.pinnedIds && props.pinnedIds.length) p.set('ids', props.pinnedIds.join(','))
            return p.toString()
        })

        // ── Column picker ─────────────────────────────────────────
        const allColumns = [
            { key: 'format',        label: 'Format'  },
            { key: 'editor',        label: 'Editor'  },
            { key: 'creation_date', label: 'Created' },
            { key: 'tags',          label: 'Tags'    },
            { key: 'cves',          label: 'CVEs'    },
            { key: 'attacks',       label: 'ATT&CK'  },
        ]
        const visibleCols  = reactive(new Set(['format', 'editor', 'creation_date']))
        const colPickerOpen = ref(false)

        function toggleCol(key) {
            if (visibleCols.has(key)) visibleCols.delete(key)
            else visibleCols.add(key)
        }

        // Close column picker when clicking outside
        function onDocClick() { colPickerOpen.value = false }

        // ── Sort ──────────────────────────────────────────────────
        const sortField = ref('')
        const sortDir   = ref('asc')

        function toggleSort(field) {
            if (sortField.value === field) {
                sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
            } else {
                sortField.value = field
                sortDir.value   = 'asc'
            }
            page.value = 1
            fetchData()
        }

        function sortIcon(field) {
            if (sortField.value !== field) return 'fas fa-sort'
            return sortDir.value === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'
        }

        const isHidden = (key) => props.hiddenFilters.includes(key)

        const activeFilterCount = computed(() =>
            (ruleType.value ? 1 : 0) +
            (exactMatch.value ? 1 : 0) +
            (searchField.value !== 'all' ? 1 : 0) +
            (mineOnly.value ? 1 : 0) +
            selectedTags.value.length +
            selectedSources.value.length +
            selectedLicenses.value.length +
            selectedVulns.value.length +
            selectedAttacks.value.length +
            personFilter.value.values.length
        )

        // ── Selection ──────────────────────────────────────────────
        const selectedIds  = reactive(new Set())
        const selectedMap  = reactive(new Map())  // id → rule

        function isSelected(id) { return selectedIds.has(id) }

        function toggleSelect(rule) {
            if (selectedIds.has(rule.id)) {
                selectedIds.delete(rule.id)
                selectedMap.delete(rule.id)
            } else {
                selectedIds.add(rule.id)
                selectedMap.set(rule.id, rule)
            }
        }

        const allOnPageSelected = computed(() =>
            items.value.length > 0 && items.value.every(r => selectedIds.has(r.id))
        )

        function togglePageSelection() {
            if (allOnPageSelected.value) {
                items.value.forEach(r => { selectedIds.delete(r.id); selectedMap.delete(r.id) })
            } else {
                items.value.forEach(r => { selectedIds.add(r.id); selectedMap.set(r.id, r) })
            }
        }

        function clearSelection() {
            selectedIds.clear()
            selectedMap.clear()
        }

        // ── Add to bundle ──────────────────────────────────────────
        function addSingleRule(rule) {
            emit('add-rules', [rule])
        }

        function addSelected() {
            const rules = [...selectedMap.values()]
            if (rules.length === 0) return
            emit('add-rules', rules)
            clearSelection()
        }

        // Click on card or row: preview + toggle selection
        function onCardClick(rule) {
            toggleSelect(rule)
            emit('preview-rule', rule)
        }

        // ── Drag-and-drop ──────────────────────────────────────────
        // If the dragged rule is part of a multi-selection, carry all selected rules.
        // Otherwise carry just this one rule.
        function onDragStart(ev, rule) {
            draggingId.value = rule.id
            ev.dataTransfer.effectAllowed = 'copy'
            let payload
            if (selectedIds.has(rule.id) && selectedIds.size > 1) {
                payload = [...selectedMap.values()].map(r => ({
                    id: r.id, title: r.title, format: r.format || '', to_string: r.to_string || '',
                }))
            } else {
                payload = [{ id: rule.id, title: rule.title, format: rule.format || '', to_string: rule.to_string || '' }]
            }
            ev.dataTransfer.setData('application/rulezet-rule', JSON.stringify(payload))
        }

        function onDragEnd(ev) {
            draggingId.value = null
            if (ev.dataTransfer.dropEffect !== 'none') clearSelection()
        }

        // ── Fetch ──────────────────────────────────────────────────
        let searchTimer = null

        async function fetchData() {
            loading.value = true
            try {
                const params = new URLSearchParams()
                params.set('page',     page.value)
                params.set('per_page', perPage.value)
                if (search.value)                   params.set('search', search.value)
                if (searchField.value !== 'all')    params.set('search_field', searchField.value)
                if (exactMatch.value)               params.set('exact_match', 'true')
                if (ruleType.value)                 params.set('rule_type', ruleType.value)
                if (sortField.value)                { params.set('sort', sortField.value); params.set('dir', sortDir.value) }
                if (mineOnly.value && props.currentUserId) params.set('user_id', props.currentUserId)
                if (selectedTags.value.length)      params.set('tags', selectedTags.value.join(','))
                if (selectedSources.value.length)   params.set('sources', selectedSources.value.join(','))
                if (selectedLicenses.value.length)  params.set('licenses', selectedLicenses.value.join(','))
                if (selectedVulns.value.length)      params.set('vulnerabilities', selectedVulns.value.join(','))
                if (selectedAttacks.value.length)   params.set('attacks', selectedAttacks.value.join(','))
                if (personFilter.value.values.length) {
                    const k = personFilter.value.mode === 'editor' ? 'editors' : 'authors'
                    params.set(k, personFilter.value.values.join(','))
                }
                if (props.pinnedIds && props.pinnedIds.length) params.set('ids', props.pinnedIds.join(','))
                const sep = props.fetchUrl.includes('?') ? '&' : '?'
                const res = await fetch(`${props.fetchUrl}${sep}${params}`)
                if (!res.ok) return
                const data = await res.json()
                const raw = data.items ?? []
                items.value      = props.excludeIds?.size ? raw.filter(r => !props.excludeIds.has(r.id)) : raw
                total.value      = data.total ?? 0
                totalPages.value = data.total_pages ?? 1
                if (page.value > totalPages.value && totalPages.value > 0)
                    page.value = totalPages.value
            } finally {
                loading.value = false
            }
        }

        async function fetchFormats() {
            try {
                const res = await fetch('/rule/get_rules_formats')
                const data = await res.json()
                rulesFormats.value = data.formats || []
            } catch {}
        }

        // ── Filter / search handlers ───────────────────────────────
        function onFilterChange() { page.value = 1; fetchData() }

        function onSearchInput() {
            clearTimeout(searchTimer)
            searchTimer = setTimeout(() => { page.value = 1; fetchData() }, 360)
        }

        function clearSearch() { search.value = ''; page.value = 1; fetchData() }

        function resetFilters() {
            ruleType.value         = ''
            searchField.value      = 'all'
            exactMatch.value       = false
            mineOnly.value         = false
            sortField.value        = ''
            sortDir.value          = 'asc'
            selectedTags.value     = []
            selectedSources.value  = []
            selectedLicenses.value = []
            selectedVulns.value    = []
            selectedAttacks.value  = []
            personFilter.value     = { mode: 'author', values: [] }
            onFilterChange()
        }

        // ── Pagination ─────────────────────────────────────────────
        function goToPage(p) { page.value = p; fetchData() }

        function setView(v) { viewMode.value = v; page.value = 1; fetchData() }

        // ── Computed ───────────────────────────────────────────────
        // When pinned to a snapshot, the server's `total` always reflects
        // the full snapshot size — subtract whatever has already been
        // placed (excludeIds) so the counter actually counts down as the
        // user adds rules, instead of staying stuck at the original count.
        const displayTotal = computed(() => {
            if (!props.pinnedIds || !props.pinnedIds.length) return total.value
            const excludedInPool = props.excludeIds
                ? props.pinnedIds.filter(id => props.excludeIds.has(id)).length
                : 0
            return Math.max(0, props.pinnedIds.length - excludedInPool)
        })

        // Same idea for pagination: a page that only had already-placed
        // rules on it must not still be offered as a page to click into.
        const displayTotalPages = computed(() => {
            if (!props.pinnedIds || !props.pinnedIds.length) return totalPages.value
            return Math.max(1, Math.ceil(displayTotal.value / perPage.value))
        })

        // If the excluded rules just took the current page out of range
        // (e.g. everything on page 2 got added), fall back to the last
        // remaining page instead of showing an empty/invalid one.
        watch(displayTotalPages, (dtp) => {
            if (props.pinnedIds && props.pinnedIds.length && page.value > dtp) {
                page.value = dtp
                fetchData()
            }
        })

        const footerInfo = computed(() => {
            if (displayTotal.value === 0) return 'No results'
            const start = (page.value - 1) * perPage.value + 1
            const end   = Math.min(page.value * perPage.value, displayTotal.value)
            return `${start}–${end} of ${displayTotal.value}`
        })

        // ── Date helpers ───────────────────────────────────────────
        function fromNow(dateStr) {
            if (!dateStr) return ''
            try {
                if (window.dayjs) return window.dayjs.utc(dateStr).fromNow()
                return formatDate(dateStr)
            } catch { return dateStr }
        }

        function formatDate(val) {
            if (!val) return '—'
            try {
                return new Date(val).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
            } catch { return val }
        }

        // ── Lifecycle ──────────────────────────────────────────────
        onMounted(() => { fetchData(); fetchFormats(); document.addEventListener('click', onDocClick) })
        onUnmounted(() => { clearTimeout(searchTimer); document.removeEventListener('click', onDocClick) })
        watch(viewMode, () => { page.value = 1; fetchData() })

        // React to bundle rule changes:
        // - Rules newly added to bundle → filter them out instantly (no re-fetch needed)
        // - Rules removed from bundle  → re-fetch so they reappear in the list
        watch(() => props.excludeIds, (newIds, oldIds) => {
            if (!newIds) return
            const anyRemoved = oldIds?.size && [...oldIds].some(id => !newIds.has(id))
            // Pinned mode is paginated over a small, fixed pool: pruning the
            // current page's already-loaded items locally leaves the page
            // stuck showing fewer rows than it should (e.g. add 20 of 21 in
            // one bulk action and the last one never gets fetched in to
            // backfill the page). Just refetch — the pool is small, so the
            // extra request is cheap and it keeps the page always correct.
            if (anyRemoved || (props.pinnedIds && props.pinnedIds.length)) {
                fetchData()
            } else {
                items.value = items.value.filter(r => !newIds.has(r.id))
            }
        })

        return {
            items, total, totalPages, loading, viewMode, draggingId,
            page, perPage, perPageModel,
            search, searchField, exactMatch, ruleType, filtersOpen, mineOnly,
            sortField, sortDir, toggleSort, sortIcon,
            allColumns, visibleCols, colPickerOpen, toggleCol,
            selectedTags, selectedSources, selectedLicenses, selectedVulns, selectedAttacks, personFilter,
            rulesFormats, activeFilterCount, filterContext,
            selectedIds, allOnPageSelected,
            isHidden, isSelected, toggleSelect, togglePageSelection, clearSelection,
            addSingleRule, addSelected, onCardClick,
            onDragStart, onDragEnd, onFilterChange, onSearchInput, clearSearch, resetFilters,
            goToPage, setView, fetchData,
            footerInfo, fromNow, formatDate, displayTotal, displayTotalPages,
        }
    },
}
