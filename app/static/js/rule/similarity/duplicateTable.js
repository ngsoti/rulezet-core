import SimilarRuleCard from '/static/js/rule/similarity/similarRulesCard.js';
import DiffViewer from '/static/js/components/diff-viewer.js';
import DeleteRuleModal from '/static/js/rule/deleteRule.js';
import { create_message } from '/static/js/toaster.js';

const { ref, reactive, computed, watch } = Vue;

/**
 * DuplicateTable — card/table renderer for similarity results.
 *
 * itemType='pair':    items are {score, rule_a_data, rule_b_data} pairs.
 *                     No selection/bulk actions (no backend "delete a pair").
 * itemType='history': items are similarity-run history records.
 *                     Selectable, supports bulk actions.
 *
 * Purely presentational for pagination/fetch — the parent still owns
 * fetching the current page; this component only searches/sorts/filters
 * the items it's given.
 */
const DuplicateTable = {
    name: 'DuplicateTable',
    components: { SimilarRuleCard, DiffViewer, DeleteRuleModal },
    delimiters: ['[[', ']]'],
    props: {
        items: { type: Array, required: true },
        itemType: { type: String, required: true }, // 'pair' | 'history'
        loading: { type: Boolean, default: false },
        isAdmin: { type: Boolean, default: false },
        selectable: { type: Boolean, default: false },
        bulkActions: { type: Array, default: () => [] },
        defaultView: { type: String, default: 'card' }, // 'table' | 'card'
        perPage: { type: Number, default: 20 },
    },
    emits: ['refresh', 'bulk-delete', 'update:per-page'],
    setup(props, { emit }) {
        const viewMode = ref(props.defaultView);
        const search = ref('');
        const sortKey = ref('');
        const sortDir = ref('asc');
        const hiddenColumns = reactive(new Set());
        const showColPicker = ref(false);
        const selectedIds = reactive(new Set());
        const expandedId = ref(null);
        const historyModeFilter = ref('all'); // all | global | filter
        const filtersOpen = ref(false);

        // Reset stale search/expand state whenever the parent hands us a new page
        watch(() => props.items, () => {
            expandedId.value = null;
        });

        const PAIR_COLUMNS = [
            { key: 'format', label: 'Format', sortable: false, hideable: true },
            { key: 'authors', label: 'Authors', sortable: false, hideable: true },
            { key: 'dates', label: 'Dates', sortable: false, hideable: true },
        ];

        const HISTORY_COLUMNS = [
            { key: 'date', label: 'Date & Time', sortable: true, hideable: false },
            { key: 'mode', label: 'Mode', sortable: true, hideable: true },
            { key: 'info', label: 'Description', sortable: false, hideable: true },
            { key: 'total_rules_processed', label: 'Processed', sortable: true, hideable: true },
            { key: 'similar_pairs_found', label: 'Pairs', sortable: true, hideable: true },
        ];

        const columns = computed(() => props.itemType === 'pair' ? PAIR_COLUMNS : HISTORY_COLUMNS);
        const visibleColumns = computed(() => columns.value.filter(c => !hiddenColumns.has(c.key)));

        function toggleColumn(key) {
            if (hiddenColumns.has(key)) hiddenColumns.delete(key);
            else hiddenColumns.add(key);
        }

        // ── Row key ──────────────────────────────────────────────────────
        function rowKey(item) {
            return props.itemType === 'pair'
                ? `${item.rule_a_data.id}_${item.rule_b_data.id}`
                : item.uuid;
        }

        // ── Score / identical helpers (mirrors SimilarRuleCard) ─────────
        function getScoreDetails(score) {
            const numScore = parseFloat(score);
            const percentage = (numScore * 100).toFixed(0);
            if (numScore >= 0.99) return { class: 'dup-score--critical', label: 'Duplicate', val: percentage };
            if (numScore > 0.85) return { class: 'dup-score--critical', label: 'Critical', val: percentage };
            if (numScore > 0.6) return { class: 'dup-score--warning', label: 'Significant', val: percentage };
            return { class: 'dup-score--low', label: 'Partial', val: percentage };
        }

        function isIdentical(item) {
            return item.rule_a_data.to_string === item.rule_b_data.to_string;
        }

        function formatDate(dateStr) {
            if (!dateStr) return 'N/A';
            return String(dateStr).split(' ')[0];
        }

        function formatTime(dateStr) {
            if (!dateStr) return '';
            const d = new Date(dateStr);
            if (isNaN(d.getTime())) return '';
            return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
        }

        function viewDetails(id) {
            window.open(`/rule/detail_rule/${id}`, '_blank');
        }

        // ── Search highlight (mirrors RuleList's highlight()) ────────────
        function escapeHtml(str) {
            return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }

        function highlight(text) {
            const str = escapeHtml(text ?? '');
            const term = search.value.trim();
            if (!term) return str;
            try {
                const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                return str.replace(new RegExp(`(${escaped})`, 'gi'), m => `<mark class="dup-highlight">${m}</mark>`);
            } catch {
                return str;
            }
        }

        // ── Search + sort + filter ───────────────────────────────────────
        function matchesSearch(item) {
            if (!search.value.trim()) return true;
            const needle = search.value.toLowerCase();
            const haystacks = props.itemType === 'pair'
                ? [
                    item.rule_a_data.title, item.rule_a_data.author, item.rule_a_data.uuid,
                    item.rule_b_data.title, item.rule_b_data.author, item.rule_b_data.uuid,
                ]
                : [item.info, item.mode];
            return haystacks.some(h => String(h ?? '').toLowerCase().includes(needle));
        }

        function matchesModeFilter(item) {
            if (props.itemType !== 'history' || historyModeFilter.value === 'all') return true;
            return item.mode === historyModeFilter.value;
        }

        function sortValue(item, key) {
            if (props.itemType === 'pair') return key === 'score' ? item.score : null;
            return item[key];
        }

        const sortableKeys = computed(() => {
            const keys = columns.value.filter(c => c.sortable).map(c => c.key);
            if (props.itemType === 'pair') keys.push('score');
            return keys;
        });

        const filteredItems = computed(() => {
            let list = props.items.filter(i => matchesSearch(i) && matchesModeFilter(i));
            if (sortKey.value) {
                list = [...list].sort((a, b) => {
                    const av = sortValue(a, sortKey.value);
                    const bv = sortValue(b, sortKey.value);
                    if (av == null && bv == null) return 0;
                    if (av == null) return 1;
                    if (bv == null) return -1;
                    if (av < bv) return sortDir.value === 'asc' ? -1 : 1;
                    if (av > bv) return sortDir.value === 'asc' ? 1 : -1;
                    return 0;
                });
            }
            return list;
        });

        function setSort(key) {
            if (!sortableKeys.value.includes(key)) return;
            if (sortKey.value === key) {
                sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc';
            } else {
                sortKey.value = key;
                sortDir.value = 'asc';
            }
        }

        function sortIcon(key) {
            if (sortKey.value !== key) return 'fa-sort';
            return sortDir.value === 'asc' ? 'fa-sort-up' : 'fa-sort-down';
        }

        // ── Selection (history only) ─────────────────────────────────────
        function isSelected(item) { return selectedIds.has(rowKey(item)); }
        function toggleItem(item) {
            const k = rowKey(item);
            if (selectedIds.has(k)) selectedIds.delete(k);
            else selectedIds.add(k);
        }
        const allOnPageSelected = computed(() =>
            filteredItems.value.length > 0 && filteredItems.value.every(i => selectedIds.has(rowKey(i)))
        );
        const someOnPageSelected = computed(() => {
            const n = filteredItems.value.filter(i => selectedIds.has(rowKey(i))).length;
            return n > 0 && n < filteredItems.value.length;
        });
        function togglePageSelection() {
            if (allOnPageSelected.value) {
                filteredItems.value.forEach(i => selectedIds.delete(rowKey(i)));
            } else {
                filteredItems.value.forEach(i => selectedIds.add(rowKey(i)));
            }
        }
        function clearSelection() { selectedIds.clear(); }
        const showBulkBar = computed(() => props.selectable && selectedIds.size > 0);

        function emitBulkAction(actionKey) {
            const ids = props.items
                .filter(i => selectedIds.has(rowKey(i)))
                .map(i => i.uuid);
            if (actionKey === 'delete') {
                emit('bulk-delete', ids);
            }
            clearSelection();
        }

        // ── Expand (table mode) ──────────────────────────────────────────
        function toggleExpand(item) {
            const k = rowKey(item);
            expandedId.value = expandedId.value === k ? null : k;
        }

        // ── Single history delete (component-owned, per approved plan) ──
        async function deleteHistoryItem(item) {
            if (!confirm('Delete this history record?')) return;
            try {
                const res = await fetch(`/rule/history_updater/delete/${item.uuid}`);
                const data = await res.json().catch(() => ({}));
                if (res.ok) {
                    create_message(data.message || 'History deleted', data.toast_class || 'success-subtle');
                    emit('refresh');
                } else {
                    create_message(data.message || 'Error deleting history', data.toast_class || 'danger-subtle');
                }
            } catch (e) {
                create_message('Error deleting history', 'danger-subtle');
            }
        }

        function goToSession(item) {
            window.location.href = `/rule/similar_loading/${item.uuid}`;
        }

        function handleRuleDeleted() {
            emit('refresh');
        }

        return {
            viewMode, search, sortKey, sortDir, hiddenColumns, showColPicker,
            selectedIds, expandedId, historyModeFilter, filtersOpen,
            columns, visibleColumns, toggleColumn,
            rowKey, getScoreDetails, isIdentical, formatDate, formatTime, viewDetails, highlight,
            filteredItems, setSort, sortIcon,
            isSelected, toggleItem, allOnPageSelected, someOnPageSelected,
            togglePageSelection, clearSelection, showBulkBar, emitBulkAction,
            toggleExpand, deleteHistoryItem, goToSession, handleRuleDeleted,
        };
    },
    template: `
    <div class="dt-wrapper" :class="{ 'dt-wrapper--bulk-open': showBulkBar }">

        <div v-if="loading" class="dt-loading-overlay" aria-live="polite">
            <div class="dt-spinner"></div>
        </div>

        <!-- Toolbar -->
        <div class="dt-toolbar">
            <div class="dt-toolbar-left">
                <div class="dt-search">
                    <i class="fas fa-search dt-search-icon"></i>
                    <input class="dt-search-input" type="text" placeholder="Search…"
                        v-model="search" aria-label="Search" />
                    <button v-if="search" class="dt-search-clear" @click="search = ''" aria-label="Clear search">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>
            </div>

            <div class="dt-toolbar-right">
                <button v-if="$slots.filters" class="dt-toolbar-btn" :class="{ 'dt-toolbar-btn--active': filtersOpen }"
                    @click="filtersOpen = !filtersOpen" title="Toggle filters">
                    <i class="fas fa-filter"></i>
                    <span>Filters</span>
                </button>

                <div class="dt-view-toggle" title="Switch view">
                    <button class="dt-view-btn" :class="{ 'dt-view-btn--active': viewMode === 'table' }"
                        @click="viewMode = 'table'" aria-label="Table view">
                        <i class="fas fa-table-cells-large"></i>
                    </button>
                    <button class="dt-view-btn" :class="{ 'dt-view-btn--active': viewMode === 'card' }"
                        @click="viewMode = 'card'" aria-label="Card view">
                        <i class="fas fa-grip"></i>
                    </button>
                </div>

                <div v-if="viewMode === 'table'" class="dt-col-picker-wrap">
                    <button class="dt-toolbar-btn" :class="{ 'dt-toolbar-btn--active': showColPicker }"
                        @click="showColPicker = !showColPicker" title="Show/hide columns">
                        <i class="fas fa-sliders"></i>
                    </button>
                    <div v-if="showColPicker" class="dt-col-picker-dropdown">
                        <label v-for="col in columns.filter(c => c.hideable)" :key="col.key" class="dt-col-picker-item">
                            <input type="checkbox" :checked="!hiddenColumns.has(col.key)" @change="toggleColumn(col.key)" />
                            [[ col.label ]]
                        </label>
                    </div>
                </div>
            </div>
        </div>

        <div v-if="$slots.filters" v-show="filtersOpen" class="dup-filter-panel">
            <slot name="filters"></slot>
        </div>

        <p class="dup-search-hint">Searching current page only ([[ items.length ]] item[[ items.length === 1 ? '' : 's' ]] loaded)</p>

        <!-- History-only mode filter pills -->
        <div v-if="itemType === 'history'" class="dup-pill-row">
            <button class="dup-pill" :class="{ 'dup-pill--active': historyModeFilter === 'all' }" @click="historyModeFilter = 'all'">All</button>
            <button class="dup-pill" :class="{ 'dup-pill--active': historyModeFilter === 'global' }" @click="historyModeFilter = 'global'">Global</button>
            <button class="dup-pill" :class="{ 'dup-pill--active': historyModeFilter === 'filter' }" @click="historyModeFilter = 'filter'">Filtered</button>
        </div>

        <!-- Select-all-on-page banner replacement: simple bulk bar only -->

        <!-- ══════════ CARD VIEW ══════════ -->
        <template v-if="viewMode === 'card'">
            <!-- Pairs: reuse SimilarRuleCard as-is -->
            <template v-if="itemType === 'pair'">
                <div v-if="!loading && filteredItems.length === 0" class="dt-empty">
                    <div class="dt-empty-icon"><i class="fas fa-grip"></i></div>
                    <p class="dt-empty-text">No results found</p>
                </div>
                <similar-rule-card v-for="item in filteredItems" :key="'card-' + rowKey(item)"
                    :rule="item" :rule-a="item.rule_a_data" :rule-b="item.rule_b_data" :score="item.score"
                    :unique-id="'card-' + rowKey(item)" :is-admin="isAdmin" :search-term="search"
                    @refresh-list="handleRuleDeleted">
                </similar-rule-card>
            </template>

            <!-- History: session cards -->
            <template v-else>
                <div class="dt-card-grid">
                    <div v-if="!loading && filteredItems.length === 0" style="grid-column: 1 / -1;">
                        <div class="dt-empty">
                            <div class="dt-empty-icon"><i class="fas fa-grip"></i></div>
                            <p class="dt-empty-text">No results found</p>
                        </div>
                    </div>
                    <div v-for="item in filteredItems" :key="'session-' + rowKey(item)"
                        class="dup-session-card" :class="{ 'dup-session-card--selected': isSelected(item) }"
                        @click="selectable ? toggleItem(item) : goToSession(item)">
                        <div class="dup-session-card__top">
                            <input v-if="selectable" type="checkbox" class="dt-checkbox" :checked="isSelected(item)"
                                @click.stop @change="toggleItem(item)" />
                            <div class="flex-grow-1">
                                <div class="dup-session-card__date">[[ formatDate(item.date) ]]</div>
                                <div class="dup-session-card__time">[[ formatTime(item.date) ]]</div>
                            </div>
                            <span :class="['dup-mode-badge', item.mode === 'global' ? 'dup-mode-badge--global' : 'dup-mode-badge--filter']">
                                [[ item.mode.toUpperCase() ]]
                            </span>
                        </div>
                        <div class="dup-session-card__desc" v-html="highlight(item.info)"></div>
                        <div class="dup-session-card__stats">
                            <div class="dup-session-card__stat">
                                <span class="dup-session-card__stat-val">[[ item.total_rules_processed ]]</span>
                                <span class="dup-session-card__stat-lbl">Processed</span>
                            </div>
                            <div class="dup-session-card__stat">
                                <span class="dup-session-card__stat-val">[[ item.similar_pairs_found ]]</span>
                                <span class="dup-session-card__stat-lbl">Pairs</span>
                            </div>
                        </div>
                        <div class="dup-session-card__actions" @click.stop>
                            <button class="dup-btn" title="View report" @click="goToSession(item)">
                                <i class="fa-solid fa-eye"></i>
                            </button>
                            <button v-if="isAdmin" class="dup-btn dup-btn--danger" title="Delete" @click="deleteHistoryItem(item)">
                                <i class="fa-solid fa-trash"></i>
                            </button>
                        </div>
                    </div>
                </div>
            </template>
        </template>

        <!-- ══════════ TABLE VIEW ══════════ -->
        <div v-else class="dt-table-wrap">
            <table class="dt-table" role="grid">
                <thead class="dt-thead">
                    <tr>
                        <th v-if="selectable" class="dt-th dt-th--checkbox">
                            <input type="checkbox" class="dt-checkbox" :checked="allOnPageSelected"
                                :indeterminate="someOnPageSelected" @change="togglePageSelection" aria-label="Select all" />
                        </th>

                        <th v-if="itemType === 'pair'" class="dt-th" :class="{ 'dt-th--sortable': true, 'dt-th--sorted': sortKey === 'score' }"
                            style="width:90px;" @click="setSort('score')">
                            <div class="dt-th-inner">
                                <span class="text-truncate">Score</span>
                                <i class="fas dt-sort-icon" :class="sortIcon('score')"></i>
                            </div>
                        </th>
                        <th v-if="itemType === 'pair'" class="dt-th">Source</th>
                        <th v-if="itemType === 'pair'" class="dt-th">Target</th>

                        <th v-for="col in visibleColumns" :key="col.key" class="dt-th"
                            :class="{ 'dt-th--sortable': col.sortable, 'dt-th--sorted': sortKey === col.key }"
                            @click="col.sortable ? setSort(col.key) : null">
                            <div class="dt-th-inner">
                                <span class="text-truncate">[[ col.label ]]</span>
                                <i v-if="col.sortable" class="fas dt-sort-icon" :class="sortIcon(col.key)"></i>
                            </div>
                        </th>

                        <th class="dt-th dt-th--actions" style="width:110px;">Actions</th>
                    </tr>
                </thead>

                <tbody>
                    <tr v-if="!loading && filteredItems.length === 0">
                        <td :colspan="12">
                            <div class="dt-empty">
                                <div class="dt-empty-icon"><i class="fas fa-table"></i></div>
                                <p class="dt-empty-text">No results found</p>
                            </div>
                        </td>
                    </tr>

                    <template v-for="item in filteredItems" :key="'row-' + rowKey(item)">
                        <tr class="dt-row" :class="{ 'dt-row--selected': isSelected(item), 'dt-row--expanded': expandedId === rowKey(item) }">

                            <td v-if="selectable" class="dt-td dt-td--checkbox">
                                <input type="checkbox" class="dt-checkbox" :checked="isSelected(item)" @change="toggleItem(item)" />
                            </td>

                            <!-- Pair-specific cells -->
                            <template v-if="itemType === 'pair'">
                                <td class="dt-td">
                                    <div :class="['dup-score-badge', getScoreDetails(item.score).class]" style="width:44px;height:44px;">
                                        <span class="dup-score-badge__pct" style="font-size:.8rem;">[[ getScoreDetails(item.score).val ]]%</span>
                                    </div>
                                </td>
                                <td class="dt-td">
                                    <div class="dup-pair-cell">
                                        <span class="dup-side-tag dup-side-tag--source">A</span>
                                        <span class="dup-title text-truncate" :title="item.rule_a_data.title" v-html="highlight(item.rule_a_data.title)"></span>
                                        <button class="dt-action-btn" title="View" @click="viewDetails(item.rule_a_data.id)">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                    </div>
                                </td>
                                <td class="dt-td">
                                    <div class="dup-pair-cell">
                                        <span class="dup-side-tag dup-side-tag--target">B</span>
                                        <span class="dup-title text-truncate" :title="item.rule_b_data.title" v-html="highlight(item.rule_b_data.title)"></span>
                                        <button class="dt-action-btn" title="View" @click="viewDetails(item.rule_b_data.id)">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                        <span v-if="isIdentical(item)" class="dup-exact-badge" style="font-size:.6rem;padding:.15rem .45rem;">Exact</span>
                                    </div>
                                </td>
                                <td v-if="!hiddenColumns.has('format')" class="dt-td">[[ (item.rule_a_data.format || 'YARA').toUpperCase() ]]</td>
                                <td v-if="!hiddenColumns.has('authors')" class="dt-td">[[ item.rule_a_data.author || 'N/A' ]] / [[ item.rule_b_data.author || 'N/A' ]]</td>
                                <td v-if="!hiddenColumns.has('dates')" class="dt-td">[[ formatDate(item.rule_a_data.creation_date) ]] / [[ formatDate(item.rule_b_data.creation_date) ]]</td>
                            </template>

                            <!-- History-specific cells -->
                            <template v-else>
                                <td v-if="!hiddenColumns.has('date')" class="dt-td">
                                    <div class="fw-bold">[[ formatDate(item.date) ]]</div>
                                    <div class="small text-muted">[[ formatTime(item.date) ]]</div>
                                </td>
                                <td v-if="!hiddenColumns.has('mode')" class="dt-td">
                                    <span :class="['dup-mode-badge', item.mode === 'global' ? 'dup-mode-badge--global' : 'dup-mode-badge--filter']">
                                        [[ item.mode.toUpperCase() ]]
                                    </span>
                                </td>
                                <td v-if="!hiddenColumns.has('info')" class="dt-td dt-td--truncate" v-html="highlight(item.info)"></td>
                                <td v-if="!hiddenColumns.has('total_rules_processed')" class="dt-td">[[ item.total_rules_processed ]]</td>
                                <td v-if="!hiddenColumns.has('similar_pairs_found')" class="dt-td">[[ item.similar_pairs_found ]]</td>
                            </template>

                            <td class="dt-td dt-td--actions">
                                <div class="dt-actions">
                                    <button v-if="itemType === 'history'" class="dt-action-btn" title="View report" @click="goToSession(item)">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                    <button v-if="itemType === 'history' && isAdmin" class="dt-action-btn dt-action-btn--danger" title="Delete"
                                        @click="deleteHistoryItem(item)">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                    <button v-if="itemType === 'pair'" class="dt-action-btn dt-action-btn--expand"
                                        :class="{ 'is-expanded': expandedId === rowKey(item) }" title="Details"
                                        @click="toggleExpand(item)">
                                        <i class="fas fa-chevron-down dt-expand-chevron"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>

                        <!-- Expanded detail row: pairs only -->
                        <tr v-if="itemType === 'pair' && expandedId === rowKey(item)" class="dt-row-expand">
                            <td :colspan="12" class="dt-expand-cell">
                                <div class="dup-expand-detail">
                                    <div class="dup-asset-panel">
                                        <label class="dup-panel-label">Asset Comparison</label>

                                        <div class="dup-asset-card dup-asset-card--a">
                                            <div class="dup-asset-card__head">
                                                <span class="dup-asset-card__side">A · Base Asset</span>
                                                <span class="dup-asset-card__id">ID [[ item.rule_a_data.id ]]</span>
                                            </div>
                                            <div class="dup-asset-card__meta">
                                                <div><i class="fa-solid fa-user fa-fw"></i> [[ item.rule_a_data.author || 'N/A' ]]</div>
                                                <div class="text-truncate"><i class="fa-solid fa-link fa-fw"></i> [[ item.rule_a_data.source || 'N/A' ]]</div>
                                                <div><i class="fa-solid fa-calendar-plus fa-fw"></i> [[ formatDate(item.rule_a_data.creation_date) ]]</div>
                                            </div>
                                            <div class="dup-asset-card__actions">
                                                <button class="dup-btn" @click="viewDetails(item.rule_a_data.id)"><i class="fa-solid fa-eye"></i> View</button>
                                                <template v-if="isAdmin">
                                                    <button class="dup-btn dup-btn--danger" data-bs-toggle="modal" :data-bs-target="'#del_a_row_' + rowKey(item)">
                                                        <i class="fa-solid fa-trash"></i>
                                                    </button>
                                                    <delete-rule-modal :rule="item.rule_a_data" :modal-id="'del_a_row_' + rowKey(item)" @deleted="handleRuleDeleted"></delete-rule-modal>
                                                </template>
                                            </div>
                                        </div>

                                        <div class="dup-asset-card dup-asset-card--b">
                                            <div class="dup-asset-card__head">
                                                <span class="dup-asset-card__side">B · Match Found</span>
                                                <span class="dup-asset-card__id">ID [[ item.rule_b_data.id ]]</span>
                                            </div>
                                            <div class="dup-asset-card__meta">
                                                <div><i class="fa-solid fa-user fa-fw"></i> [[ item.rule_b_data.author || 'N/A' ]]</div>
                                                <div class="text-truncate"><i class="fa-solid fa-link fa-fw"></i> [[ item.rule_b_data.source || 'N/A' ]]</div>
                                                <div><i class="fa-solid fa-calendar-plus fa-fw"></i> [[ formatDate(item.rule_b_data.creation_date) ]]</div>
                                            </div>
                                            <div class="dup-asset-card__actions">
                                                <button class="dup-btn" @click="viewDetails(item.rule_b_data.id)"><i class="fa-solid fa-eye"></i> View</button>
                                                <template v-if="isAdmin">
                                                    <button class="dup-btn dup-btn--danger" data-bs-toggle="modal" :data-bs-target="'#del_b_row_' + rowKey(item)">
                                                        <i class="fa-solid fa-trash"></i>
                                                    </button>
                                                    <delete-rule-modal :rule="item.rule_b_data" :modal-id="'del_b_row_' + rowKey(item)" @deleted="handleRuleDeleted"></delete-rule-modal>
                                                </template>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="dup-diff-panel">
                                        <diff-viewer :initial-left="item.rule_a_data.content || ''" :initial-right="item.rule_b_data.content || ''"
                                            left-label="Original" right-label="Modified" mode="read">
                                        </diff-viewer>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    </template>
                </tbody>
            </table>
        </div>

        <div class="dt-footer">
            <div class="dt-per-page">
                <span>Per page</span>
                <select :value="perPage" @change="$emit('update:per-page', Number($event.target.value))" aria-label="Items per page">
                    <option v-for="n in [10, 20, 50, 100]" :key="n" :value="n">[[ n ]]</option>
                </select>
            </div>
        </div>

        <!-- Bulk bar (History only) -->
        <transition name="dt-bulk-slide">
            <div v-if="showBulkBar" class="dt-bulk-bar">
                <span class="dt-bulk-count">[[ selectedIds.size ]] [[ selectedIds.size === 1 ? 'item' : 'items' ]] selected</span>
                <div class="dt-bulk-actions">
                    <button v-for="action in bulkActions" :key="action.key" class="dt-bulk-btn"
                        :class="action.variant === 'danger' ? 'dt-bulk-btn--danger' : ''"
                        @click="emitBulkAction(action.key)">
                        <i v-if="action.icon" :class="'fas ' + action.icon"></i>
                        [[ action.label ]]
                    </button>
                </div>
                <button class="dt-bulk-clear" @click="clearSelection">
                    <i class="fas fa-xmark"></i> Clear
                </button>
            </div>
        </transition>
    </div>
    `
};

export default DuplicateTable;
