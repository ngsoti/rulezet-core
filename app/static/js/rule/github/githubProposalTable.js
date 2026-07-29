import UserChip from '/static/js/components/UserChip.js';

const { ref, reactive, computed, watch } = Vue;

/**
 * GithubProposalTable — card/table renderer for non-admin GitHub import
 * proposals, admin review panel (Manage GitHub → Community Proposals).
 *
 * Structurally mirrors app/static/js/rule/similarity/duplicateTable.js
 * (card/table toggle, sortable columns, remote search, selection + bulk
 * bar) but for a single flat item type instead of pair/history.
 *
 * Purely presentational for pagination/fetch — the parent owns fetching the
 * current page; this component only sorts/searches (locally, unless
 * remoteSearch) the items it's given, and emits bulk-decision for accept/reject.
 */
const GithubProposalTable = {
    name: 'GithubProposalTable',
    components: { UserChip },
    delimiters: ['[[', ']]'],
    props: {
        items: { type: Array, required: true },
        loading: { type: Boolean, default: false },
        isAdmin: { type: Boolean, default: false },
        defaultView: { type: String, default: 'table' }, // 'table' | 'card'
        perPage: { type: Number, default: 20 },
        remoteSearch: { type: Boolean, default: false },
    },
    emits: ['refresh', 'bulk-decision', 'delete', 'bulk-delete', 'update:per-page', 'search'],
    setup(props, { emit }) {
        const viewMode = ref(props.defaultView);
        const search = ref('');
        let searchDebounce = null;

        watch(search, (val) => {
            if (!props.remoteSearch) return;
            clearTimeout(searchDebounce);
            searchDebounce = setTimeout(() => emit('search', val), 350);
        });

        const sortKey = ref('created_at');
        const sortDir = ref('desc');
        const hiddenColumns = reactive(new Set());
        const showColPicker = ref(false);
        const selectedIds = reactive(new Set());
        const statusFilter = ref('all');

        watch(() => props.items, () => { /* no per-row expand state to reset */ });

        const COLUMNS = [
            { key: 'requester', label: 'Requester', sortable: true, hideable: false },
            { key: 'branch', label: 'Branch', sortable: true, hideable: true },
            { key: 'license', label: 'License', sortable: true, hideable: true },
            { key: 'status', label: 'Status', sortable: true, hideable: false },
            { key: 'created_at', label: 'Submitted', sortable: true, hideable: true },
        ];

        const columns = COLUMNS;
        const visibleColumns = computed(() => COLUMNS.filter(c => !hiddenColumns.has(c.key)));

        function toggleColumn(key) {
            if (hiddenColumns.has(key)) hiddenColumns.delete(key);
            else hiddenColumns.add(key);
        }

        function rowKey(item) { return item.uuid; }

        function formatDate(dateStr) {
            if (!dateStr) return 'N/A';
            return String(dateStr).split(' ')[0];
        }

        function goToDetail(item) {
            window.location.href = `/rule/github_proposal_detail/${item.uuid}`;
        }

        // ── Search highlight ──────────────────────────────────────────────
        function escapeHtml(str) {
            return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }
        function highlight(text) {
            const str = escapeHtml(text ?? '');
            const term = search.value.trim();
            if (!term) return str;
            try {
                const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                return str.replace(new RegExp(`(${escaped})`, 'gi'), m => `<mark class="gpt-highlight">${m}</mark>`);
            } catch {
                return str;
            }
        }

        // ── Search + status filter + sort ─────────────────────────────────
        function matchesSearch(item) {
            if (props.remoteSearch) return true;
            if (!search.value.trim()) return true;
            const needle = search.value.toLowerCase();
            const haystacks = [item.repo_url, item.requester_username, item.message];
            return haystacks.some(h => String(h ?? '').toLowerCase().includes(needle));
        }

        function matchesStatusFilter(item) {
            return statusFilter.value === 'all' || item.status === statusFilter.value;
        }

        function sortValue(item, key) {
            switch (key) {
                case 'requester': return item.requester_username;
                default: return item[key];
            }
        }

        const filteredItems = computed(() => {
            let list = props.items.filter(i => matchesSearch(i) && matchesStatusFilter(i));
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

        // ── Selection + bulk bar ───────────────────────────────────────────
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
        const showBulkBar = computed(() => selectedIds.size > 0);
        const selectedAllPending = computed(() =>
            props.items.filter(i => selectedIds.has(rowKey(i))).every(i => i.status === 'pending')
        );

        function emitBulkDecision(decision) {
            const uuids = props.items.filter(i => selectedIds.has(rowKey(i))).map(i => i.uuid);
            emit('bulk-decision', { uuids, decision });
            clearSelection();
        }

        function deleteItem(item) {
            if (!confirm(`Delete the proposal for ${item.repo_url}?`)) return;
            emit('delete', item.uuid);
        }

        function bulkDelete() {
            const uuids = props.items.filter(i => selectedIds.has(rowKey(i))).map(i => i.uuid);
            if (!uuids.length) return;
            if (!confirm(`Delete ${uuids.length} selected proposal(s)?`)) return;
            emit('bulk-delete', uuids);
            clearSelection();
        }

        return {
            viewMode, search, sortKey, sortDir, hiddenColumns, showColPicker,
            selectedIds, statusFilter, columns, visibleColumns, toggleColumn,
            rowKey, formatDate, goToDetail, highlight,
            filteredItems, setSort, sortIcon,
            isSelected, toggleItem, allOnPageSelected, someOnPageSelected,
            togglePageSelection, clearSelection, showBulkBar, selectedAllPending, emitBulkDecision,
            deleteItem, bulkDelete,
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
                    <input class="dt-search-input" type="text" placeholder="Search repo, requester, message…"
                        v-model="search" aria-label="Search" />
                    <button v-if="search" class="dt-search-clear" @click="search = ''" aria-label="Clear search">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>
                <select v-model="statusFilter" class="dt-toolbar-btn" style="padding:.4rem .6rem;" aria-label="Filter by status">
                    <option value="all">All statuses</option>
                    <option value="pending">Pending</option>
                    <option value="accepted">Accepted</option>
                    <option value="imported">Imported</option>
                    <option value="rejected">Rejected</option>
                    <option value="failed">Failed</option>
                    <option value="transferred">Transferred</option>
                </select>
            </div>

            <div class="dt-toolbar-right">
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

        <p v-if="!remoteSearch" class="gpt-search-hint">Searching current page only ([[ items.length ]] item[[ items.length === 1 ? '' : 's' ]] loaded)</p>
        <p v-else class="gpt-search-hint">Searching across all results</p>

        <!-- ══════════ CARD VIEW ══════════ -->
        <template v-if="viewMode === 'card'">
            <div class="dt-card-grid">
                <div v-if="!loading && filteredItems.length === 0" style="grid-column: 1 / -1;">
                    <div class="dt-empty">
                        <div class="dt-empty-icon"><i class="fas fa-grip"></i></div>
                        <p class="dt-empty-text">No proposals found</p>
                    </div>
                </div>
                <div v-for="item in filteredItems" :key="'card-' + rowKey(item)" class="gpt-card">
                    <div class="gpt-card__top">
                        <input type="checkbox" class="dt-checkbox" :checked="isSelected(item)"
                            @click.stop @change="toggleItem(item)" />
                        <span :class="['gpt-status-badge', 'gpt-status-badge--' + item.status]">[[ item.status ]]</span>
                    </div>
                    <div class="gpt-card__repo text-truncate" :title="item.repo_url" v-html="highlight(item.repo_url)"></div>
                    <div class="gpt-card__meta">
                        <user-chip :user-id="item.user_id" :username="item.requester_username" :avatar="item.requester_avatar" size="xs"></user-chip>
                        <span v-if="item.branch" class="text-muted"><i class="fas fa-code-branch me-1"></i>[[ item.branch ]]</span>
                        <span v-if="item.license" class="gpt-license-badge">[[ item.license ]]</span>
                    </div>
                    <div class="gpt-card__date text-muted">[[ item.created_at ]]</div>
                    <div class="gpt-card__actions">
                        <button class="gpt-btn" @click="goToDetail(item)"><i class="fa-solid fa-eye"></i> View</button>
                        <button v-if="isAdmin" class="gpt-btn gpt-btn--danger" @click="deleteItem(item)"><i class="fa-solid fa-trash"></i></button>
                    </div>
                </div>
            </div>
        </template>

        <!-- ══════════ TABLE VIEW ══════════ -->
        <div v-else class="dt-table-wrap">
            <table class="dt-table" role="grid">
                <thead class="dt-thead">
                    <tr>
                        <th class="dt-th dt-th--checkbox">
                            <input type="checkbox" class="dt-checkbox" :checked="allOnPageSelected"
                                :indeterminate="someOnPageSelected" @change="togglePageSelection" aria-label="Select all" />
                        </th>

                        <th class="dt-th">Repository</th>

                        <th v-for="col in visibleColumns" :key="col.key" class="dt-th"
                            :class="{ 'dt-th--sortable': col.sortable, 'dt-th--sorted': sortKey === col.key }"
                            @click="col.sortable ? setSort(col.key) : null">
                            <div class="dt-th-inner">
                                <span class="text-truncate">[[ col.label ]]</span>
                                <i v-if="col.sortable" class="fas dt-sort-icon" :class="sortIcon(col.key)"></i>
                            </div>
                        </th>

                        <th class="dt-th dt-th--actions" style="width:90px;">Actions</th>
                    </tr>
                </thead>

                <tbody>
                    <tr v-if="!loading && filteredItems.length === 0">
                        <td :colspan="8">
                            <div class="dt-empty">
                                <div class="dt-empty-icon"><i class="fas fa-table"></i></div>
                                <p class="dt-empty-text">No proposals found</p>
                            </div>
                        </td>
                    </tr>

                    <tr v-for="item in filteredItems" :key="'row-' + rowKey(item)"
                        class="dt-row" :class="{ 'dt-row--selected': isSelected(item) }">

                        <td class="dt-td dt-td--checkbox">
                            <input type="checkbox" class="dt-checkbox" :checked="isSelected(item)" @change="toggleItem(item)" />
                        </td>

                        <td class="dt-td gpt-name-cell">
                            <div class="gpt-pair-cell">
                                <i class="fa-brands fa-github text-muted"></i>
                                <span class="gpt-title" :title="item.repo_url" v-html="highlight(item.repo_url)"></span>
                            </div>
                        </td>

                        <td v-if="!hiddenColumns.has('requester')" class="dt-td">
                            <user-chip :user-id="item.user_id" :username="item.requester_username" :avatar="item.requester_avatar" size="xs"></user-chip>
                        </td>
                        <td v-if="!hiddenColumns.has('branch')" class="dt-td">[[ item.branch || 'default' ]]</td>
                        <td v-if="!hiddenColumns.has('license')" class="dt-td">
                            <span v-if="item.license" class="gpt-license-badge">[[ item.license ]]</span>
                            <span v-else class="text-muted">N/A</span>
                        </td>
                        <td v-if="!hiddenColumns.has('status')" class="dt-td">
                            <span :class="['gpt-status-badge', 'gpt-status-badge--' + item.status]">[[ item.status ]]</span>
                        </td>
                        <td v-if="!hiddenColumns.has('created_at')" class="dt-td">[[ formatDate(item.created_at) ]]</td>

                        <td class="dt-td dt-td--actions">
                            <div class="dt-actions">
                                <button class="dt-action-btn" title="View proposal" @click="goToDetail(item)">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <button v-if="isAdmin" class="dt-action-btn dt-action-btn--danger" title="Delete proposal" @click="deleteItem(item)">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
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

        <!-- Bulk bar: accept / reject -->
        <transition name="dt-bulk-slide">
            <div v-if="showBulkBar" class="dt-bulk-bar">
                <span class="dt-bulk-count">[[ selectedIds.size ]] [[ selectedIds.size === 1 ? 'item' : 'items' ]] selected</span>
                <div class="dt-bulk-actions">
                    <template v-if="selectedAllPending">
                        <button class="dt-bulk-btn" @click="emitBulkDecision('accept')">
                            <i class="fas fa-check"></i> Accept
                        </button>
                        <button class="dt-bulk-btn dt-bulk-btn--danger" @click="emitBulkDecision('reject')">
                            <i class="fas fa-xmark"></i> Reject
                        </button>
                    </template>
                    <button v-if="isAdmin" class="dt-bulk-btn dt-bulk-btn--danger" @click="bulkDelete()">
                        <i class="fas fa-trash"></i> Delete
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

export default GithubProposalTable;
