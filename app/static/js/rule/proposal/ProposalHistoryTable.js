import PaginationComponent from '/static/js/rule/paginationComponent.js';
import { create_message } from '/static/js/toaster.js';

const ProposalHistoryTable = {
    props: {
        csrfToken: { type: String, required: true },
        apiEndpoint: { type: String, default: '/rule/get_rules_propose_edit_history_page' },
        submitEndpoint: { type: String, default: '/rule/manage_proposals' },
        showManage: { type: Boolean, default: false },
        showDiffButton: { type: Boolean, default: true }
    },
    emits: ['view-diff', 'decision-made'],
    delimiters: ['[[', ']]'],
    components: { 'pagination-component': PaginationComponent },
    data() {
        return {
            proposals: [],
            groupedProposals: [],
            expandedRules: new Set(),
            expandedProposals: new Set(),
            totalPages: 1,
            currentPage: 1,
            totalCount: 0,
            transitioning: false,
            initialLoad: true,
            loading: false,
            searchQuery: '',
            statusFilter: '',
            searchTimer: null,
            // available statuses based on actual data
            availableStatuses: new Set(),
            selectedIds: new Set(),
            excludedIds: new Set(),
            isAllSelectedMode: false,
        };
    },
    computed: {
        selectedCount() {
            if (this.isAllSelectedMode) return this.totalCount - this.excludedIds.size;
            return this.selectedIds.size;
        },
        allPendingOnPage() {
            return this.proposals.filter(p => p.status === 'pending');
        },
        isPageFullySelected() {
            if (this.allPendingOnPage.length === 0) return false;
            return this.allPendingOnPage.every(p => this.isChecked(p.id));
        },
        hasPendingTotal() {
            return this.groupedProposals.some(g => g.counts.pending > 0);
        },
        statusOptions() {
            const all = [
                { value: 'pending', label: 'Pending' },
                { value: 'accepted', label: 'Accepted' },
                { value: 'rejected', label: 'Rejected' },
            ];
            return all.filter(opt => this.availableStatuses.has(opt.value));
        }
    },
    methods: {
        async fetchProposals(page = 1) {
            // soft transition — don't flash empty state, just fade
            if (!this.initialLoad) {
                this.transitioning = true;
                await new Promise(r => setTimeout(r, 150));
            }
            this.loading = true;
            try {
                const params = new URLSearchParams({
                    page,
                    search: this.searchQuery,
                    status: this.statusFilter,
                });
                const res = await fetch(`${this.apiEndpoint}?${params.toString()}`);
                if (res.ok) {
                    const data = await res.json();
                    this.proposals = data.rules_list || data.rules_pendings_list || [];
                    this.totalPages = data.total_pages_old || data.total_pages_pending || 1;
                    this.totalCount = data.total_count || 0;
                    this.currentPage = page;
                    this.groupProposals();
                    this.expandedRules = new Set();
                    this.expandedProposals = new Set();
                    // update available statuses from all loaded data
                    this.proposals.forEach(p => this.availableStatuses.add(p.status));
                }
            } catch (err) {
                console.error("Fetch error:", err);
            } finally {
                this.loading = false;
                this.transitioning = false;
                this.initialLoad = false;
            }
        },

        groupProposals() {
            const map = new Map();
            for (const p of this.proposals) {
                if (!map.has(p.rule_id)) {
                    map.set(p.rule_id, {
                        rule_id: p.rule_id,
                        rule_name: p.rule_name,
                        proposals: [],
                        counts: { pending: 0, accepted: 0, rejected: 0 }
                    });
                }
                const group = map.get(p.rule_id);
                group.proposals.push(p);
                if (p.status in group.counts) group.counts[p.status]++;
            }
            this.groupedProposals = Array.from(map.values());
        },

        onSearchInput() {
            clearTimeout(this.searchTimer);
            this.searchTimer = setTimeout(() => this.fetchProposals(1), 350);
        },

        toggleRule(ruleId) {
            const s = new Set(this.expandedRules);
            s.has(ruleId) ? s.delete(ruleId) : s.add(ruleId);
            this.expandedRules = s;
        },

        toggleProposal(id) {
            const s = new Set(this.expandedProposals);
            s.has(id) ? s.delete(id) : s.add(id);
            this.expandedProposals = s;
        },

        isChecked(id) {
            if (this.isAllSelectedMode) return !this.excludedIds.has(id);
            return this.selectedIds.has(id);
        },

        updateSelection(id, checked) {
            if (this.isAllSelectedMode) {
                checked ? this.excludedIds.delete(id) : this.excludedIds.add(id);
            } else {
                checked ? this.selectedIds.add(id) : this.selectedIds.delete(id);
            }
        },

        toggleAllOnPage(checked) {
            this.allPendingOnPage.forEach(p => this.updateSelection(p.id, checked));
        },

        selectAll() {
            if (!this.hasPendingTotal || this.loading) return;
            this.isAllSelectedMode = true;
            this.selectedIds.clear();
            this.excludedIds.clear();
        },

        clearSelection() {
            this.isAllSelectedMode = false;
            this.selectedIds.clear();
            this.excludedIds.clear();
        },

        async submitBulk(action) {
            if (this.selectedCount === 0) return;
            this.loading = true;
            try {
                const res = await fetch(this.submitEndpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': this.csrfToken
                    },
                    body: JSON.stringify({
                        action,
                        mode: this.isAllSelectedMode ? 'all' : 'partial',
                        selected_ids: Array.from(this.selectedIds),
                        excluded_ids: Array.from(this.excludedIds),
                    })
                });
                const result = await res.json();
                create_message(result.message, result.toast_class);
                if (res.ok) {
                    this.clearSelection();
                    this.fetchProposals(this.currentPage);
                    this.$emit('decision-made'); 
                }
            } catch (err) {
                create_message("An error occurred.", "danger-subtle");
            } finally {
                this.loading = false;
            }
        },

        async handleDecision(proposalId, decision, ruleId) {
            try {
                const res = await fetch(`/rule/validate_proposal?ruleId=${ruleId}&decision=${decision}&ruleproposalId=${proposalId}`);
                const result = await res.json();
                if (res.status === 200) {
                    this.fetchProposals(this.currentPage);
                    this.$emit('decision-made');  
                }
                create_message(result.message, result.toast_class);
            } catch (err) {
                create_message("An error occurred.", "danger-subtle");
            }
        },
        statusClass(status) {
            return {
                'bg-secondary': status === 'pending',
                'bg-success': status === 'accepted',
                'bg-danger': status === 'rejected',
            };
        },

        viewDiff(proposal) { this.$emit('view-diff', proposal); },

        formatDate(ts) {
            if (!ts) return 'N/A';
            return new Date(ts).toLocaleDateString('en-GB', {
                day: '2-digit', month: 'short', year: 'numeric'
            });
        }
    },
    mounted() { this.fetchProposals(1); },
    template: `
    <div class="proposal-history-container" v-cloak>

        <!-- Bulk toolbar -->
        <transition name="fade">
            <div v-if="showManage && selectedCount > 0"
                class="d-flex align-items-center justify-content-between p-3 mb-4 rounded-3 shadow-sm"
                style=" border: 1px solid var(--border-color);">
                <div class="d-flex align-items-center gap-3">
                    <span class="fw-bold">
                        <i class="fas fa-check-square me-2 text-primary"></i>
                        [[ selectedCount ]] proposal(s) selected
                        <span v-if="isAllSelectedMode" class="badge bg-primary ms-1">All results</span>
                    </span>
                    <button class="btn btn-sm btn-outline-secondary rounded-pill" @click="clearSelection">
                        <i class="fas fa-times me-1"></i> Clear
                    </button>
                </div>
                <div class="d-flex gap-2">
                    <button class="btn btn-sm btn-success rounded-pill px-3"
                        :disabled="loading" @click="submitBulk('accept')">
                        <i class="fas fa-check me-1"></i> Accept [[ selectedCount ]]
                    </button>
                    <button class="btn btn-sm btn-danger rounded-pill px-3"
                        :disabled="loading" @click="submitBulk('reject')">
                        <i class="fas fa-times me-1"></i> Reject [[ selectedCount ]]
                    </button>
                </div>
            </div>
        </transition>

        <!-- Search & filter bar -->
        <div class="d-flex gap-3 mb-4 flex-wrap align-items-end">
            <div class="flex-grow-1">
                <label class="small fw-bold text-muted mb-1 text-uppercase">Search</label>
                <div class="input-group input-group-sm shadow-sm" style="border-radius: 10px; overflow: hidden;">
                    <span class="input-group-text border-0 bg-light">
                        <div v-if="loading" class="spinner-border spinner-border-sm text-primary" role="status"></div>
                        <i v-else class="fas fa-search text-muted"></i>
                    </span>
                    <input type="text" v-model="searchQuery" @input="onSearchInput"
                        class="form-control border-0 bg-light"
                        placeholder="Search by rule name or contributor..."
                        style="height: 36px;">
                    <span v-if="searchQuery" @click="searchQuery = ''; fetchProposals(1)"
                        class="input-group-text border-0 bg-light text-muted" style="cursor: pointer;">
                        <i class="fas fa-times"></i>
                    </span>
                </div>
            </div>

            <!-- Status filters — only show statuses present in data -->
            <div v-if="statusOptions.length > 0">
                <label class="small fw-bold text-muted mb-1 text-uppercase">Status</label>
                <div class="d-flex gap-1 flex-wrap">
                    <button
                        @click="statusFilter = ''; fetchProposals(1)"
                        class="btn btn-sm rounded-pill px-3"
                        :class="statusFilter === '' ? 'btn-dark' : 'btn-outline-secondary'">
                        All
                    </button>
                    <button v-for="opt in statusOptions" :key="opt.value"
                        @click="statusFilter = opt.value; fetchProposals(1)"
                        class="btn btn-sm rounded-pill px-3"
                        :class="statusFilter === opt.value ? 'btn-dark' : 'btn-outline-secondary'">
                        [[ opt.label ]]
                    </button>
                </div>
            </div>

            <div v-if="showManage && hasPendingTotal" class="ms-auto">
                <label class="small fw-bold text-muted mb-1 text-uppercase d-block">&nbsp;</label>
                <button class="btn btn-sm btn-outline-primary rounded-pill px-3"
                    @click="selectAll"
                    :disabled="!hasPendingTotal || loading">
                    <i class="fas fa-check-double me-1"></i> All results
                </button>
            </div>
        </div>

        <!-- Table wrapper with opacity transition instead of mount/unmount -->
        <div :style="{ opacity: transitioning ? 0 : 1, transition: 'opacity 0.15s ease' }">

            <!-- Initial loading skeleton -->
            <div v-if="initialLoad && loading"
                class="custom-table-wrapper border rounded-4 overflow-hidden mb-4 shadow-sm">
                <table class="table align-middle mb-0 custom-table">
                    <thead>
                        <tr class="text-muted small fw-bold text-uppercase"
                          >
                            <th style="width: 40px;"></th>
                            <th v-if="showManage" style="width: 40px;"></th>
                            <th>Rule</th>
                            <th class="text-center">Total</th>
                            <th class="text-center"><span class="badge bg-success">Accepted</span></th>
                            <th class="text-center"><span class="badge bg-danger">Rejected</span></th>
                            <th class="text-center"><span class="badge bg-secondary">Pending</span></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="i in 5" :key="i">
                            <td><div class="skeleton-line" style="width: 20px;"></div></td>
                            <td v-if="showManage"><div class="skeleton-line" style="width: 16px;"></div></td>
                            <td>
                                <div class="skeleton-line mb-1" style="width: 55%;"></div>
                                <div class="skeleton-line" style="width: 25%;"></div>
                            </td>
                            <td class="text-center"><div class="skeleton-line mx-auto" style="width: 24px;"></div></td>
                            <td class="text-center"><div class="skeleton-line mx-auto" style="width: 24px;"></div></td>
                            <td class="text-center"><div class="skeleton-line mx-auto" style="width: 24px;"></div></td>
                            <td class="text-center"><div class="skeleton-line mx-auto" style="width: 24px;"></div></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Empty state -->
            <div v-else-if="!loading && groupedProposals.length === 0"
                class="text-center py-5 rounded-4 border">
                <i class="fas fa-inbox fa-3x mb-3 text-muted opacity-25"></i>
                <h5 class="fw-bold">No proposals found</h5>
                <p class="text-muted small">Try adjusting your filters.</p>
            </div>

            <!-- Table -->
            <div v-else class="custom-table-wrapper border rounded-4 overflow-hidden shadow-sm mb-4">
                <table class="table align-middle mb-0">
                    <thead>
                        <tr class="bg-light text-muted small fw-bold"
                           >
                            <th style="width: 40px;"></th>
                            <th v-if="showManage" style="width: 40px;" class="text-center">
                                <input type="checkbox"
                                    :checked="isPageFullySelected"
                                    :disabled="allPendingOnPage.length === 0"
                                    @change="toggleAllOnPage($event.target.checked)">
                            </th>
                            <th>Rule</th>
                            <th class="text-center">Total</th>
                            <th class="text-center"><span class="badge bg-success">Accepted</span></th>
                            <th class="text-center"><span class="badge bg-danger">Rejected</span></th>
                            <th class="text-center"><span class="badge bg-secondary">Pending</span></th>
                        </tr>
                    </thead>
                    <tbody>
                        <template v-for="group in groupedProposals" :key="group.rule_id">

                            <!-- Group row -->
                            <!-- Group row -->
<tr @click="toggleRule(group.rule_id)" style="cursor: pointer;"
    :class="[
        expandedRules.has(group.rule_id) ? 'table-active' : '',
        group.counts.pending > 0 ? 'row-pending' : ''
    ]">
                                <td class="text-center">
                                    <i class="fas text-muted"
                                        :class="expandedRules.has(group.rule_id) ? 'fa-chevron-down' : 'fa-chevron-right'">
                                    </i>
                                </td>
                               <td v-if="showManage" class="text-center" @click.stop>
                                    <input v-if="group.counts.pending > 0"
                                        type="checkbox"
                                        :checked="group.proposals.filter(p => p.status === 'pending').length > 0 &&
                                                group.proposals.filter(p => p.status === 'pending').every(p => isChecked(p.id))"
                                        @change="group.proposals.filter(p => p.status === 'pending').forEach(p => updateSelection(p.id, $event.target.checked))">
                                    <span v-else class="text-muted small">—</span>
                                </td>
                                <td>
                                    <div class="fw-bold">[[ group.rule_name ]]</div>
                                    <div class="x-small text-muted font-monospace">Rule #[[ group.rule_id ]]</div>
                                </td>
                                <td class="text-center fw-bold">[[ group.proposals.length ]]</td>
                                <td class="text-center">
                                    <span v-if="group.counts.accepted > 0" class="fw-bold text-success">
                                        [[ group.counts.accepted ]]
                                    </span>
                                    <span v-else class="text-muted">—</span>
                                </td>
                                <td class="text-center">
                                    <span v-if="group.counts.rejected > 0" class="fw-bold text-danger">
                                        [[ group.counts.rejected ]]
                                    </span>
                                    <span v-else class="text-muted">—</span>
                                </td>
                                <td class="text-center">
                                    <span v-if="group.counts.pending > 0" class="fw-bold text-secondary">
                                        [[ group.counts.pending ]]
                                    </span>
                                    <span v-else class="text-muted">—</span>
                                </td>
                            </tr>

                            <!-- Proposals inside group -->
                            <template v-if="expandedRules.has(group.rule_id)">
                                <tr v-for="prop in group.proposals" :key="prop.id"
                                    :class="isChecked(prop.id) ? 'table-primary-subtle' : ''"
                                    style="border-left: 3px solid var(--bs-primary);">
                                    <td></td>
                                    <td v-if="showManage" class="text-center" @click.stop>
                                        <input v-if="prop.status === 'pending'"
                                            type="checkbox"
                                            :checked="isChecked(prop.id)"
                                            @change="updateSelection(prop.id, $event.target.checked)">
                                        <span v-else class="text-muted x-small">—</span>
                                    </td>
                                    <td :colspan="showManage ? 5 : 6" class="py-2 ps-3">

                                        <!-- Summary row -->
                                        <div class="d-flex align-items-center gap-2 flex-wrap mb-1">
                                            <button class="btn btn-link btn-sm p-0 text-dark"
                                                @click.stop="toggleProposal(prop.id)">
                                                <i class="fas"
                                                    :class="expandedProposals.has(prop.id) ? 'fa-chevron-down' : 'fa-chevron-right'">
                                                </i>
                                            </button>
                                            <span class="badge rounded-pill" :class="statusClass(prop.status)">
                                                [[ prop.status ]]
                                            </span>
                                            <span class="small fw-semibold">
                                                <i class="fas fa-user me-1 text-muted"></i>[[ prop.user_name ]]
                                            </span>
                                            <span class="x-small text-muted">
                                                <i class="fas fa-calendar me-1"></i>[[ formatDate(prop.timestamp) ]]
                                            </span>
                                            <span class="badge bg-light text-dark border small">
                                                [[ prop.edit_type ]]
                                            </span>
                                            <span class="small fw-bold"
                                                :class="prop.change_score > 80 ? 'text-success' : 'text-primary'">
                                                [[ prop.change_score ]]%
                                            </span>
                                        </div>

                                        <!-- Expanded detail -->
                                        <div v-if="expandedProposals.has(prop.id)"
                                            class="mt-2 ps-4 pb-2 border-top pt-2">
                                            <div class="row g-3">
                                                <div class="col-md-7">
                                                    <p class="small mb-2">
                                                        <span class="fw-bold text-muted text-uppercase"
                                                            style="font-size: 0.7rem;">Message</span><br>
                                                        [[ prop.message || 'No message provided.' ]]
                                                    </p>
                                                    <p v-if="prop.rejection_reason" class="small mb-2 text-danger">
                                                        <span class="fw-bold text-uppercase"
                                                            style="font-size: 0.7rem;">Rejection reason</span><br>
                                                        [[ prop.rejection_reason ]]
                                                    </p>
                                                    <p v-if="prop.reviewed_at" class="x-small text-muted mb-0">
                                                        Reviewed on [[ formatDate(prop.reviewed_at) ]]
                                                    </p>
                                                </div>
                                                <div class="col-md-5">
                                                    <p class="x-small text-muted mb-1">
                                                        Proposal <span class="font-monospace">#[[ prop.id ]]</span>
                                                    </p>
                                                    <p class="x-small text-muted mb-3">
                                                        [[ prop.comments ? prop.comments.length : 0 ]] comment(s)
                                                    </p>
                                                    <div class="d-flex gap-2 flex-wrap align-items-center">
                                                        <a :href="'/rule/proposal_content_discuss?id=' + prop.id"
                                                            class="btn btn-sm rounded-pill px-3 fw-semibold"
                                                            style="background: var(--light-bg-color); color: var(--text-color); border: 1px solid var(--border-color);">
                                                            <i class="fas fa-comments me-1 opacity-75"></i> Discuss
                                                        </a>

                                                        <button v-if="showDiffButton"
                                                            class="btn btn-sm rounded-pill px-3 fw-semibold"
                                                            style="background: var(--light-bg-color); color: var(--text-color); border: 1px solid var(--border-color);"
                                                            type="button"
                                                            data-bs-toggle="modal"
                                                            data-bs-target="#fullscreenDiffModal"
                                                            @click.stop="viewDiff(prop)">
                                                            <i class="fas fa-code-compare me-1 opacity-75"></i> Diff
                                                        </button>

                                                        <a :href="'/rule/detail_rule/' + prop.rule_id"
                                                            class="btn btn-sm rounded-pill px-3 fw-semibold"
                                                            style="background: var(--light-bg-color); color: var(--text-color); border: 1px solid var(--border-color);">
                                                            <i class="fas fa-arrow-up-right-from-square me-1 opacity-75"></i> Rule
                                                        </a>

                                                        <template v-if="showManage && prop.status === 'pending'">
                                                            <div class="vr mx-1" style="opacity: 0.2;"></div>
                                                            <button class="btn btn-sm rounded-pill px-3 fw-semibold"
                                                                style="background: rgba(25,135,84,0.1); color: #198754; border: 1px solid rgba(25,135,84,0.25);"
                                                                @click.stop="handleDecision(prop.id, 'accepted', prop.rule_id)">
                                                                <i class="fas fa-check me-1"></i> Accept
                                                            </button>
                                                            <button class="btn btn-sm rounded-pill px-3 fw-semibold"
                                                                style="background: rgba(220,53,69,0.1); color: #dc3545; border: 1px solid rgba(220,53,69,0.25);"
                                                                @click.stop="handleDecision(prop.id, 'rejected', prop.rule_id)">
                                                                <i class="fas fa-times me-1"></i> Reject
                                                            </button>
                                                        </template>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                            </template>

                        </template>
                    </tbody>
                </table>
            </div>

            <pagination-component
                :current-page="currentPage"
                :total-pages="totalPages"
                @change-page="fetchProposals">
            </pagination-component>

        </div>
    </div>
    `
};

export default ProposalHistoryTable;