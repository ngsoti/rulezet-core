import PaginationComponent from '/static/js/rule/paginationComponent.js';

const ProposalSelectionTable = {
    props: {
        csrfToken: { type: String, required: true },
        submitEndpoint: { type: String, required: true }
    },
    delimiters: ['[[', ']]'],
    components: {
        'pagination-component': PaginationComponent
    },
    data() {
        return {
            proposals: [], 
            allLoadedProposals: new Map(), 
            expandedRows: new Set(),
            totalProposals: 0,
            currentPage: 1,
            totalPages: 1,
            loading: false,
            
            selectedIds: new Set(),      
            excludedIds: new Set(),      
            isAllSelectedMode: false
        };
    },
    computed: {
        selectedCount() {
            if (this.isAllSelectedMode) {
                return this.totalProposals - this.excludedIds.size;
            }
            return this.selectedIds.size;
        },
        isPageFullySelected() {
            if (this.proposals.length === 0) return false;
            return this.proposals.every(p => this.isProposalChecked(p.id));
        },
        displayedSelection() {
            const items = [];
            if (!this.isAllSelectedMode) {
                for (let id of this.selectedIds) {
                    const prop = this.allLoadedProposals.get(id);
                    items.push({ id: id, title: prop ? prop.rule_name : `ID: ${id}` });
                    if (items.length >= 50) break;
                }
            }
            return items;
        }
    },
    methods: {
        async fetchRules(page) {
            this.loading = true;
            try {
                const res = await fetch('/rule/get_rules_propose_edit_page?page=' + page);
                if (res.ok) {
                    const data = await res.json();
                    this.proposals = data.rules_pendings_list || [];
                    this.totalPages = data.total_pages_pending || 1;
                    this.currentPage = page;
                    this.proposals.forEach(p => this.allLoadedProposals.set(p.id, p));
                    this.totalProposals = data.total_count || (this.totalPages * 10); 
                }
            } catch (err) {
                console.error("Fetch error:", err);
            } finally {
                this.loading = false;
                this.expandedRows.clear();
            }
        },

        async handleDecision(ruleProposalId, decision, ruleId) {
            this.loading = true;
            try {
                const res = await fetch(`/rule/validate_proposal?ruleId=${ruleId}&decision=${decision}&ruleproposalId=${ruleProposalId}`);
                const result = await res.json();
                if (res.status === 200) {
                    this.fetchRules(this.currentPage);
                }
                // Global toast function if available
                if (typeof create_message !== 'undefined') {
                    create_message(result.message, result.toast_class);
                }
            } catch (err) {
                console.error("Decision error:", err);
            } finally {
                this.loading = false;
            }
        },

        openDiffModal(prop) {
            // Emits the event to the parent to trigger renderDiff in the modal
            this.$emit('view-diff', prop);
        },

        toggleRow(proposalId) {
            if (this.expandedRows.has(proposalId)) this.expandedRows.delete(proposalId);
            else this.expandedRows.add(proposalId);
        },

        toggleAllOnPage(event) {
            const checked = event.target.checked;
            this.proposals.forEach(p => this.updateSelection(p.id, checked));
        },

        updateSelection(id, isChecked) {
            if (this.isAllSelectedMode) {
                if (!isChecked) this.excludedIds.add(id);
                else this.excludedIds.delete(id);
            } else {
                if (isChecked) this.selectedIds.add(id);
                else this.selectedIds.delete(id);
            }
        },

        isProposalChecked(id) {
            if (this.isAllSelectedMode) return !this.excludedIds.has(id);
            return this.selectedIds.has(id);
        },

        toggleGlobalSelectAll() {
            this.isAllSelectedMode = true;
            this.selectedIds.clear();
            this.excludedIds.clear();
        },

        clearAllSelection() {
            this.isAllSelectedMode = false;
            this.selectedIds.clear();
            this.excludedIds.clear();
        },

        async submitSelection(actionType) {
            this.loading = true;
            const payload = {
                action: actionType, 
                mode: this.isAllSelectedMode ? 'all' : 'partial',
                selected_ids: Array.from(this.selectedIds),
                excluded_ids: Array.from(this.excludedIds)
            };

            try {
                const response = await fetch(this.submitEndpoint, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json', 
                        'X-CSRFToken': this.csrfToken 
                    },
                    body: JSON.stringify(payload)
                });

                if (response.ok) {
                    alert(`Bulk ${actionType} successful.`);
                    this.clearAllSelection();
                    this.fetchRules(this.currentPage);
                }
            } catch (err) {
                alert("An error occurred during bulk processing.");
            } finally {
                this.loading = false;
            }
        }
    },
    mounted() {
        this.fetchRules(1);
    },
    template: `
    <div class="proposal-selection-container">
        <div v-if="proposals.length > 0" class="selection-status-card mb-4 shadow-sm border-0 card p-3">
            <div class="d-flex justify-content-between align-items-center">
                <div class="d-flex align-items-center">
                    <div class="selection-icon-box bg-primary text-white me-3 p-2 rounded">
                        <i class="fas fa-tasks"></i>
                        <span v-if="selectedCount > 0" class="selection-badge ms-1 badge bg-danger">[[ selectedCount ]]</span>
                    </div>
                    <div>
                        <h6 class="mb-0 fw-bold">Management Toolbar</h6>
                        <p class="text-muted small mb-0">[[ isAllSelectedMode ? 'Mode: All Results' : 'Mode: Manual Selection' ]]</p>
                    </div>
                </div>
                
                <div class="d-flex gap-2">
                    <button class="btn btn-outline-primary btn-sm rounded-pill px-3" @click="toggleGlobalSelectAll">
                        <i class="fas fa-check-double me-1"></i> Select All
                    </button>
                    
                    <template v-if="selectedCount > 0">
                        <button class="btn btn-outline-danger btn-sm rounded-pill px-3" @click="clearAllSelection">
                            <i class="fas fa-trash-alt me-1"></i> Clear
                        </button>
                        <div class="vr mx-2"></div>
                        <button class="btn btn-success btn-sm rounded-pill px-3" :disabled="loading" @click="submitSelection('accept')">
                            <i class="fas fa-check me-1"></i> Accept Selected
                        </button>
                        <button class="btn btn-danger btn-sm rounded-pill px-3" :disabled="loading" @click="submitSelection('reject')">
                            <i class="fas fa-times me-1"></i> Reject Selected
                        </button>
                    </template>
                </div>
            </div>
        </div>

        <div class="custom-table-wrapper border rounded-4 overflow-hidden mb-4 shadow-sm bg-white">
            <table class="table align-middle mb-0">
                <thead>
                    <tr class="bg-light text-muted small fw-bold">
                        <th style="width: 50px;"></th>
                        <th class="text-center" style="width: 50px;">
                            <input type="checkbox" :checked="isPageFullySelected" @change="toggleAllOnPage">
                        </th>
                        <th>Proposed Rule Change</th>
                        <th>Contributor</th>
                        <th>Type</th>
                        <th class="text-center">Score</th>
                        <th class="text-end pe-4">Status</th>
                    </tr>
                </thead>
                <tbody v-if="proposals.length > 0">
                    <template v-for="prop in proposals" :key="prop.id">
                        <tr :class="{'table-primary-subtle': isProposalChecked(prop.id)}">
                            <td class="text-center">
                                <button class="btn btn-sm btn-link p-0 text-dark" @click="toggleRow(prop.id)">
                                    <i class="fas" :class="expandedRows.has(prop.id) ? 'fa-chevron-down' : 'fa-chevron-right'"></i>
                                </button>
                            </td>
                            <td class="text-center">
                                <input type="checkbox" :checked="isProposalChecked(prop.id)" @change="updateSelection(prop.id, $event.target.checked)">
                            </td>
                            <td>
                                <div class="fw-bold text-dark">[[ prop.rule_name ]]</div>
                                <div class="x-small text-muted">ID: [[ prop.id ]]</div>
                            </td>
                            <td>
                                <div class="small fw-medium">[[ prop.user_name ]]</div>
                                <div class="x-small text-muted">[[ new Date(prop.timestamp).toLocaleDateString() ]]</div>
                            </td>
                            <td><span class="badge bg-light text-dark border">[[ prop.edit_type ]]</span></td>
                            <td class="text-center">
                                <div class="fw-bold" :class="prop.change_score > 80 ? 'text-success' : 'text-primary'">[[ prop.change_score ]]%</div>
                            </td>
                            <td class="text-end pe-4">
                                <span class="badge" :class="prop.status === 'pending' ? 'bg-secondary' : 'bg-success'">[[ prop.status ]]</span>
                            </td>
                        </tr>
                        
                        <tr v-if="expandedRows.has(prop.id)" class="detail-row bg-light">
                            <td colspan="7" class="p-4 border-0">
                                <div class="animate__animated animate__fadeIn">
                                    <div class="row">
                                        <div class="col-md-8">
                                            <h6 class="x-small fw-bold text-uppercase">Proposed Message</h6>
                                            <p class="small">[[ prop.message || 'No message provided.' ]]</p>
                                            <div class="d-flex gap-2 mt-3">
                                                <a :href="'/rule/proposal_content_discuss?id=' + prop.id" class="btn btn-sm btn-primary rounded-pill">
                                                    <i class="fas fa-comments me-1"></i> Discuss
                                                </a>
                                                 
                                                <button class="btn btn-sm btn-outline-dark rounded-pill" 
                                                        type="button" 
                                                        data-bs-toggle="modal"
                                                        data-bs-target="#fullscreenDiffModal"
                                                        @click="openDiffModal(prop)">
                                                    <i class="fas fa-eye me-1"></i> View Diff
                                                </button>
                                                
                                                <div class="vr mx-1"></div>

                                                <button class="btn btn-success btn-sm rounded-pill"
                                                    @click="handleDecision(prop.id, 'accepted', prop.rule_id)">
                                                    <i class="fas fa-check me-1"></i> Accept
                                                </button>

                                                <button class="btn btn-danger btn-sm rounded-pill"
                                                    @click="handleDecision(prop.id, 'rejected', prop.rule_id)">
                                                    <i class="fas fa-times me-1"></i> Reject
                                                </button>
                                            </div>
                                        </div>
                                        <div class="col-md-4 border-start">
                                            <div class="ps-3">
                                                <span class="x-small fw-bold text-uppercase d-block">Metadata</span>
                                                <div class="small">Original Rule ID: [[ prop.rule_id ]]</div>
                                                <div class="small">Comments: [[ prop.comments ? prop.comments.length : 0 ]]</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    </template>
                </tbody>
                <tbody v-else>
                    <tr>
                        <td colspan="7" class="text-center text-muted py-5">
                            <i class="fas fa-inbox fa-3x mb-3 opacity-25"></i>
                            <div>No pending proposals found.</div>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <pagination-component 
            :current-page="currentPage" 
            :total-pages="totalPages"
            @change-page="(p) => fetchRules(p)">
        </pagination-component>

        <div v-if="selectedCount > 0" class="selection-preview-box mt-4 p-4 rounded-4 shadow-sm border-dashed bg-white">
            <h6 class="mb-3 fw-bold"><i class="fas fa-clipboard-list me-2"></i>Current Selection</h6>
            <div class="d-flex flex-wrap gap-2">
                <div v-if="isAllSelectedMode" class="badge bg-primary p-2">
                    <i class="fas fa-globe me-2"></i> ALL [[ totalProposals ]] PROPOSALS SELECTED
                </div>
                <template v-else>
                    <div v-for="item in displayedSelection" :key="item.id" class="badge bg-light text-dark border p-2">
                        [[ item.title ]]
                        <i class="fas fa-times ms-2 cursor-pointer text-danger" @click="updateSelection(item.id, false)"></i>
                    </div>
                </template>
            </div>
        </div>
    </div>
    `
};

export default ProposalSelectionTable;