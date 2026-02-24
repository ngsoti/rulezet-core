import RuleFilterBar from '/static/js/rule/ruleFilterBar.js';
import PaginationComponent from '/static/js/rule/paginationComponent.js';

const RuleSelectionTable = {
    props: {
        apiEndpoint: { type: String, required: true },
        submitEndpoint: { type: String, required: true },
        csrfToken: { type: String, required: true },
        currentUserIsAuthenticated: { type: [Boolean, String], default: false },
        isSimilarityUpdate: { type: Boolean, default: false }
    },
    delimiters: ['[[', ']]'],
    components: {
        'rule-filter-bar': RuleFilterBar,
        'pagination-component': PaginationComponent
    },
    data() {
        return {
            rules: [], 
            allLoadedRules: new Map(), 
            expandedRows: new Set(),
            totalRules: 0,
            currentPage: 1,
            totalPages: 1,
            loading: false,
            
            selectedIds: new Set(),      
            excludedIds: new Set(),      
            isAllSelectedMode: false,    
            currentFilters: {}           
        };
    },
    computed: {
        selectedCount() {
            if (this.isAllSelectedMode) {
                return this.totalRules - this.excludedIds.size;
            }
            return this.selectedIds.size;
        },
        isPageFullySelected() {
            if (this.rules.length === 0) return false;
            return this.rules.every(rule => this.isRuleChecked(rule.id));
        },
        displayedSelection() {
            const items = [];
            if (!this.isAllSelectedMode) {
                for (let id of this.selectedIds) {
                    const rule = this.allLoadedRules.get(id);
                    items.push({ id: id, title: rule ? rule.title : `ID: ${id}` });
                    if (items.length >= 50) break;
                }
            }
            return items;
        }
    },
    methods: {
        onRulesUpdated(data) {
            this.rules = data.rules && data.rules.rule ? data.rules.rule : [];
            this.rules.forEach(r => this.allLoadedRules.set(r.id, r));
            this.totalRules = data.total_rules || 0;
            this.totalPages = data.total_pages || 1;
            this.currentPage = data.current_page || 1;
            this.currentFilters = data.filters || {}; 
            this.expandedRows.clear();
        },

        toggleRow(ruleId) {
            if (this.expandedRows.has(ruleId)) this.expandedRows.delete(ruleId);
            else this.expandedRows.add(ruleId);
        },

        toggleAllOnPage(event) {
            const checked = event.target.checked;
            this.rules.forEach(rule => this.updateSelection(rule.id, checked));
        },

        updateSelection(ruleId, isChecked) {
            if (this.isAllSelectedMode) {
                if (!isChecked) this.excludedIds.add(ruleId);
                else this.excludedIds.delete(ruleId);
            } else {
                if (isChecked) this.selectedIds.add(ruleId);
                else this.selectedIds.delete(ruleId);
            }
        },

        isRuleChecked(ruleId) {
            if (this.isAllSelectedMode) return !this.excludedIds.has(ruleId);
            return this.selectedIds.has(ruleId);
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

        async submitSelection() {
            this.loading = true;
            const payload = {
                mode: this.isAllSelectedMode ? 'all' : 'partial',
                filters: this.isAllSelectedMode ? this.currentFilters : null,
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

                const result = await response.json();

                if (this.isSimilarityUpdate && response.status === 201) {
                    if (result.session_uuid) {
                        window.location.href = "/rule/similar_loading/" + result.session_uuid;
                        return; 
                    }
                }

      
                if (result.success || response.status === 200) {
                    alert(`Action successful for ${this.selectedCount} rules.`);
                }
            } catch (err) {
                console.error("Submission error:", err);
                alert("An error occurred during processing.");
            } finally {
                this.loading = false;
            }
        }
    },
    template: `
    <div class="rule-selection-container">
        <rule-filter-bar 
            ref="filterBar"
            :api-endpoint="apiEndpoint"
            :csrf-token="csrfToken"
            :current-user-is-authenticated="currentUserIsAuthenticated"
            @update:results="onRulesUpdated"
            @loading="loading = $event"
            :show-export="false">
        </rule-filter-bar>

        <div v-if="totalRules > 0" class="selection-status-card mb-4 shadow-sm border-0">
            <div class="d-flex justify-content-between align-items-center">
                <div class="d-flex align-items-center">
                    <div class="selection-icon-box bg-primary text-white me-3">
                        <i class="fas" :class="isSimilarityUpdate ? 'fa-magic' : 'fa-tasks'"></i>
                        <span v-if="selectedCount > 0" class="selection-badge animate__animated animate__bounceIn">[[ selectedCount ]]</span>
                    </div>
                    <div>
                        <h6 class="mb-0 fw-bold">[[ isSimilarityUpdate ? 'Similarity Update' : 'Selection Management' ]]</h6>
                        <p class="text-muted small mb-0">[[ isAllSelectedMode ? 'Global Filter' : 'Manual Selection' ]]</p>
                    </div>
                </div>
                
                <div class="d-flex gap-2">
                    <button class="btn btn-outline-primary btn-sm rounded-pill px-3" @click="toggleGlobalSelectAll">
                        <i class="fas fa-check-double me-1"></i> Select All results
                    </button>
                    <button v-if="selectedCount > 0" class="btn btn-outline-danger btn-sm rounded-pill px-3" @click="clearAllSelection">
                        <i class="fas fa-trash-alt me-1"></i> Clear
                    </button>
                    <button class="btn btn-primary btn-sm rounded-pill px-4 shadow-sm" :disabled="selectedCount === 0 || loading" @click="submitSelection">
                        <span v-if="loading" class="spinner-border spinner-border-sm me-1"></span>
                        <i v-else class="fas fa-play me-1"></i>
                        [[ isSimilarityUpdate ? 'Start Analysis' : 'Process Selection' ]]
                    </button>
                </div>
            </div>
        </div>

        <div class="custom-table-wrapper border rounded-4 overflow-hidden mb-4 shadow-sm">
            <table class="table align-middle mb-0 custom-table">
                <thead>
                    <tr class="bg-light text-muted small fw-bold">
                        <th style="width: 50px;"></th>
                        <th class="text-center" style="width: 50px;">
                            <div class="custom-checkbox">
                                <input type="checkbox" :checked="isPageFullySelected" @change="toggleAllOnPage" id="checkAll">
                                <label for="checkAll"></label>
                            </div>
                        </th>
                        <th>Rule Identification</th>
                        <th>Author & Source</th>
                        <th>Format</th>
                        <th class="text-end pe-4">Activity</th>
                    </tr>
                </thead>
                <tbody v-if="rules.length > 0">
                    <template v-for="rule in rules" :key="rule.id">
                        <tr :class="{'row-selected': isRuleChecked(rule.id), 'row-expanded': expandedRows.has(rule.id)}">
                            <td class="text-center">
                                <button class="btn btn-sm btn-link p-0" @click="toggleRow(rule.id)">
                                    <i style="color: var(--text-color)" class="fas" :class="expandedRows.has(rule.id) ? 'fa-chevron-down' : 'fa-chevron-right'"></i>
                                </button>
                            </td>
                            <td class="text-center">
                                <div class="custom-checkbox">
                                    <input type="checkbox" :checked="isRuleChecked(rule.id)" @change="updateSelection(rule.id, $event.target.checked)" :id="'rule-'+rule.id">
                                    <label :for="'rule-'+rule.id"></label>
                                </div>
                            </td>
                            <td>
                                <div class="fw-bold text-dark">[[ rule.title ]]</div>
                                <div class="x-small">UUID: [[ rule.uuid.substring(0,8) ]]...</div>
                            </td>
                            <td>
                                <div class="small fw-medium">[[ rule.author || 'Internal' ]]</div>
                                <div class="x-small text-primary">[[ rule.source || 'Default' ]]</div>
                            </td>
                            <td><span class="badge-format">[[ rule.format ]]</span></td>
                            <td class="text-end pe-4 small">[[ rule.last_modif ]]</td>
                        </tr>
                        
                        <tr v-if="expandedRows.has(rule.id)" class="detail-row">
                            <td colspan="6" class="p-0 border-0">
                                <div class="detail-content p-4 animate__animated animate__fadeIn">
                                    <div class="row g-3">
                                        <div class="col-md-7">
                                            <label class="x-small fw-bold text-uppercase">Description</label>
                                            <p class="small mb-3">[[ rule.description || 'No description available.' ]]</p>
                                            <div class="d-flex gap-2 flex-wrap">
                                                <div v-for="tag in (rule.tags || [])" class="badge border px-2 py-1">#[[ tag ]]</div>
                                            </div>
                                        </div>
                                        <div class="col-md-5 border-start">
                                            <div class="ms-md-3">
                                                <span class="x-small fw-bold text-uppercase d-block">Full UUID</span>
                                                <code class="x-small text-break">[[ rule.uuid ]]</code>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    </template>
                </tbody>
            </table>
        </div>

        <pagination-component 
            :current-page="currentPage" 
            :total-pages="totalPages"
            @change-page="(p) => $refs.filterBar.fetchRules(p)">
        </pagination-component>

        <div v-if="selectedCount > 0" class="selection-preview-box mt-4 p-4 rounded-4 shadow-sm border-dashed">
            <h6 class="mb-3 fw-bold"><i class="fas fa-clipboard-list me-2"></i>Selection Preview</h6>
            <div class="d-flex flex-wrap gap-2">
                <div v-if="isAllSelectedMode" class="selection-pill global shadow-sm">
                    <i class="fas fa-globe me-2"></i> ALL [[ totalRules ]] RULES (Filtered)
                </div>
                <div v-if="!isAllSelectedMode" v-for="item in displayedSelection" :key="item.id" class="selection-pill manual shadow-sm">
                    <span class="text-truncate" style="max-width: 180px;">[[ item.title ]]</span>
                    <i class="fas fa-times ms-2 close-btn" @click="updateSelection(item.id, false)"></i>
                </div>
                <div v-if="selectedIds.size > 50 && !isAllSelectedMode" class="selection-pill info">
                    +[[ selectedIds.size - 50 ]] others
                </div>
            </div>
        </div>
    </div>
    `
};

export default RuleSelectionTable;