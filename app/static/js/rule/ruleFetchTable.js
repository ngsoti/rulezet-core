import RuleFilterBar from '/static/js/rule/ruleFilterBar.js';
import PaginationComponent from '/static/js/rule/paginationComponent.js';
import VulnerabilityDisplaysList from '/static/js/vulnerability/vulnerabilityDisplayList.js';

const UserRulesManagementComponent = {
    props: {
        userId: {
            type: [String, Number],
            required: true
        },
        viewOnly: {
            type: Boolean,
            default: false
        },
        csrfToken: {
            type: String,
            default: ''
        },
        currentUserIsAuthenticated: {
            type: [Boolean, String],
            default: false
        }
    },
    emits: ['rules-loaded'],
    delimiters: ['[[', ']]'],
    components: {
        'rule-filter-bar': RuleFilterBar,
        'pagination-component': PaginationComponent,
        'vulnerability-displays-list': VulnerabilityDisplaysList
    },
    setup(props, { emit }) {
        const rules_list = Vue.ref([]);
        const total_rules_liste = Vue.ref(0);
        const current_page = Vue.ref(1);
        const total_pages = Vue.ref(1);
        const search_is_loading = Vue.ref(true);
        const filterBar = Vue.ref(null);
        const selectedRules = Vue.ref([]);
        const ruleToDelete = Vue.ref(null);
        const expandedRows = Vue.ref(new Set());
        const showColumnFilter = Vue.ref(false);

        // Column visibility state - ALL filters visible except Actions in view-only mode
        const columnVisibility = Vue.ref({
            title: true,
            description: true,
            format: true,
            license: true,
            vulnerabilities: true,
            actions: !props.viewOnly
        });

        const onRulesUpdated = (results) => {
            rules_list.value = results.rules.rule || [];
            total_pages.value = results.total_pages || 1;
            current_page.value = results.current_page || 1;
            total_rules_liste.value = results.total_rules || 0;
            search_is_loading.value = false;
            emit('rules-loaded', {
                rules: rules_list.value,
                total: total_rules_liste.value
            });
        };

        const changePage = (page) => {
            if (filterBar.value) {
                filterBar.value.fetchRules(page);
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        };

        const detailRule = (id) => {
            window.location.href = `/rule/detail_rule/${id}`;
        };

        const confirmDelete = (rule) => {
            ruleToDelete.value = rule;
            const modal = new bootstrap.Modal(document.getElementById('deleteConfirmModal-' + rule.id));
            modal.show();
        };

        const executeDelete = async () => {
            const res = await fetch(`/rule/delete_rule?id=${ruleToDelete.value.id}`);
            if (res.ok) {
                rules_list.value = rules_list.value.filter(r => r.id !== ruleToDelete.value.id);
                const bootstrap_module = window.bootstrap;
                bootstrap_module.Modal.getInstance(document.getElementById('deleteConfirmModal-' + ruleToDelete.value.id)).hide();
            }
        };

        const deleteSelectedRules = async () => {
            if (!confirm(`Delete ${selectedRules.value.length} rules?`)) return;

            const res = await fetch('/rule/delete_rule_list', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                body: JSON.stringify({ ids: selectedRules.value })
            });
            const data = await res.json();
            if (data.success) {
                selectedRules.value = [];
                filterBar.value.fetchRules(current_page.value);
            }
        };

        const favorite = async (rule_id) => {
            const res = await fetch(`/rule/favorite/${rule_id}`);
            const data = await res.json();
            if (res.ok) {
                const rule = rules_list.value.find(r => r.id === rule_id);
                if (rule) rule.is_favorited = data.is_favorited;
            }
        };

        const toggleRow = (ruleId) => {
            if (expandedRows.value.has(ruleId)) {
                expandedRows.value.delete(ruleId);
            } else {
                expandedRows.value.add(ruleId);
            }
            expandedRows.value = new Set(expandedRows.value);
        };

        const isRowExpanded = (ruleId) => {
            return expandedRows.value.has(ruleId);
        };

        const toggleAllOnPage = (event) => {
            const checked = event.target.checked;
            rules_list.value.forEach(rule => {
                if (checked) {
                    if (!selectedRules.value.includes(rule.id)) {
                        selectedRules.value.push(rule.id);
                    }
                } else {
                    selectedRules.value = selectedRules.value.filter(id => id !== rule.id);
                }
            });
        };

        const isPageFullySelected = Vue.computed(() => {
            if (rules_list.value.length === 0) return false;
            return rules_list.value.every(rule => selectedRules.value.includes(rule.id));
        });

        const toggleColumnVisibility = (column) => {
            columnVisibility.value[column] = !columnVisibility.value[column];
        };

        const visibleColumnsCount = Vue.computed(() => {
            let count = 1; // expand button
            if (!props.viewOnly) count += 1; // checkbox
            if (columnVisibility.value.title) count += 1;
            if (columnVisibility.value.description) count += 1;
            if (columnVisibility.value.format) count += 1;
            if (columnVisibility.value.license) count += 1;
            if (columnVisibility.value.vulnerabilities) count += 1;
            if (columnVisibility.value.actions && !props.viewOnly) count += 1;
            return count;
        });

        const resetColumnVisibility = () => {
            columnVisibility.value = {
                title: true,
                description: true,
                format: true,
                license: true,
                vulnerabilities: true,
                actions: !props.viewOnly
            };
        };

        return {
            rules_list,
            total_rules_liste,
            current_page,
            total_pages,
            search_is_loading,
            filterBar,
            selectedRules,
            ruleToDelete,
            expandedRows,
            columnVisibility,
            showColumnFilter,
            onRulesUpdated,
            changePage,
            detailRule,
            confirmDelete,
            executeDelete,
            deleteSelectedRules,
            favorite,
            toggleRow,
            isRowExpanded,
            toggleAllOnPage,
            isPageFullySelected,
            toggleColumnVisibility,
            visibleColumnsCount,
            resetColumnVisibility
        };
    },
    template: `
    <div class="user-rules-management-component">
        <!-- Header Section -->
        <div class="mb-4 header-section" v-if="!viewOnly">
            <h3 class="mb-2 fw-bold">
                <i class="fas fa-user-shield me-2"></i> My Rules
            </h3>
            <p class="text-muted mb-0">
                Manage, edit, or delete the security rules you've contributed to the platform.
            </p>
        </div>

        <!-- Filter Bar -->
        <rule-filter-bar 
            ref="filterBar" 
            :user-id="userId" 
            :auto-fetch="true"
            api-endpoint="/rule/get_rules_page_filter"
            :current-user-is-authenticated="currentUserIsAuthenticated"
            @update:results="onRulesUpdated"
            @loading="search_is_loading = $event"
            :csrf-token="csrfToken">
        </rule-filter-bar>

        <!-- Bulk Action Bar (only in edit mode) -->
        <div v-if="!viewOnly && selectedRules.length > 0" class="bulk-action-bar shadow-lg mb-4">
            <div class="d-flex align-items-center justify-content-between bg-danger text-white p-3 rounded-4">
                <div class="ms-2">
                    <i class="fa-solid fa-circle-check me-2"></i>
                    <strong>[[ selectedRules.length ]]</strong> rules selected
                </div>
                <button class="btn btn-light btn-sm fw-bold rounded-pill px-4" @click="deleteSelectedRules">
                    <i class="fa-solid fa-trash-can me-2 text-danger"></i> Delete Selected
                </button>
            </div>
        </div>

        <!-- Results Wrapper -->
        <div class="results-wrapper">
            <!-- Loading State -->
            <template v-if="search_is_loading">
                <div class="text-center py-5">
                    <div class="spinner-border text-primary" role="status" style="width: 3rem; height: 3rem;"></div>
                    <p class="text-muted mt-3">Loading rules...</p>
                </div>
            </template>

            <!-- Rules Table View -->
            <template v-else-if="rules_list && rules_list.length > 0">
                <div v-if="!viewOnly" class="d-flex justify-content-between align-items-center mb-3">
                    <span class="small text-muted">Showing [[ rules_list.length ]] of [[ total_rules_liste ]] rules</span>
                    <pagination-component :current-page="current_page" :total-pages="total_pages"
                        @change-page="changePage"></pagination-component>
                </div>

                <!-- Table Layout -->
                <div class="card shadow border-0">
                    <!-- Column Filter Header -->
                    <div class="column-filter-header">
                        <div class="d-flex justify-content-between align-items-center p-3 border-bottom">
                            <div class="d-flex align-items-center gap-2">
                                <i class="fas fa-columns text-muted"></i>
                                <span class="small fw-bold text-muted">Display Columns</span>
                            </div>
                            <button class="btn btn-link p-0 text-muted" @click="showColumnFilter = !showColumnFilter" 
                                    style="font-size: 1rem; text-decoration: none;">
                                <i class="fas" :class="showColumnFilter ? 'fa-chevron-up' : 'fa-chevron-down'"></i>
                            </button>
                        </div>

                        <!-- Column Filter Options -->
                        <div v-if="showColumnFilter" class="column-filter-options p-3 border-bottom">
                            <div class="row g-2">
                                <div class="col-md-6 col-lg-4">
                                    <label class="column-checkbox-label">
                                        <input type="checkbox" 
                                               :checked="columnVisibility.title" 
                                               @change="toggleColumnVisibility('title')"
                                               class="form-check-input">
                                        <i class="px-1 fas fa-heading me-2"></i>
                                        <span>Title</span>
                                    </label>
                                </div>

                                <div class="col-md-6 col-lg-4">
                                    <label class="column-checkbox-label">
                                        <input type="checkbox" 
                                               :checked="columnVisibility.description" 
                                               @change="toggleColumnVisibility('description')"
                                               class="form-check-input">
                                        <i class="px-1 fas fa-align-left me-2"></i>
                                        <span>Description</span>
                                    </label>
                                </div>

                                <div class="col-md-6 col-lg-4">
                                    <label class="column-checkbox-label">
                                        <input type="checkbox" 
                                               :checked="columnVisibility.format" 
                                               @change="toggleColumnVisibility('format')"
                                               class="form-check-input">
                                        <i class="px-1 fas fa-code me-2"></i>
                                        <span>Format</span>
                                    </label>
                                </div>

                                <div class="col-md-6 col-lg-4">
                                    <label class="column-checkbox-label">
                                        <input type="checkbox" 
                                               :checked="columnVisibility.license" 
                                               @change="toggleColumnVisibility('license')"
                                               class="form-check-input">
                                        <i class="px-1 fas fa-certificate me-2"></i>
                                        <span>License</span>
                                    </label>
                                </div>

                                <div class="col-md-6 col-lg-4">
                                    <label class="column-checkbox-label">
                                        <input type="checkbox" 
                                               :checked="columnVisibility.vulnerabilities" 
                                               @change="toggleColumnVisibility('vulnerabilities')"
                                               class="form-check-input">
                                        <i class="px-1 fas fa-shield-alt me-2"></i>
                                        <span>Vulnerabilities</span>
                                    </label>
                                </div>

                                <div v-if="!viewOnly" class="col-md-6 col-lg-4">
                                    <label class="column-checkbox-label">
                                        <input type="checkbox" 
                                               :checked="columnVisibility.actions" 
                                               @change="toggleColumnVisibility('actions')"
                                               class="form-check-input">
                                        <i class="px-1 fas fa-toolbox me-2"></i>
                                        <span>Actions</span>
                                    </label>
                                </div>
                            </div>

                            <div class="d-flex gap-2 mt-3 pt-3 border-top">
                                <button class="btn btn-sm btn-outline-primary rounded-pill" @click="resetColumnVisibility">
                                    <i class="fas fa-undo me-1"></i> Reset to Default
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Card Header -->
                    <div class="card-header  py-3 border-bottom">
                        <div class="d-flex justify-content-between align-items-center">
                            <h5 class="mb-0 fw-bold">
                                <i class="fas fa-list me-2"></i> Rules
                            </h5>
                            <span class="badge rounded-pill bg-primary">
                                [[ total_rules_liste ]] Rule(s)
                            </span>
                        </div>
                    </div>

                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table align-middle mb-0" style="color: var(--text-color);">
                                <thead class="">
                                    <tr>
                                        <th style="width: 40px;"></th>
                                        <th v-if="!viewOnly" style="width: 50px;">
                                            <div class="custom-checkbox">
                                                <input type="checkbox" :checked="isPageFullySelected" @change="toggleAllOnPage" id="checkAll">
                                                <label for="checkAll"></label>
                                            </div>
                                        </th>
                                        <th v-if="columnVisibility.title">Title</th>
                                        <th v-if="columnVisibility.description">Description</th>
                                        <th v-if="columnVisibility.format" class="text-center">Format</th>
                                        <th v-if="columnVisibility.license" class="text-center">License</th>
                                        <th v-if="columnVisibility.vulnerabilities" class="text-center">Vulnerabilities</th>
                                        <th v-if="columnVisibility.actions && !viewOnly" class="text-center pe-3">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <template v-for="rule in rules_list" :key="rule.id">
                                        <!-- Main Row -->
                                        <tr :class="{'table-active': selectedRules.includes(rule.id)}">
                                            <td class="text-center">
                                                <button class="btn btn-sm btn-link p-0" @click="toggleRow(rule.id)" style="color: var(--text-color);">
                                                    <i class="fas" :class="isRowExpanded(rule.id) ? 'fa-chevron-down' : 'fa-chevron-right'"></i>
                                                </button>
                                            </td>
                                            <td v-if="!viewOnly" class="text-center">
                                                <div class="custom-checkbox">
                                                    <input type="checkbox" :value="rule.id" v-model="selectedRules" :id="'check-'+rule.id">
                                                    <label :for="'check-'+rule.id"></label>
                                                </div>
                                            </td>
                                            <td v-if="columnVisibility.title">
                                                <div class="fw-bold">
                                                    <a href="#" @click.prevent="detailRule(rule.id)" 
                                                       class="text-decoration-none"
                                                       style="color: var(--rule-name-color);">
                                                        [[ rule.title ]]
                                                    </a>
                                                </div>
                                            </td>
                                            <td v-if="columnVisibility.description">
                                                <small class="text-muted d-inline-block text-truncate" style="max-width: 200px;">
                                                    [[ rule.description || 'No description' ]]
                                                </small>
                                            </td>
                                            <td v-if="columnVisibility.format" class="text-center">
                                                <span class="badge bg-primary">
                                                    [[ rule.format ]]
                                                </span>
                                            </td>
                                            <td v-if="columnVisibility.license" class="text-center">
                                                <span v-if="rule.license" class="badge bg-info">
                                                    [[ rule.license ]]
                                                </span>
                                                <span v-else class="text-muted small">—</span>
                                            </td>
                                            <td v-if="columnVisibility.vulnerabilities" class="text-center">
                                                <vulnerability-displays-list 
                                                    object-type="rule" 
                                                    :object-id="rule.id" 
                                                    :max-visible="3">
                                                </vulnerability-displays-list>
                                            </td>
                                            <td v-if="columnVisibility.actions && !viewOnly" class="text-center pe-3">
                                                <div class="d-flex gap-1 justify-content-center" @click.stop>
                                                    <a :href="'/rule/edit_rule/' + rule.id" class="btn btn-sm btn-light border rounded-circle" title="Edit">
                                                        <i class="fas fa-pen-to-square text-primary"></i>
                                                    </a>
                                                    <button class="btn btn-sm btn-light border rounded-circle" @click="confirmDelete(rule)" title="Delete">
                                                        <i class="fas fa-trash text-danger"></i>
                                                    </button>
                                                    <button class="btn btn-sm btn-light border rounded-circle" @click="favorite(rule.id)" :title="rule.is_favorited ? 'Unstar' : 'Star'">
                                                        <i class="fas fa-star" :class="{'text-warning': rule.is_favorited}"></i>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>

                                        <!-- Expanded Detail Row -->
                                        <tr v-if="isRowExpanded(rule.id)" class="detail-row">
                                            <td :colspan="visibleColumnsCount" class="p-0 border-0">
                                                <div class="bg-light p-4 animate__animated animate__fadeIn">
                                                    <div class="row g-3">
                                                        <div class="col-md-8">
                                                            <div v-if="columnVisibility.description" class="mb-3">
                                                                <label class="small fw-bold text-uppercase text-muted d-block mb-1">
                                                                    <i class="fas fa-align-left me-1"></i> Full Description
                                                                </label>
                                                                <p class="mb-0">[[ rule.description || 'No description available.' ]]</p>
                                                            </div>
                                                        </div>
                                                        <div class="col-md-4 border-start">
                                                            <div class="ms-md-3">
                                                                <label class="small fw-bold text-uppercase text-muted d-block mb-2">
                                                                    <i class="fas fa-info-circle me-1"></i> Additional Info
                                                                </label>
                                                                <div class="small">
                                                                    <div v-if="columnVisibility.format" class="mb-2">
                                                                        <strong>Format:</strong> [[ rule.format ]]
                                                                    </div>
                                                                    <div v-if="columnVisibility.license && rule.license" class="mb-2">
                                                                        <strong>License:</strong> [[ rule.license ]]
                                                                    </div>
                                                                    <div v-if="rule.created_at" class="mb-2">
                                                                        <strong>Created:</strong> [[ rule.created_at ]]
                                                                    </div>
                                                                    <div v-if="rule.vote_up !== undefined" class="mb-0">
                                                                        <strong>Likes:</strong> 
                                                                        <span class="badge bg-success">[[ rule.vote_up || 0 ]]</span>
                                                                    </div>
                                                                </div>
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
                    </div>

                    <!-- Pagination -->
                    <div v-if="total_pages > 1" class="card-footer bg-light">
                        <pagination-component 
                            :current-page="current_page" 
                            :total-pages="total_pages"
                            @change-page="changePage">
                        </pagination-component>
                    </div>
                </div>

                
            </template>

            <!-- Empty State -->
            <div v-else class="text-center py-5 rounded-4 bg-light-subtle border border-dashed">
                <i class="fas fa-inbox fa-3x text-muted mb-3 d-block" style="opacity: 0.3;"></i>
                <h5 class="fw-bold">No rules found</h5>
                <p class="text-muted">
                    This user haven't created any rules matching these criteria yet.
                </p>
                <a v-if="!viewOnly" href="/rule/create_rule" class="btn btn-primary rounded-pill px-4 mt-2">
                    <i class="fa-solid fa-plus me-2"></i>Create your first rule
                </a>
            </div>
        </div>

        <!-- Delete Confirmation Modals (only in edit mode) -->
        <template v-if="!viewOnly">
            <template v-for="rule in rules_list" :key="'modal-' + rule.id">
                <div class="modal fade" :id="'deleteConfirmModal-' + rule.id" tabindex="-1" aria-hidden="true">
                    <div class="modal-dialog modal-dialog-centered">
                        <div class="modal-content border-0 shadow">
                            <div class="modal-body text-center p-4">
                                <i class="fa-solid fa-triangle-exclamation text-danger fa-3x mb-3"></i>
                                <h5 class="fw-bold">Delete Rule?</h5>
                                <p class="text-muted">Are you sure you want to delete <strong>[[ rule.title ]]</strong>? This action is irreversible.</p>
                                <div class="d-flex gap-2 justify-content-center mt-4">
                                    <button class="btn btn-light rounded-pill px-4" :data-bs-dismiss="'modal'">Cancel</button>
                                    <button class="btn btn-danger rounded-pill px-4" @click="ruleToDelete = rule; executeDelete()">Confirm Delete</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </template>
        </template>
    </div>
    `
};

export default UserRulesManagementComponent;