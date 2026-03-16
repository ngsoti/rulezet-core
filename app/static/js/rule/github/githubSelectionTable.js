import PaginationComponent from '/static/js/rule/paginationComponent.js';
import GithubFilter from '/static/js/rule/github/githubFilter.js';
import GithubActionModal from '/static/js/rule/github/githubActionModal.js';
import { message_list, create_message } from '/static/js/toaster.js'

const GitHubSelectionTable = {
    props: {
        apiEndpoint: { type: String, required: true },
        submitEndpoint: { type: String, required: true },
        csrfToken: { type: String, required: true },
        currentUserIsAdmin: { 
        type: [Boolean, String], set: v => v === 'true' || v === true }
    },
    delimiters: ['[[', ']]'],
    components: {
        'pagination-component': PaginationComponent,
        'github-filter': GithubFilter,
        'github-action-modal': GithubActionModal
    },
    data() {
        return {
            githubUrls: [],
            totalUrls: 0,
            currentPage: 1,
            totalPages: 1,
            loading: false,
            selectedIds: new Set(),
            excludedIds: new Set(),
            isAllSelectedMode: false,
            expandedRows: new Set(),
            isActionLoading: false,
            activeAction: {
                type: 'delete',
                title: 'Massive Deletion',
                icon: 'fa-trash-can',
                variant: 'danger',
                confirmText: 'Yes, Delete Everything'
            }
        };
    },
    computed: {
        isAdmin() {
            return this.currentUserIsAdmin === 'true' || this.currentUserIsAdmin === true;
        },
        selectedCount() {
            if (this.isAllSelectedMode) {
                return this.totalUrls - this.excludedIds.size;
            }
            return this.selectedIds.size;
        },
        isPageFullySelected() {
            if (this.githubUrls.length === 0) return false;
            return this.githubUrls.every(item => this.isItemChecked(item.url));
        },
        actionPayload() {
            const filter = this.$refs.filter || {};
            return {
                mode: this.isAllSelectedMode ? 'all' : 'partial',
                search_query: filter.searchQuery || '',
                search_field: filter.searchField || 'url',
                format_filter: filter.selectedFormat || '',
                author_filter: filter.authorQuery || '',
                selected_ids: Array.from(this.selectedIds),
                excluded_ids: Array.from(this.excludedIds)
            };
        }
    },
    methods: {
        handleSearchResults(data) {
            this.githubUrls = data.github_url.map(item => ({ ...item, isUpdating: false }));
            this.totalUrls = data.total_url;
            this.totalPages = data.total_pages;
            this.currentPage = data.current_page;
        },

        changePage(page) {
            console.log("Changing to page:", this.currentUserIsAdmin);
            this.$refs.filter.fetchUrls(page);
        },

        toggleRow(url) {
            if (this.expandedRows.has(url)) {
                this.expandedRows.delete(url);
            } else {
                this.expandedRows.add(url);
            }
        },

        updateSelection(itemUrl, isChecked) {
            if (this.isAllSelectedMode) {
                if (!isChecked) this.excludedIds.add(itemUrl);
                else this.excludedIds.delete(itemUrl);
            } else {
                if (isChecked) this.selectedIds.add(itemUrl);
                else this.selectedIds.delete(itemUrl);
            }
        },

        isItemChecked(itemUrl) {
            if (this.isAllSelectedMode) return !this.excludedIds.has(itemUrl);
            return this.selectedIds.has(itemUrl);
        },

        toggleAllOnPage(event) {
            const checked = event.target.checked;
            this.githubUrls.forEach(item => this.updateSelection(item.url, checked));
        },

        toggleGlobalSelectAll() {
            this.isAllSelectedMode = true;
            this.selectedIds.clear();
            this.excludedIds.clear();
        },

        clearSelection() {
            this.isAllSelectedMode = false;
            this.selectedIds.clear();
            this.excludedIds.clear();
        },
        handleActionSuccess(result) {
            this.clearSelection();
            setTimeout(() => this.changePage(this.currentPage), 1500);
        },

        openActionModal(actionType) {
            if (actionType === 'delete') {
                this.activeAction = {
                    type: 'delete',
                    title: 'Massive Deletion',
                    icon: 'fa-trash-can',
                    variant: 'danger',
                    confirmText: 'Delete Selected'
                };
            } else if (actionType === 'export') {
                this.activeAction = {
                    type: 'export',
                    title: 'Export Repositories',
                    icon: 'fa-file-export',
                    variant: 'primary',
                    confirmText: 'Start Export'
                };
            }
            

            const modal = new bootstrap.Modal(document.getElementById('githubActionModal'));
            modal.show();
        },

        async deleteSingleRepo(url) {
            this.isActionLoading = true;
            try {
                const res = await fetch(`/rule/delete_all_rule_github?url=${encodeURIComponent(url)}`);
                const data = await res.json();
                
                if (res.status === 202) {

                    create_message("Action: " + data.message, "success-subtle");
                    
                    const repo = this.githubUrls.find(u => u.url === url);
                    if (repo) {
                        repo.rule_count = "Deleting...";
                    }
                    

                    setTimeout(() => {
                        this.changePage(1);
                    }, 5000);
                   
                } else {
                    create_message(data.message || "Error starting the deletion.", "danger-subtle");
                }
            } catch (err) {
                console.error("Deletion request failed", err);
                create_message("Network error. Could not reach the server.", "danger-subtle");
            } finally {
               
                this.isActionLoading = false;
            }
        },
        async updateSingleRepo(item) {
            if (!confirm(`Check for updates for: ${item.url}?`)) return;

            item.isUpdating = true; 
            try {
                const response = await fetch("/rule/check_updates_by_url", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRFToken": this.csrfToken 
                    },
                    body: JSON.stringify({ 
                        url: [{ "url": item.url }] 
                    }),
                });

                if (response.status === 201) {
                    const data = await response.json();
                    window.location.href = "/rule/update_loading/" + data.session_uuid;
                } else {
                    const errorData = await response.json();
                    alert(errorData.message || "Error starting update check");
                    item.isUpdating = false; 
                }
            } catch (err) {
                console.error("Update check failed", err);
                item.isUpdating = false;
            }
        },
       
    },
    template: `
    <div class="github-selection-wrapper">
        <github-filter 
            ref="filter"
            :api-endpoint="apiEndpoint" 
            @update:results="handleSearchResults"
            @loading="val => loading = val"
        ></github-filter>

        <div class="mb-4 d-flex justify-content-between align-items-center">
            <button class="btn btn-outline-primary rounded-pill px-3" @click="toggleGlobalSelectAll">
                <i class="fas fa-check-double me-1"></i> Select All results ([[ totalUrls ]])
            </button>
            <button v-if="selectedCount > 0" class="btn btn-link text-danger text-decoration-none" @click="clearSelection">
                Clear Selection
            </button>
        </div>

        <div v-if="selectedCount > 0" class="alert alert-primary shadow-lg border-0 rounded-pill d-flex justify-content-between align-items-center px-4 py-3 sticky-top animate__animated animate__fadeIn" style="top: 20px; z-index: 1020;">
            <div>
                <strong class="me-2"><i class="fas fa-tasks me-2"></i> [[ selectedCount ]] repositories selected</strong>
            </div>
            <div class="d-flex gap-2">
                <template v-if="isAdmin">
                    <button class="btn btn-danger btn-sm rounded-pill px-4 fw-bold" @click="openActionModal('delete')" :disabled="isActionLoading">
                        <i class="fas fa-trash-alt me-1"></i> Delete Selected
                    </button>
                </template>
                <!-- Future actions can be added here -->
                <button class="btn btn-primary btn-sm rounded-pill px-4 fw-bold" @click="openActionModal('export')" :disabled="isActionLoading">
                    <i class="fas fa-file-export me-1"></i> Export Selected
                </button>
            </div>
        </div>

        <div class="card border-0 shadow-sm rounded-4 overflow-hidden">
            <div class="table-responsive">
                <table class="table align-middle mb-0">
                    <thead class="bg-light">
                        <tr class="text-muted small text-uppercase">
                            <th style="width: 50px;" class="text-center">
                                <input type="checkbox" class="form-check-input" :checked="isPageFullySelected" @change="toggleAllOnPage">
                            </th>
                            <th style="width: 40px;"></th>
                            <th>Repository Details</th>
                            <th class="text-center">Rules</th>
                            <th class="text-end pe-4">Actions</th>
                        </tr>
                    </thead>
                    <tbody v-if="!loading">
                        <template v-for="(item, index) in githubUrls" :key="item.url">
                            <tr :class="{'table-active': isItemChecked(item.url)}" style="cursor: pointer;" @click="toggleRow(item.url)">
                                <td class="text-center" @click.stop>
                                    <input type="checkbox" class="form-check-input" 
                                           :checked="isItemChecked(item.url)" 
                                           @change="updateSelection(item.url, $event.target.checked)">
                                </td>
                                <td class="text-center">
                                    <i class="fas" :class="expandedRows.has(item.url) ? 'fa-chevron-down text-primary' : 'fa-chevron-right text-muted'"></i>
                                </td>
                                <td>
                                    <div class="d-flex align-items-center">
                                        <div class="bg-light rounded p-2 me-3">
                                            <i class="fab fa-github fa-lg"></i>
                                        </div>
                                        <div>
                                            <div class="fw-bold text-dark text-truncate" style="max-width: 300px;">[[ item.url ]]</div>
                                            <div class="x-small text-muted">
                                                Detected Rules: [[ item.rule_count ]] 
                                                <span v-if="item.last_import && item.last_import.imported !== null">
                                                     | <i class="fas fa-check text-success"></i> Imported
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </td>
                                <td class="text-center">
                                    <span class="badge bg-primary-soft text-primary rounded-pill px-3">
                                        [[ item.rule_count ]] rules
                                    </span>
                                </td>
                                <td class="text-end pe-4" @click.stop>
                                    <template v-if="isAdmin">
                                        <button class="btn btn-sm btn-outline-danger border-0 rounded-circle me-1" 
                                                data-bs-toggle="modal"
                                                :data-bs-target="'#delete_repo_modal_' + index"
                                                title="Delete Repository">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </template>
                                    <div class="modal fade" :id="'delete_repo_modal_' + index" tabindex="-1" aria-hidden="true">
                                        <div class="modal-dialog modal-dialog-centered">
                                            <div class="modal-content border-0 shadow-lg" style="border-radius: 15px;">
                                                <div class="modal-header border-0 pb-0 text-start">
                                                    <h5 class="modal-title fw-bold">Confirm Deletion</h5>
                                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                                </div>
                                                <div class="modal-body py-4 text-center">
                                                    <div class="text-danger mb-3"><i class="fas fa-exclamation-triangle fa-3x"></i></div>
                                                    <p class="mb-0 text-dark">
                                                        Are you sure you want to delete all rules for:<br>
                                                        <strong class="text-break">[[ item.url ]]</strong>?
                                                    </p>
                                                </div>
                                                <div class="modal-footer border-0 pt-0">
                                                    <button type="button" class="btn btn-light rounded-pill px-4" data-bs-dismiss="modal">Cancel</button>
                                                    <button class="btn btn-danger rounded-pill px-4" 
                                                            @click="deleteSingleRepo(item.url)" 
                                                            data-bs-dismiss="modal">
                                                        Confirm Delete
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <a :href="'/rule/github_detail?url=' + encodeURIComponent(item.url)" 
                                       class="btn btn-sm btn-outline-primary border-0 rounded-circle me-1" title="View Details">
                                        <i class="fas fa-external-link-alt"></i>
                                    </a>
                                    <template v-if="isAdmin">
                                        <!-- update button -->
                                        <button class="btn btn-sm btn-outline-success border-0 rounded-circle" 
                                                @click="updateSingleRepo(item)" 
                                                :disabled="item.isUpdating"
                                                title="Check for updates">
                                            <i class="fas fa-sync-alt" :class="{'fa-spin': item.isUpdating}"></i>
                                        </button>
                                    </template>
                                </td>
                            </tr>

                            <tr v-if="expandedRows.has(item.url)" class="bg-light shadow-inner">
                                <td colspan="5" class="p-4">
                                    <div class="animate__animated animate__fadeIn">
                                        <div class="d-flex justify-content-between align-items-center mb-3">
                                            <h6 class="fw-bold mb-0"><i class="fas fa-info-circle me-2"></i>Repository Analysis</h6>
                                            <span v-if="item.has_conflicts" class="badge bg-danger animate__animated animate__pulse animate__infinite">
                                                <i class="fas fa-exclamation-triangle me-1"></i> High Similarity Detected (>90%)
                                            </span>
                                            <span v-else class="badge bg-success">
                                                <i class="fas fa-check-circle me-1"></i> No Duplicate Conflicts
                                            </span>
                                        </div>

                                        <div class="row g-3">
                                            <div class="col-md-4">
                                                <div class="p-3 border rounded h-100">
                                                    <small class="text-muted d-block mb-2 text-uppercase fw-bold" style="font-size: 0.7rem;">Detected Formats</small>
                                                    <div class="d-flex flex-wrap gap-1">
                                                        <span v-for="fmt in item.formats" :key="fmt" class="badge border text-dark fw-normal">[[ fmt ]]</span>
                                                        <span v-if="!item.formats.length" class="text-muted small">None</span>
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="col-md-4">
                                                <div class="p-3 border rounded h-100  d-flex flex-column justify-content-center">
                                                    <small class="text-muted d-block mb-1 text-uppercase fw-bold" style="font-size: 0.7rem;">CVE Identifiers</small>
                                                    <div class="d-flex align-items-center">
                                                        <h4 class="mb-0 fw-bold text-primary">[[ item.cve_count ]]</h4>
                                                        <i class="fas fa-bug ms-2 text-muted"></i>
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="col-md-4">
                                                <div class="p-3 border rounded h-100 ">
                                                    <small class="text-muted d-block mb-2 text-uppercase fw-bold" style="font-size: 0.7rem;">Repository Link</small>
                                                    <a :href="item.url" target="_blank" class="btn btn-sm btn-outline-dark w-100 text-truncate">
                                                        <i class="fab fa-github me-2"></i>Open on GitHub
                                                    </a>
                                                </div>
                                            </div>
                                        </div>

                                        <div class="row g-4 mt-1">
                                            <div class="col-md-6" v-if="item.last_import">
                                                <div class="p-3 border-0 rounded-4 shadow-sm h-100 ">
                                                    <div class="d-flex justify-content-between align-items-center mb-3">
                                                        <div class="d-flex align-items-center mb-3">
                                                            <div class="bg-success-soft rounded-circle p-2 me-2"><i class="fas fa-file-import text-success"></i></div>
                                                            <small class="text-muted text-uppercase fw-bold" style="font-size: 0.75rem;">Latest Import</small>
                                                        </div>
                                                        <div>
                                                            <a v-if="item.last_import.url_imported" 
                                                                :href="item.last_import.url_imported" 
                                                                class="btn btn-sm btn-link text-success p-1 ms-2" 
                                                                style="vertical-align: middle; line-height: 1;"
                                                                title="View Import Details">
                                                                <i class="fas fa-external-link-alt"></i>
                                                            </a>
                                                        </div>
                                                    </div>
                                                    
                                                    <div class="vstack gap-2">
                                                        <div class="d-flex justify-content-between align-items-center">
                                                            <span class="small text-muted"><i class="far fa-calendar-alt me-1"></i> Date</span>
                                                            <span class="small fw-bold text-dark">[[ item.last_import.date ]]</span>
                                                        </div>
                                                       
                                                        <hr class="my-1 opacity-5">
                                                        <div class="d-flex justify-content-between align-items-center">
                                                            <span class="small text-muted">Imported Rules</span>
                                                            <span class="badge rounded-pill bg-success-subtle text-success border border-success-subtle px-3">[[ item.last_import.imported ]]</span>
                                                        </div>
                                                        <div class="d-flex justify-content-between align-items-center">
                                                            <span class="small text-muted">Bad Rules</span>
                                                            <span class="badge rounded-pill" :class="item.last_import.bad_rules > 0 ? 'bg-danger text-white' : 'bg-light text-muted px-3'">[[ item.last_import.bad_rules ]]</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="col-md-6" v-if="item.last_update">
                                                <div class="p-3 border-0 rounded-4 shadow-sm h-100 ">
                                                    <div class="d-flex justify-content-between align-items-center mb-3">
                                                        <div class="d-flex align-items-center mb-3">
                                                            <div class="bg-primary-soft rounded-circle p-2 me-2"><i class="fas fa-sync-alt text-primary"></i></div>
                                                            <small class="text-muted text-uppercase fw-bold" style="font-size: 0.75rem;">Latest Update</small>
                                                        </div>
                                                        <div>
                                                            <div class="d-flex align-items-center">
                                                                <button class="btn btn-sm btn-outline-success border-0 rounded-circle me-1" 
                                                                        @click="updateSingleRepo(item.url)" 
                                                                        :disabled="isActionLoading"
                                                                        title="Check for updates">
                                                                    <i class="fas fa-sync-alt" :class="{'fa-spin': isActionLoading}"></i>
                                                                </button>
                                                                <a v-if="item.last_update.url_updated" 
                                                                    :href="item.last_update.url_updated" 
                                                                    class="btn btn-sm btn-link text-primary p-1 ms-2" 
                                                                    style="vertical-align: middle; line-height: 1;"
                                                                    title="View Update Details">
                                                                    <i class="fas fa-external-link-alt"></i>
                                                                </a>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div class="vstack gap-2">
                                                        <div class="d-flex justify-content-between align-items-center">
                                                            <span class="small text-muted"><i class="far fa-calendar-alt me-1"></i> Date</span>
                                                            <span class="small fw-bold text-dark">[[ item.last_update.date ]]</span>
                                                        </div>
                                                        <hr class="my-1 opacity-5">
                                                        <div class="d-flex justify-content-between align-items-center">
                                                            <span class="small text-muted">Updated</span>
                                                            <span v-if="item.last_update.updated > 0" class="badge rounded-pill bg-primary px-3">[[ item.last_update.updated ]]</span>
                                                            <span v-else class="text-muted smaller italic">No changes</span>
                                                        </div>
                                                        <div class="d-flex justify-content-between align-items-center">
                                                            <span class="small text-muted">New Rules Found</span>
                                                            <span class="badge rounded-pill bg-info-subtle text-info border border-info-subtle px-3">[[ item.last_update.new_rules_count ]]</span>
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
                <div v-if="loading" class="text-center py-5">
                    <div class="spinner-border text-primary" role="status"></div>
                    <p class="mt-2 text-muted">Loading repositories...</p>
                </div>
                <div v-if="githubUrls.length === 0 && !loading" class="text-center py-5 text-muted">
                    <i class="fas fa-search fa-3x mb-3 opacity-25"></i>
                    <p>No GitHub URLs found matching your search.</p>
                </div>
            </div>
        </div>

        <div class="mt-4">
            <pagination-component :current-page="currentPage" :total-pages="totalPages" @change-page="changePage"></pagination-component>
        </div>

        <github-action-modal 
            modal-id="githubActionModal"
            :title="activeAction.title"
            :icon="activeAction.icon"
            :variant="activeAction.variant"
            :confirm-text="activeAction.confirmText"
            :selected-count="selectedCount"
            :action-type="activeAction.type"
            :endpoint="submitEndpoint"
            :csrf-token="csrfToken"
            :payload="actionPayload"
            @success="handleActionSuccess"
        >
            <template #description>
                <div v-if="activeAction.type === 'delete'" class="alert alert-warning border-0 small rounded-3 text-start mb-0">
                    <i class="fa-solid fa-circle-info me-2"></i>
                    This will remove all associated rules from the database. This process runs in the background.
                </div>
                <div v-else class="text-muted small">
                    This will prepare a bundle of all selected repositories for export.
                </div>
            </template>
        </github-action-modal>
    </div>
    `
};

export default GitHubSelectionTable;