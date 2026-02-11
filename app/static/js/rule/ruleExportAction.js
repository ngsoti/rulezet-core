import RuleBundleManager from './ruleBundleManager.js';
import { display_toast, message_list, create_message } from '/static/js/toaster.js'
const RuleExportAction = {
    components: {
        RuleBundleManager
    },
    props: {
        totalRules: { type: Number, default: 0 },
        searchQuery: { type: String, default: '' },
        sortBy: { type: String, default: 'newest' },
        searchField: { type: String, default: 'all' },
        ruleType: { type: String, default: '' },
        selectedSources: { type: Array, default: () => [] },
        selectedVulnerabilities: { type: Array, default: () => [] },
        selectedLicenses: { type: Array, default: () => [] },
        selectedTags: { type: Array, default: () => [] },
        userId: { type: Number, default: null },
        authorFilter: { type: String, default: '' },
        csrfToken: { type: String, default: '' },
        currentUserIsAuthenticated: { type: Boolean, default: false }
    },
    delimiters: ['[[', ']]'],
    setup(props) {
        const MAX_LIMIT = 100;
        const isProcessing = Vue.ref(false);
        const currentView = Vue.ref('main');
        const csrfToken = Vue.ref(props.csrfToken);
        const isOverLimit = Vue.computed(() => props.totalRules > MAX_LIMIT);
        
        const current_user_is_authenticated = Vue.ref(props.currentUserIsAuthenticated);
       
        const currentFilters = Vue.computed(() => ({
            search: props.searchQuery,
            sort_by: props.sortBy,
            rule_type: props.ruleType,
            sources: props.selectedSources,
            vulnerabilities: props.selectedVulnerabilities,
            licenses: props.selectedLicenses,
            tags: props.selectedTags,
            user_id: props.userId,
            author: props.authorFilter
        }));

        const resetView = () => {
            currentView.value = 'main';
        };

        const onBundleCompleted = () => {
            create_message('Export completed!', 'success-subtle');
            resetView();
            const modalEl = document.getElementById('exportActionModal');
            const modal = bootstrap.Modal.getInstance(modalEl);
            if (modal) modal.hide();
        };

        const downloadFormat = async (formatType) => {
            isProcessing.value = true;
            try {
                const params = new URLSearchParams();
                params.append('export_format', formatType);
                params.append('search', props.searchQuery || '');
                params.append('sort_by', props.sortBy);
                params.append('rule_type', props.ruleType || '');
                params.append('author', props.authorFilter || '');
                
                if (props.userId) params.append('user_id', props.userId);
                if (props.selectedSources.length) params.append('sources', props.selectedSources.join(','));
                if (props.selectedVulnerabilities.length) params.append('vulnerabilities', props.selectedVulnerabilities.join(','));
                if (props.selectedLicenses.length) params.append('licenses', props.selectedLicenses.join(','));
                if (props.selectedTags.length) params.append('tags', props.selectedTags.join(','));
                if (props.searchField) params.append('search_field', props.searchField);

                const response = await fetch(`/rule/export/download?${params.toString()}`);
                if (!response.ok) throw new Error('Export failed');
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `export_${formatType}_${new Date().getTime()}.zip`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
            } catch (error) {
                console.error("Export error:", error);
            } finally {
                isProcessing.value = false;
            }
        };

        return {
            isProcessing,
            currentView,
            resetView,
            downloadFormat,
            isOverLimit,
            MAX_LIMIT,
            currentFilters,
            onBundleCompleted,
            message_list,
            current_user_is_authenticated
        };
    },
    template: `
    <div class="export-action-container p-3 border-top bg-light-subtle" style="border-radius: 0 0 15px 15px;">
        <button class="btn btn-primary shadow-sm px-4 fw-bold rounded-pill" 
                data-bs-toggle="modal" 
                data-bs-target="#exportActionModal"
                @click="resetView">
            <i class="fa-solid fa-file-export me-2"></i> Export / Bundle
        </button>

        <teleport to="body">
            <div class="modal fade" id="exportActionModal" tabindex="-1" aria-hidden="true" style="z-index: 2000;">
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content border-0 shadow-lg" style="border-radius: 20px;">
                        
                        <div class="modal-header border-0 pb-0">
                            <div class="d-flex align-items-center">
                                <button v-if="currentView !== 'main'" @click="resetView" class="btn btn-sm btn-light rounded-circle me-2">
                                    <i class="fa-solid fa-arrow-left"></i>
                                </button>
                                <h5 class="modal-title fw-bold">
                                    [[ currentView === 'main' ? 'Export Actions' : (currentView === 'download' ? 'Download Options' : 'Bundle Management') ]]
                                </h5>
                            </div>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>

                        <div class="modal-body p-4">
                            <div v-if="currentView === 'main'" class="row g-3">
                                <p class="text-muted small mb-2 text-center">Matching <strong>[[ totalRules ]]</strong> rules. Choose an action:</p>
                                <div class="col-12">
                                    <div class="p-3 border rounded-4 cursor-pointer transition-all shadow-sm-hover" @click="currentView = 'download'">
                                        <div class="d-flex align-items-center text-start">
                                            <div class="bg-primary-subtle text-primary rounded-circle p-3 me-3">
                                                <i class="fa-solid fa-cloud-arrow-down fa-lg"></i>
                                            </div>
                                            <div class="flex-grow-1">
                                                <h6 class="mb-0 fw-bold">Download Files</h6>
                                                <small class="text-muted">Export rules to your device</small>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <template v-if="current_user_is_authenticated === 'True'">
                                    <div class="col-12">
                                        <div class="p-3 border rounded-4 cursor-pointer transition-all shadow-sm-hover" @click="currentView = 'bundle'">
                                            <div class="d-flex align-items-center text-start">
                                                <div class="bg-success-subtle text-success rounded-circle p-3 me-3">
                                                    <i class="fa-solid fa-box-archive fa-lg"></i>
                                                </div>
                                                <div class="flex-grow-1">
                                                    <h6 class="mb-0 fw-bold">Add to Bundle</h6>
                                                    <small class="text-muted">Save to a new or existing collection</small>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </template>
                            </div>

                            <div v-if="currentView === 'download'" class="row g-3">
                                <p class="text-muted small mb-2">Select your preferred export format:</p>
                                <div class="col-12" v-for="opt in [
                                    {id: 'json_each', icon: 'fa-file-code', color: 'text-warning', title: 'JSON (Individual)', desc: 'Each rule as .json'},
                                    {id: 'ext_each', icon: 'fa-file-lines', color: 'text-info', title: 'Native Extensions', desc: 'Yara (.yar), Sigma (.yaml), etc.'},
                                    {id: 'merged_by_type', icon: 'fa-file-zipper', color: 'text-primary', title: 'Merged by Type', desc: 'One file per format type'}
                                ]" :key="opt.id">
                                    <div class="p-3 border rounded-4 cursor-pointer" @click="downloadFormat(opt.id)">
                                        <div class="d-flex align-items-center text-start">
                                            <i class="fa-solid fa-lg me-3" :class="[opt.icon, opt.color]"></i>
                                            <div>
                                                <h6 class="mb-0 fw-bold small">[[ opt.title ]]</h6>
                                                <small class="text-muted italic">[[ opt.desc ]]</small>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <template v-if="current_user_is_authenticated === 'True'">
                                <div v-if="currentView === 'bundle'">
                                    <rule-bundle-manager 
                                        :total-rules="totalRules"
                                        :is-over-limit="isOverLimit"
                                        :max-limit="MAX_LIMIT"
                                        :filters="currentFilters"
                                        @processing="(val) => isProcessing = val"
                                        @completed="onBundleCompleted"
                                        :csrf="csrfToken"
                                    />
                                </div>
                            </template>
                            <div v-if="isProcessing" class="text-center mt-4">
                                <div class="spinner-border spinner-border-sm text-primary me-2"></div>
                                <span class="small text-muted fw-bold">PROCESSING...</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </teleport>
    </div>
    `
};

export default RuleExportAction;