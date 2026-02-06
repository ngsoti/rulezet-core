import MultiVulnerabilityFilter from '/static/js/vulnerability/multiVulnerabilityFilter.js';
import MultiSourceFilter from '/static/js/rule/multiSourceFilter.js';

const RuleFilterBar = {
    props: {
        apiEndpoint: { type: String, required: true },
        authorFilter: { type: String, default: '' },
        placeholder: { type: String, default: 'Search rules...' },
        autoFetch: { type: Boolean, default: true },
        userId: { type: Number, default: null },
        
        hiddenFields: { type: Array, default: () => [] },
        sourceRules: { type: String, default: '' }
    },
    emits: ['update:results', 'loading'],
    delimiters: ['[[', ']]'],
    components: {
        'multi-vulnerability-filter': MultiVulnerabilityFilter,
        'multi-source-filter': MultiSourceFilter
    },
    setup(props, { emit }) {
        const searchQuery = Vue.ref('');
        const sortBy = Vue.ref('newest');
        const ruleType = Vue.ref('');
        const searchIsLoading = Vue.ref(false);
        
        const selectedSourceNames = Vue.ref([]); 
        const selectedVulnerabilityNames = Vue.ref([]); 
        const rulesFormats = Vue.ref([]);

      
        const isVisible = (field) => !props.hiddenFields.includes(field);

        Vue.watch(searchQuery, (newVal) => {
            if (newVal.trim() === '') fetchRules(1);
        });

        const fetchMetadata = async () => {
            if (!isVisible('format')) return; 
            try {
                const res = await fetch('/rule/get_rules_formats');
                const data = await res.json();
                rulesFormats.value = data.formats || [];
            } catch (e) { console.error("Metadata fetch error:", e); }
        };

        const fetchRules = async (page = 1) => {
            searchIsLoading.value = true;
            emit('loading', true);

            const params = new URLSearchParams();
            params.append('page', page.toString());
            params.append('search', searchQuery.value || '');
            params.append('author', props.authorFilter || '');

            if (isVisible('sort')) params.append('sort_by', sortBy.value);
            if (isVisible('format')) params.append('rule_type', ruleType.value || '');

            if (props.userId !== null && !isNaN(props.userId)) {
                params.append('user_id', props.userId.toString());
            }

           
            if (props.sourceRules) {
                params.append('sources', props.sourceRules);
            } else if (isVisible('sources') && selectedSourceNames.value.length > 0) {
                params.append('sources', selectedSourceNames.value.join(','));
            }
            
            if (isVisible('vulnerabilities') && selectedVulnerabilityNames.value.length > 0) {
                params.append('vulnerabilities', selectedVulnerabilityNames.value.join(','));
            }

            try {
                const url = `${props.apiEndpoint}?${params.toString()}`;
                const res = await fetch(url);
                const data = await res.json();
                
                emit('update:results', {
                    rules: data, 
                    total_pages: data.total_pages,
                    total_rules: data.total_rules, 
                    current_page: page
                });
            } catch (error) {
                console.error("Fetch rules error:", error);
            } finally {
                searchIsLoading.value = false;
                emit('loading', false);
            }
        };

        const clearSearch = () => { searchQuery.value = ''; };

        Vue.onMounted(() => { 
            fetchMetadata(); 
            if (props.autoFetch) fetchRules(1); 
        });

        return {
            searchQuery, sortBy, ruleType, selectedSourceNames, 
            selectedVulnerabilityNames, searchIsLoading, rulesFormats, 
            fetchRules, clearSearch, isVisible
        };
    },
    template: `
    <div class="card shadow-sm border-0 mb-4" style="border-radius: 15px; background-color: var(--card-bg-color);">
        <div class="card-body p-4 position-relative">
            <div v-if="searchIsLoading" class="position-absolute top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center" 
                 style="background: rgba(255,255,255,0.5); z-index: 10; border-radius: 15px;">
            </div>

            <div class="row g-3">
                <div :class="isVisible('sort') || isVisible('format') ? 'col-md-6' : 'col-md-12'" v-if="isVisible('search')">
                    <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">Keywords</label>
                    <div class="input-group input-group-sm position-relative">
                        <span class="input-group-text border-0 bg-light text-muted" style="border-radius: 10px 0 0 10px; min-width: 40px; justify-content: center;">
                            <div v-if="searchIsLoading" class="spinner-border spinner-border-sm text-primary" role="status"></div>
                            <i v-else class="fa-solid fa-magnifying-glass"></i>
                        </span>
                        <input type="text" v-model="searchQuery" @keyup.enter="fetchRules(1)" 
                            class="form-control border-0 bg-light pe-5" :placeholder="placeholder" 
                            style="border-radius: 0 10px 10px 0; height: 38px;" :disabled="searchIsLoading">
                        <span v-if="searchQuery && !searchIsLoading" @click="clearSearch" class="position-absolute end-0 top-50 translate-middle-y me-2 text-muted cursor-pointer" style="z-index: 5; cursor: pointer;">
                            <i class="fa-solid fa-circle-xmark opacity-50"></i>
                        </span>
                    </div>
                </div>

                <div class="col-md-3" v-if="isVisible('sort')">
                    <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">Sort</label>
                    <select v-model="sortBy" class="form-select form-select-sm border-0 bg-light px-3" @change="fetchRules(1)" 
                            style="border-radius: 10px; height: 38px;" :disabled="searchIsLoading">
                        <option value="newest">Newest</option>
                        <option value="oldest">Oldest</option>
                        <option value="most_likes">Most Liked</option>
                    </select>
                </div>

                <div class="col-md-3" v-if="isVisible('format')">
                    <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">Format</label>
                    <select v-model="ruleType" class="form-select form-select-sm border-0 bg-light px-3" @change="fetchRules(1)" 
                            style="border-radius: 10px; height: 38px;" :disabled="searchIsLoading">
                        <option value="">All Formats</option>
                        <option v-for="f in rulesFormats" :key="f.id" :value="f.name">[[ f.name.toUpperCase() ]]</option>
                    </select>
                </div>
            </div>

            <div class="row g-3 mt-1" v-if="isVisible('sources') || isVisible('vulnerabilities')" 
                 :style="{ opacity: searchIsLoading ? 0.6 : 1, pointerEvents: searchIsLoading ? 'none' : 'auto' }">
                
                <div :class="isVisible('vulnerabilities') ? 'col-md-6' : 'col-md-12'" v-if="isVisible('sources')">
                    <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">
                        <i class="fa-solid fa-code-branch me-1 text-primary"></i> Sources
                    </label>
                    <multi-source-filter v-model="selectedSourceNames" @change="fetchRules(1)"
                        api-endpoint="/rule/get_rules_sources_usage" placeholder="Filter sources..." :userId="userId">
                    </multi-source-filter>
                </div>

                <div :class="isVisible('sources') ? 'col-md-6' : 'col-md-12'" v-if="isVisible('vulnerabilities')">
                    <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">
                        <i class="fa-solid fa-shield-virus me-1 text-danger"></i> Vulnerabilities
                    </label>
                    <multi-vulnerability-filter 
                        v-model="selectedVulnerabilityNames" 
                        @change="fetchRules(1)"
                        api-endpoint="/rule/get_all_rules_vulnerabilities_usage" 
                        placeholder="CVE, GHSA..." 
                        :user-id="userId"
                        :source-rules="sourceRules"> </multi-vulnerability-filter>
                </div>
            </div>
        </div>
    </div>
    `
};
export default RuleFilterBar;