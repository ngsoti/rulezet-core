import MultiVulnerabilityFilter from '/static/js/vulnerability/multiVulnerabilityFilter.js';
import MultiSourceFilter from '/static/js/rule/multiSourceFilter.js';
import MultiLicenseFilter from '/static/js/rule/multiLicenseFilter.js';
import MultiTagFilter from '/static/js/tags/multiTagFIlter.js';
import RuleExportAction from '/static/js/rule/ruleExportAction.js';

const RuleFilterBar = {
    props: {
        apiEndpoint: { type: String, required: true },
        authorFilter: { type: String, default: '' },
        placeholder: { type: String, default: 'Search rules...' },
        autoFetch: { type: Boolean, default: true },
        userId: { type: Number, default: null },
        hiddenFields: { type: Array, default: () => [] },
        sourceRules: { type: String, default: '' },
        csrfToken: { type: String, default: '' },
        currentUserIsAuthenticated: { type: Boolean, default: false },
        showExport: { type: Boolean, default: true },
        exactMatch: { type: Boolean, default: false } ,
        initialFilters: { type: Object, default: () => ({}) },
    },
    emits: ['update:results', 'loading'],
    delimiters: ['[[', ']]'],
    components: {
        'multi-vulnerability-filter': MultiVulnerabilityFilter,
        'multi-source-filter': MultiSourceFilter,
        'multi-license-filter': MultiLicenseFilter,
        'multi-tag-filter': MultiTagFilter,
        'rule-export-action': RuleExportAction
    },
    setup(props, { emit }) {

        const init = props.initialFilters;

        const searchQuery = Vue.ref(init.search || '');
        const searchField = Vue.ref(init.search_field || 'all');
        const exactMatch = Vue.ref(init.exact_match === 'true' || props.exactMatch);
        const sortBy = Vue.ref(init.sort_by || 'newest');


        const ruleType = Vue.ref(init.format || '');
        const searchIsLoading = Vue.ref(false);
        const csrfToken = Vue.ref(props.csrfToken);

        const selectedSourceNames = Vue.ref(init.sources ? init.sources.split(',') : []); 
        const selectedVulnerabilityNames = Vue.ref(init.vulnerabilities ? init.vulnerabilities.split(',') : []); 
        const selectedLicenseNames = Vue.ref(init.licenses ? init.licenses.split(',') : []);
       
        const selectedTagNames = Vue.ref(init.tags ? init.tags.split(',') : []);

        const rulesFormats = Vue.ref([]);
        const total_rules_count = Vue.ref(0);
        const current_user_is_authenticated = Vue.ref(props.currentUserIsAuthenticated);

        const isVisible = (field) => !props.hiddenFields.includes(field);

        const hasActiveFilters = Vue.computed(() => {
            return searchQuery.value.trim() !== '' || 
                   ruleType.value !== '' || 
                   selectedSourceNames.value.length > 0 || 
                   selectedVulnerabilityNames.value.length > 0 || 
                   selectedLicenseNames.value.length > 0 || 
                   selectedTagNames.value.length > 0;
        });

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
            params.append('search_field', searchField.value);
            params.append('exact_match', exactMatch.value ? 'true' : 'false');
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

            if (isVisible('licenses') && selectedLicenseNames.value.length > 0) {
                params.append('licenses', selectedLicenseNames.value.join(','));
            }

            if (isVisible('tags') && selectedTagNames.value.length > 0) {
                params.append('tags', selectedTagNames.value.join(','));
            }

            try {
                const url = `${props.apiEndpoint}?${params.toString()}`;
                const res = await fetch(url);
                const data = await res.json();
                total_rules_count.value = data.total_rules;
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
            searchQuery, searchField, sortBy, ruleType, selectedSourceNames, 
            selectedVulnerabilityNames, selectedLicenseNames, selectedTagNames,
            searchIsLoading, rulesFormats, fetchRules, clearSearch, isVisible, hasActiveFilters, total_rules_count, csrfToken, current_user_is_authenticated,
            exactMatch
        };
    },
    template: `
    <div class="filter-container">
        <div class="d-inline-flex gap-1 mb-3">
            <button class="btn btn-primary rounded-pill px-3 shadow-sm" 
                    type="button" 
                    data-bs-toggle="collapse" 
                    data-bs-target="#collapseFilter" 
                    aria-expanded="false" 
                    aria-controls="collapseFilter">
                <i class="fas fa-filter me-2"></i>Filter Rules <i class="fas fa-chevron-down"></i>
            </button>
        </div>

        <div class="collapse show" id="collapseFilter">
            <div class="card shadow-sm border-0 mb-4" style="border-radius: 15px; background-color: var(--card-bg-color);">
                <div class="card-body p-4 position-relative">
                    <div v-if="searchIsLoading" class="position-absolute top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center" 
                        style="background: rgba(255,255,255,0.5); z-index: 10; border-radius: 15px;">
                    </div>

                    <div class="row g-3">
                        <div :class="isVisible('sort') || isVisible('format') ? 'col-md-6' : 'col-md-12'" v-if="isVisible('search')">
                            <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">Keywords</label>

                            <!-- INPUT GROUP -->
                            <div class="input-group input-group-sm position-relative shadow-sm"
                                style="border-radius: 10px; overflow: hidden; background-color: var(--bg-color);">

                                <select v-model="searchField"
                                        class="form-select border-0 text-muted small fw-bold"
                                        @change="fetchRules(1)"
                                        style="max-width: 100px; font-size: 0.75rem; border-right: 1px solid; background-color: var(--bg-color); cursor: pointer;">
                                    <option value="all">All</option>
                                    <option value="title">Title</option>
                                    <option value="content">Content</option>
                                </select>

                                <span class="input-group-text border-0 text-muted"
                                    style="min-width: 40px; justify-content: center; background-color: var(--bg-color);">
                                    <div v-if="searchIsLoading" class="spinner-border spinner-border-sm text-primary" role="status"></div>
                                    <i v-else class="fa-solid fa-magnifying-glass"></i>
                                </span>

                                <input type="text"
                                    v-model="searchQuery"
                                    @keyup.enter="fetchRules(1)"
                                    class="form-control border-0 pe-5"
                                    :placeholder="placeholder"
                                    style="height: 38px;"
                                    :disabled="searchIsLoading">

                                <!-- Clear button -->
                                <span v-if="searchQuery && !searchIsLoading"
                                    @click="clearSearch"
                                    class="position-absolute end-0 top-50 translate-middle-y me-2 text-muted cursor-pointer"
                                    style="z-index: 5;">
                                    <i class="fa-solid fa-circle-xmark opacity-50"></i>
                                </span>
                            </div>

                            <!-- EXACT MATCH SWITCH (moved outside input group) -->
                            <div class="form-check form-switch mt-2 ms-1">
                                <input class="form-check-input"
                                    type="checkbox"
                                    v-model="exactMatch"
                                    @change="fetchRules(1)"
                                    :disabled="searchIsLoading">
                                <label class="form-check-label small text-muted">
                                    Exact match
                                </label>
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

                    <div class="row g-3 mt-1" v-if="isVisible('sources') || isVisible('vulnerabilities') || isVisible('licenses') || isVisible('tags')" 
                        :style="{ opacity: searchIsLoading ? 0.6 : 1, pointerEvents: searchIsLoading ? 'none' : 'auto' }">
                        
                        <div class="col-md-6" v-if="isVisible('sources')">
                            <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">
                                <i class="fa-solid fa-code-branch me-1 text-primary"></i> Sources
                            </label>
                            <multi-source-filter v-model="selectedSourceNames" @change="fetchRules(1)"
                                api-endpoint="/rule/get_rules_sources_usage" placeholder="Filter sources..." :userId="userId">
                            </multi-source-filter>
                        </div>

                        <div class="col-md-6" v-if="isVisible('vulnerabilities')">
                            <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">
                                <i class="fa-solid fa-shield-virus me-1 text-danger"></i> Vulnerabilities
                            </label>
                            <multi-vulnerability-filter 
                                v-model="selectedVulnerabilityNames" 
                                @change="fetchRules(1)"
                                api-endpoint="/rule/get_all_rules_vulnerabilities_usage" 
                                placeholder="CVE, GHSA..." 
                                :user-id="userId"
                                :source-rules="sourceRules"> 
                            </multi-vulnerability-filter>
                        </div>

                        <div class="col-md-6" v-if="isVisible('licenses')">
                            <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">
                                <i class="fa-solid fa-scale-balanced me-1 text-info"></i> Licenses
                            </label>
                            <multi-license-filter 
                                v-model="selectedLicenseNames" 
                                @change="fetchRules(1)"
                                api-endpoint="/rule/get_rules_licenses_usage" 
                                placeholder="Filter licenses..." 
                                :user-id="userId"
                                :source-rules="sourceRules">
                            </multi-license-filter>
                        </div>

                        <div class="col-md-6" v-if="isVisible('tags')">
                            <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">
                                <i class="fa-solid fa-tags me-1 text-primary"></i> Tags
                            </label>
                            <multi-tag-filter 
                                v-model="selectedTagNames" 
                                @change="fetchRules(1)"
                                api-endpoint="/rule/get_all_tags_usage" 
                                placeholder="Filter tags..." 
                                :user-id="userId"
                                target-type="rule">
                            </multi-tag-filter>
                        </div>
                    </div>
                </div>

                <rule-export-action 
                    v-if="showExport && hasActiveFilters"
                    :search-query="searchQuery"
                    :sort-by="sortBy"
                    :rule-type="ruleType"
                    :selected-sources="selectedSourceNames"
                    :selected-vulnerabilities="selectedVulnerabilityNames"
                    :selected-licenses="selectedLicenseNames"
                    :selected-tags="selectedTagNames"
                    :user-id="userId"
                    :author-filter="authorFilter"
                    :total-rules="total_rules_count"
                    :csrf-token="csrfToken"
                    :current-user-is-authenticated="current_user_is_authenticated"
                    :search-field="searchField">
                </rule-export-action>
            </div>
        </div>
    </div>
    `
};

export default RuleFilterBar;