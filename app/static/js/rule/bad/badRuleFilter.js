import BadRuleMultiErrorMessage from '/static/js/rule/bad/badRuleMultiErrorMessage.js';
import BadRuleMultiSource from '/static/js/rule/bad/badRuleMultiSource.js';
import badRuleMultiLicense from '/static/js/rule/bad/badRuleMultiLicense.js';

const BadRuleFilterBar = {
    props: {
        apiEndpoint: { type: String, required: true },
        userId: { type: Number, default: null },
        placeholder: { type: String, default: 'Search rules...' },
        hiddenFields: { type: Array, default: () => [] },
    },
    emits: ['update:results', 'loading'],
    delimiters: ['[[', ']]'],
    components: {
        'bad-rule-multi-error-message': BadRuleMultiErrorMessage,
        'bad-rule-multi-source': BadRuleMultiSource,
        'bad-rule-multi-license': badRuleMultiLicense
    },
    setup(props, { emit }) {
        const searchQuery = Vue.ref('');
        const searchField = Vue.ref('all');
        const searchIsLoading = Vue.ref(false);

        const rulesFormats = Vue.ref([]); 
        const selectedFormat = Vue.ref('');

        const selectedErrorMessages = Vue.ref([]);
        const selectedSources = Vue.ref([]);
        const selectedLicenses = Vue.ref([]);

        const total_rules_count = Vue.ref(0);

        const isVisible = (field) => !props.hiddenFields.includes(field);

        const hasActiveFilters = Vue.computed(() => {
            return searchQuery.value.trim() !== '' ||
                   selectedErrorMessages.value.length > 0 ||
                   selectedSources.value.length > 0;
        });

        Vue.watch(searchQuery, (newVal) => {
            if (newVal.trim() === '') fetchRules(1);
        });
        const getParams = () => {
            const params = new URLSearchParams();
            params.append('search', searchQuery.value || '');
            params.append('search_field', searchField.value);
            return params;
        }
        const fetchRules = async (page = 1) => {
            searchIsLoading.value = true;
            emit('loading', true);

            const params = new URLSearchParams();
            params.append('page', page.toString());
            params.append('search', searchQuery.value || '');
            params.append('search_field', searchField.value);

            if (props.userId !== null && !isNaN(props.userId)) {
                params.append('user_id', props.userId.toString());
            }

            if (selectedErrorMessages.value.length > 0) {
                params.append('error_messages', selectedErrorMessages.value.join(','));
            }

            if (selectedSources.value.length > 0) {
                params.append('sources', selectedSources.value.join(','));
            }

            if (selectedLicenses.value.length > 0) {
                params.append('licenses', selectedLicenses.value.join(','));
            }

            params.append('rule_types', selectedFormat.value);

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

        const clearSearch = () => {
            searchQuery.value = '';
        };

        const fetchMetadata = async () => {
            try {
                const res = await fetch('/rule/get_rules_formats');
                const data = await res.json();
                rulesFormats.value = data.formats || [];
            } catch (e) { console.error("Metadata fetch error:", e); }
        };

        Vue.onMounted(() => {
            fetchMetadata();
            fetchRules(1);
        });

        return {
            searchQuery,
            searchField,
            selectedErrorMessages,
            selectedSources,
            searchIsLoading,
            fetchRules,
            clearSearch,
            isVisible,
            hasActiveFilters,
            total_rules_count,
            fetchMetadata,
            rulesFormats,
            selectedFormat,
            selectedLicenses,
            selectedSources,
            getParams
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
                <i class="fas fa-filter me-2"></i>Filter Rules
            </button>
        </div>

        <div class="collapse" id="collapseFilter">
            <div class="card shadow-sm border-0 mb-4" style="border-radius: 15px; background-color: var(--card-bg-color);">
                <div class="card-body p-4 position-relative">
                    
                    <div v-if="searchIsLoading" class="position-absolute top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center"
                        style="background: rgba(255,255,255,0.5); z-index: 10; border-radius: 15px;">
                        <div class="spinner-border text-primary" role="status"></div>
                    </div>

                    <div class="row g-3">
                        <div :class="isVisible('search') ? 'col-md-6' : 'col-md-12'" v-if="isVisible('search')">
                            <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">Keywords</label>

                            <div class="input-group input-group-sm position-relative shadow-sm"
                                style="border-radius: 10px; overflow: hidden; background-color: var(--bg-color);">

                                <select v-model="searchField"
                                        class="form-select border-0 text-muted small fw-bold"
                                        @change="fetchRules(1)"
                                        style="max-width: 100px; font-size: 0.75rem; border-right: 1px solid; background-color: var(--bg-color); cursor: pointer;">
                                    <option value="all">All</option>
                                    <option value="file_name">File Name</option>
                                    <option value="error_message">Error</option>
                                </select>

                                <span class="input-group-text border-0 text-muted"
                                    style="min-width: 40px; justify-content: center; background-color: var(--bg-color);">
                                    <i class="fa-solid fa-magnifying-glass"></i>
                                </span>

                                <input type="text"
                                    v-model="searchQuery"
                                    @keyup.enter="fetchRules(1)"
                                    class="form-control border-0 pe-5"
                                    :placeholder="placeholder"
                                    style="height: 38px;"
                                    :disabled="searchIsLoading">

                                <span v-if="searchQuery && !searchIsLoading"
                                    @click="clearSearch"
                                    class="position-absolute end-0 top-50 translate-middle-y me-2 text-muted cursor-pointer"
                                    style="z-index: 5;">
                                    <i class="fa-solid fa-circle-xmark opacity-50"></i>
                                </span>
                            </div>
                        </div>

                        <div class="col-md-3">
                            <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">Format</label>
                            <select v-model="selectedFormat" 
                                    class="form-select form-select-sm border-0 bg-light px-3" 
                                    @change="fetchRules(1)" 
                                    style="border-radius: 10px; height: 38px;" 
                                    :disabled="searchIsLoading">
                                <option value="">All Formats</option>
                                <option v-for="f in rulesFormats" :key="f.id" :value="f.name">
                                    [[ f.name.toUpperCase() ]]
                                </option>
                            </select>
                        </div>
                    </div>

                    <div class="row g-3 mt-1" v-if="isVisible('error_messages') || isVisible('sources')"
                        :style="{ opacity: searchIsLoading ? 0.6 : 1, pointerEvents: searchIsLoading ? 'none' : 'auto' }">

                        <div class="col-md-6" v-if="isVisible('error_messages')">
                            <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">
                                <i class="fa-solid fa-bug me-1 text-danger"></i> Error Messages
                            </label>
                            <bad-rule-multi-error-message v-model="selectedErrorMessages" @change="fetchRules(1)"
                                api-endpoint="/rule/get_bad_rules_error_messages_usage" placeholder="Filter errors..." :userId="userId">
                            </bad-rule-multi-error-message>
                        </div>

                        <div class="col-md-6" v-if="isVisible('sources')">
                            <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">
                                <i class="fa-solid fa-code-branch me-1 text-primary"></i> Sources
                            </label>
                            <bad-rule-multi-source v-model="selectedSources" @change="fetchRules(1)"
                                api-endpoint="/rule/get_bad_rules_sources_usage" placeholder="Filter sources..." :userId="userId">
                            </bad-rule-multi-source>
                        </div>
                    </div>

                    <div class="row g-3 mt-1" v-if="isVisible('licenses')">
                        <div class="col-md-6">
                            <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">
                                <i class="fa-solid fa-scale-balanced me-1 text-info"></i> Licenses
                            </label>
                            <bad-rule-multi-license v-model="selectedLicenses" @change="fetchRules(1)"
                                api-endpoint="/rule/get_bad_rules_licenses_usage" placeholder="Filter licenses..." :userId="userId">
                            </bad-rule-multi-license>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    `
};

export default BadRuleFilterBar;