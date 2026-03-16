const GithubFilter = {
    props: {
        apiEndpoint: { type: String, required: true },
        placeholder: { type: String, default: 'Search by repository URL...' },
        autoFetch: { type: Boolean, default: true }
    },
    emits: ['update:results', 'loading'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const searchQuery = Vue.ref('');
        const searchField = Vue.ref('url'); 
        const selectedFormat = Vue.ref('');
        const authorQuery = Vue.ref('');
        const searchIsLoading = Vue.ref(false);
        const totalUrls = Vue.ref(0);
        const availableFormats = Vue.ref([]);

        const fetchMetadata = async () => {
            try {
                const res = await fetch('/rule/get_rules_formats');
                const data = await res.json();
                availableFormats.value = data.formats || [];
            } catch (e) { 
                availableFormats.value = [];
            }
        };

        const fetchUrls = async (page = 1) => {
            searchIsLoading.value = true;
            emit('loading', true);

            const params = new URLSearchParams({
                page: page.toString(),
                search: searchQuery.value || '',
                search_field: searchField.value,
                format: selectedFormat.value,
                author: authorQuery.value
            });

            try {
                const res = await fetch(`${props.apiEndpoint}?${params.toString()}`);
                const data = await res.json();
                
                if (res.status === 200) {
                    totalUrls.value = data.total_url || 0;
                    emit('update:results', {
                        github_url: data.github_url || [],
                        total_url: data.total_url || 0,
                        total_pages: data.total_pages || 1,
                        current_page: page
                    });
                }
            } catch (err) {
                console.error('Error fetching GitHub URLs:', err);
            } finally {
                searchIsLoading.value = false;
                emit('loading', false);
            }
        };

        const clearSearch = () => {
            searchQuery.value = '';
            fetchUrls(1);
        };

        const clearAuthor = () => {
            authorQuery.value = '';
            fetchUrls(1);
        };
        
        Vue.watch([searchQuery, authorQuery], ([newSearch, newAuthor], [oldSearch, oldAuthor]) => {
            if ((oldSearch !== '' && newSearch === '') || (oldAuthor !== '' && newAuthor === '')) {
                fetchUrls(1);
            }
        });

        Vue.onMounted(() => {
            fetchMetadata();
            if (props.autoFetch) fetchUrls(1);
        });

        return {
            searchQuery,
            searchField,
            selectedFormat,
            searchIsLoading,
            totalUrls,
            availableFormats,
            fetchUrls,
            clearSearch,
            clearAuthor,
            authorQuery
        };
    },
    template: `
   <div class="card shadow-sm border-0 mb-4 rounded-4" style="background-color: var(--card-bg-color);">
        <div class="card-body p-4">
            <div class="row g-3 align-items-end">
                <div class="col-md-5">
                    <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">Keywords</label>
                    <div class="input-group input-group-sm position-relative shadow-sm rounded-3 overflow-hidden">
                        <select v-model="searchField" class="form-select border-0 text-muted small fw-bold" @change="fetchUrls(1)" style="max-width: 80px; background-color: var(--bg-color);">
                            <option value="url">URL</option>
                            <option value="all">All</option>
                        </select>
                        <span class="input-group-text border-0 text-muted" style="background-color: var(--bg-color);">
                            <i v-if="!searchIsLoading" class="fa-solid fa-magnifying-glass"></i>
                            <span v-else class="spinner-border spinner-border-sm text-primary"></span>
                        </span>
                        <input type="text" v-model="searchQuery" @keyup.enter="fetchUrls(1)" class="form-control border-0" :placeholder="placeholder" style="height: 38px; background-color: var(--bg-color);">
                        
                        <span v-if="searchQuery" @click="clearSearch" class="position-absolute end-0 top-50 translate-middle-y me-2 text-muted cursor-pointer" style="z-index: 5;">
                            <i class="fa-solid fa-circle-xmark opacity-50"></i>
                        </span>
                    </div>
                </div>

                <div class="col-md-3">
                    <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">Author</label>
                    <div class="input-group input-group-sm position-relative shadow-sm rounded-3 overflow-hidden">
                        <input type="text" 
                            v-model="authorQuery" 
                            @keyup.enter="fetchUrls(1)" 
                            class="form-control border-0" 
                            placeholder="e.g. Neo23x0" 
                            style="height: 38px; background-color: var(--bg-color);">
                        
                        <span v-if="authorQuery" 
                            @click="clearAuthor" 
                            class="position-absolute end-0 top-50 translate-middle-y me-2 text-muted cursor-pointer" 
                            style="z-index: 5;">
                            <i class="fa-solid fa-circle-xmark opacity-50"></i>
                        </span>
                    </div>
                </div>

                <div class="col-md-2">
                    <label class="small fw-bold text-muted mb-1 ms-1 text-uppercase">Format</label>
                    <select v-model="selectedFormat" @change="fetchUrls(1)" class="form-select form-select-sm border-0 shadow-sm" style="border-radius: 10px; height: 38px; background-color: var(--bg-color);">
                        <option value="">All</option>
                        <option v-for="fmt in availableFormats" 
                                :key="typeof fmt === 'object' ? fmt.name : fmt" 
                                :value="typeof fmt === 'object' ? fmt.name : fmt">
                            [[ typeof fmt === 'object' ? fmt.name : fmt ]]
                        </option>
                    </select>
                </div>

                <div class="col-md-2 text-end">
                    <div class="border-start ps-3 text-start">
                        <small class="text-muted d-block text-uppercase fw-bold" style="font-size: 0.6rem;">Total</small>
                        <span class="h5 fw-bold mb-0 text-primary">[[ totalUrls ]]</span>
                    </div>
                </div>
            </div>
        </div>
    </div>
    `
};

export default GithubFilter;