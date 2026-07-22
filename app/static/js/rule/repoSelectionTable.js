import PaginationComponent from '/static/js/rule/paginationComponent.js';

/**
 * Repo picker for Sync Schedules — true "select all N matching this filter"
 * bulk selection (selectedUrls/excludedUrls/isAllSelectedMode), mirroring
 * app/static/js/rule/ruleSelectionTable.js's pattern (the one fully-working
 * "select all across pages" implementation in the codebase) adapted to
 * GitHub repo rows instead of Rule rows, and to *emit* the current
 * selection instead of submitting it — the parent Sync Schedule form
 * combines it with title/description/recurrence into one create/update call.
 */
const RepoSelectionTable = {
    props: {
        apiEndpoint: { type: String, default: '/rule/github/schedule/repo_candidates' },
        initialSelectedUrls: { type: Array, default: () => [] },
        initialRepoSettings: { type: Object, default: () => ({}) },
    },
    delimiters: ['[[', ']]'],
    components: { 'pagination-component': PaginationComponent },
    data() {
        return {
            repos: [],
            allLoadedRepos: new Map(),
            totalRepos: 0,
            currentPage: 1,
            totalPages: 1,
            loading: false,

            search: '',
            searchField: 'url',
            formatFilter: '',
            authorFilter: '',

            selectedUrls: new Set(this.initialSelectedUrls),
            excludedUrls: new Set(),
            isAllSelectedMode: false,
            perRepoSettings: new Map(Object.entries(this.initialRepoSettings)),
            defaultSettings: { auto_accept_update: false, auto_add_new_rule: false },
        };
    },
    computed: {
        currentFilters() {
            return {
                search: this.search || null,
                search_field: this.searchField,
                format: this.formatFilter || null,
                author: this.authorFilter || null,
            };
        },
        selectedCount() {
            if (this.isAllSelectedMode) return this.totalRepos - this.excludedUrls.size;
            return this.selectedUrls.size;
        },
        isPageFullySelected() {
            if (this.repos.length === 0) return false;
            return this.repos.every(r => this.isRepoChecked(r.url));
        },
        manuallySelectedRepos() {
            if (this.isAllSelectedMode) return [];
            const out = [];
            for (const url of this.selectedUrls) {
                const repo = this.allLoadedRepos.get(url);
                out.push({ url, rule_count: repo ? repo.rule_count : null });
                if (out.length >= 100) break;
            }
            return out;
        },
    },
    mounted() {
        this.fetchRepos(1);
    },
    methods: {
        async fetchRepos(page) {
            this.loading = true;
            const params = new URLSearchParams({ page });
            if (this.search) params.set('search', this.search);
            params.set('search_field', this.searchField);
            if (this.formatFilter) params.set('format', this.formatFilter);
            if (this.authorFilter) params.set('author', this.authorFilter);

            try {
                const res = await fetch(this.apiEndpoint + '?' + params.toString());
                const data = await res.json();
                if (res.status === 200) {
                    this.repos = data.repos || [];
                    this.repos.forEach(r => this.allLoadedRepos.set(r.url, r));
                    this.totalRepos = data.total || 0;
                    this.totalPages = data.total_pages || 1;
                    this.currentPage = page;
                } else {
                    this.repos = [];
                    this.totalRepos = 0;
                    this.totalPages = 1;
                }
            } finally {
                this.loading = false;
            }
        },

        onSearchInput() {
            clearTimeout(this._searchTimer);
            this._searchTimer = setTimeout(() => this.fetchRepos(1), 300);
        },

        toggleAllOnPage(event) {
            const checked = event.target.checked;
            this.repos.forEach(r => this.updateSelection(r.url, checked));
        },

        updateSelection(url, isChecked) {
            if (this.isAllSelectedMode) {
                if (!isChecked) this.excludedUrls.add(url);
                else this.excludedUrls.delete(url);
            } else {
                if (isChecked) this.selectedUrls.add(url);
                else { this.selectedUrls.delete(url); this.perRepoSettings.delete(url); }
            }
            this.emitChange();
        },

        isRepoChecked(url) {
            if (this.isAllSelectedMode) return !this.excludedUrls.has(url);
            return this.selectedUrls.has(url);
        },

        toggleGlobalSelectAll() {
            this.isAllSelectedMode = true;
            this.selectedUrls.clear();
            this.excludedUrls.clear();
            this.emitChange();
        },

        clearAllSelection() {
            this.isAllSelectedMode = false;
            this.selectedUrls.clear();
            this.excludedUrls.clear();
            this.perRepoSettings.clear();
            this.emitChange();
        },

        repoSetting(url, key) {
            const cfg = this.perRepoSettings.get(url);
            return cfg ? !!cfg[key] : false;
        },

        updateRepoSetting(url, key, value) {
            const cfg = this.perRepoSettings.get(url) || { auto_accept_update: false, auto_add_new_rule: false };
            cfg[key] = value;
            this.perRepoSettings.set(url, cfg);
            this.emitChange();
        },

        updateDefaultSetting(key, value) {
            this.defaultSettings[key] = value;
            this.emitChange();
        },

        emitChange() {
            const repo_settings = Array.from(this.perRepoSettings.entries()).map(([repo_url, cfg]) => ({
                repo_url, auto_accept_update: !!cfg.auto_accept_update, auto_add_new_rule: !!cfg.auto_add_new_rule,
            }));
            this.$emit('selection-change', {
                repo_mode: this.isAllSelectedMode ? 'all' : 'partial',
                repo_filters: this.isAllSelectedMode ? this.currentFilters : null,
                selected_repo_urls: Array.from(this.selectedUrls),
                excluded_repo_urls: Array.from(this.excludedUrls),
                repo_settings,
                default_repo_settings: this.isAllSelectedMode ? { ...this.defaultSettings } : null,
                count: this.selectedCount,
            });
        },
    },
    template: `
    <div class="repo-selection-container">
        <div class="dt-toolbar mb-3">
            <div class="dt-toolbar-left">
                <div class="dt-search">
                    <i class="fas fa-search dt-search-icon"></i>
                    <input class="dt-search-input" type="text" placeholder="Search repository…"
                        v-model="search" @input="onSearchInput" aria-label="Search GitHub repositories" />
                </div>
                <input class="rl-fp-select" type="text" placeholder="Filter by author…"
                    v-model="authorFilter" @change="fetchRepos(1)" style="max-width:180px;" />
            </div>
            <div class="dt-toolbar-right">
                <button v-if="!isAllSelectedMode" class="dt-toolbar-btn dt-toolbar-btn--primary" @click="toggleGlobalSelectAll">
                    <i class="fa-solid fa-check-double"></i><span>Select all [[ totalRepos ]] matching</span>
                </button>
                <button v-else class="dt-toolbar-btn" @click="clearAllSelection">
                    <i class="fa-solid fa-xmark"></i><span>Clear selection</span>
                </button>
            </div>
        </div>

        <div v-if="isAllSelectedMode" class="rl-filter-panel mb-3">
            <div class="rl-fp-row">
                <div class="rl-fp-item">
                    <div class="fw-bold mb-2" style="font-size:.82rem;">
                        <i class="fa-solid fa-globe me-1 text-primary"></i>
                        Default automation for all [[ selectedCount ]] matching repositories
                    </div>
                    <div class="d-flex gap-4">
                        <div class="form-check form-switch mb-0">
                            <input class="form-check-input" type="checkbox" :checked="defaultSettings.auto_accept_update"
                                @change="updateDefaultSetting('auto_accept_update', $event.target.checked)">
                            <label class="form-check-label" style="font-size:.82rem;">Auto-accept updates</label>
                        </div>
                        <div class="form-check form-switch mb-0">
                            <input class="form-check-input" type="checkbox" :checked="defaultSettings.auto_add_new_rule"
                                @change="updateDefaultSetting('auto_add_new_rule', $event.target.checked)">
                            <label class="form-check-label" style="font-size:.82rem;">Auto-add new rules</label>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="dt-table-wrap">
            <table class="dt-table">
                <thead class="dt-thead">
                    <tr>
                        <th class="dt-th dt-th--checkbox">
                            <input type="checkbox" class="dt-checkbox" :checked="isPageFullySelected" @change="toggleAllOnPage" />
                        </th>
                        <th class="dt-th">Repository</th>
                        <th class="dt-th text-center">Rules</th>
                        <th class="dt-th">Formats</th>
                        <th class="dt-th">Author</th>
                    </tr>
                </thead>
                <tbody v-if="!loading && repos.length > 0">
                    <tr v-for="repo in repos" :key="repo.url" class="dt-row">
                        <td class="dt-td dt-td--checkbox">
                            <input type="checkbox" class="dt-checkbox" :checked="isRepoChecked(repo.url)"
                                @change="updateSelection(repo.url, $event.target.checked)" />
                        </td>
                        <td class="dt-td dt-td--truncate" style="max-width:320px;" :title="repo.url">[[ repo.url ]]</td>
                        <td class="dt-td text-center">[[ repo.rule_count ]]</td>
                        <td class="dt-td">
                            <span v-for="fmt in repo.formats" :key="fmt" class="repo-fmt-badge">[[ fmt ]]</span>
                        </td>
                        <td class="dt-td">[[ repo.author || '—' ]]</td>
                    </tr>
                </tbody>
            </table>
            <div v-if="loading" class="dt-empty">
                <div class="spinner-border spinner-border-sm"></div>
            </div>
            <div v-else-if="repos.length === 0" class="dt-empty">
                <div class="dt-empty-icon"><i class="fa-brands fa-github"></i></div>
                <p class="dt-empty-text">No GitHub-sourced repositories found.</p>
            </div>
        </div>

        <pagination-component :current-page="currentPage" :total-pages="totalPages" @change-page="fetchRepos"></pagination-component>

        <div v-if="!isAllSelectedMode && manuallySelectedRepos.length > 0" class="rl-filter-panel mt-3">
            <div class="fw-bold mb-2" style="font-size:.82rem;">
                Selected repositories ([[ selectedCount ]]) — per-repo automation
            </div>
            <div class="dt-table-wrap">
                <table class="dt-table">
                    <thead class="dt-thead">
                        <tr>
                            <th class="dt-th">Repository</th>
                            <th class="dt-th text-center">Auto-accept updates</th>
                            <th class="dt-th text-center">Auto-add new rules</th>
                            <th class="dt-th dt-th--checkbox"></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="item in manuallySelectedRepos" :key="item.url" class="dt-row">
                            <td class="dt-td dt-td--truncate" style="max-width:320px;" :title="item.url">[[ item.url ]]</td>
                            <td class="dt-td text-center">
                                <input type="checkbox" class="dt-checkbox" :checked="repoSetting(item.url, 'auto_accept_update')"
                                    @change="updateRepoSetting(item.url, 'auto_accept_update', $event.target.checked)">
                            </td>
                            <td class="dt-td text-center">
                                <input type="checkbox" class="dt-checkbox" :checked="repoSetting(item.url, 'auto_add_new_rule')"
                                    @change="updateRepoSetting(item.url, 'auto_add_new_rule', $event.target.checked)">
                            </td>
                            <td class="dt-td text-center">
                                <button class="dt-action-btn dt-action-btn--danger" @click="updateSelection(item.url, false)" title="Remove">
                                    <i class="fa-solid fa-xmark"></i>
                                </button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    `,
};

export default RepoSelectionTable;
