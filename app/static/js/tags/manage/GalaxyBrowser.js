import { mapIcon, truncateText } from '../utils/galaxie.js';
import BrowserPagination from './BrowserPagination.js';

const GalaxyBrowser = {
    components: { 'browser-pagination': BrowserPagination },
    props: { csrfToken: { type: String, required: true } },
    emits: ['notify', 'refresh-main'],
    setup(props, { emit }) {
        const { ref, computed, onMounted } = Vue;

        // ── galaxy list state ─────────────────────────────────────────────────
        const galaxies = ref([]);
        const total = ref(0);
        const totalPages = ref(1);
        const page = ref(1);
        const searchQ = ref('');
        const pageLoading = ref(false);
        const loadingMap = ref({});

        // ── cherry-pick panel state ───────────────────────────────────────────
        const pickGalaxy = ref(null);   // { uuid, name, galaxy_type, icon }
        const clusters = ref([]);
        const pickLoading = ref(false);
        const pickSearch = ref('');
        const selected = ref([]);
        const importing = ref(false);

        // ── load galaxy list ──────────────────────────────────────────────────
        async function load(p = 1) {
            pageLoading.value = true;
            try {
                const res = await fetch('/tags/get_tags_galaxy?' + new URLSearchParams({ page: p, search: searchQ.value }));
                const data = await res.json();
                if (res.ok) {
                    galaxies.value = data.tags;
                    total.value = data.total_tags;
                    totalPages.value = data.total_pages;
                    page.value = p;
                }
            } finally {
                pageLoading.value = false;
            }
        }

        // ── import all (original behaviour) ──────────────────────────────────
        async function importAll(g) {
            loadingMap.value[g.uuid] = true;
            try {
                const res = await fetch('/tags/add_tags_galaxy?' + new URLSearchParams({ uuid: g.uuid }));
                const data = await res.json();
                emit('notify', data.message, res.ok ? 'success-subtle' : 'danger-subtle');
                if (res.ok) { await load(page.value); emit('refresh-main'); }
            } finally {
                loadingMap.value[g.uuid] = false;
            }
        }

        // ── open cherry-pick panel ────────────────────────────────────────────
        async function openPick(g) {
            pickGalaxy.value = g;
            pickSearch.value = '';
            selected.value = [];
            clusters.value = [];
            pickLoading.value = true;
            try {
                const res = await fetch(`/tags/get_galaxy_clusters/${g.uuid}`);
                const data = await res.json();
                if (res.ok) clusters.value = data.clusters || [];
                else emit('notify', data.message || 'Failed to load clusters', 'danger-subtle');
            } finally {
                pickLoading.value = false;
            }
        }

        function closePick() {
            pickGalaxy.value = null;
            clusters.value = [];
            selected.value = [];
        }

        // ── cluster filtering ─────────────────────────────────────────────────
        const filteredClusters = computed(() => {
            if (!pickSearch.value) return clusters.value;
            const q = pickSearch.value.toLowerCase();
            return clusters.value.filter(c =>
                c.value.toLowerCase().includes(q) ||
                (c.description || '').toLowerCase().includes(q)
            );
        });

        // ── selection helpers ─────────────────────────────────────────────────
        function toggleCluster(uuid) {
            const i = selected.value.indexOf(uuid);
            if (i >= 0) selected.value.splice(i, 1);
            else selected.value.push(uuid);
        }
        function isSelected(uuid) { return selected.value.includes(uuid); }
        function selectAll() { selected.value = filteredClusters.value.filter(c => !c.already_imported).map(c => c.uuid); }
        function deselectAll() { selected.value = []; }

        const availableCount = computed(() => clusters.value.filter(c => !c.already_imported).length);
        const allSelected = computed(() =>
            availableCount.value > 0 &&
            filteredClusters.value.filter(c => !c.already_imported).every(c => isSelected(c.uuid))
        );

        // ── import selected clusters ──────────────────────────────────────────
        async function importSelected() {
            if (!selected.value.length) return;
            importing.value = true;
            try {
                const res = await fetch('/tags/add_tags_galaxy', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body: JSON.stringify({
                        uuid: pickGalaxy.value.uuid,
                        cluster_uuids: selected.value,
                    }),
                });
                const data = await res.json();
                emit('notify', data.message, res.ok ? 'success-subtle' : 'danger-subtle');
                if (res.ok) {
                    await load(page.value);
                    emit('refresh-main');
                    // refresh the cluster list to update already_imported flags
                    await openPick(pickGalaxy.value);
                }
            } finally {
                importing.value = false;
            }
        }

        function onSearchInput() { if (!searchQ.value.trim()) load(1); }

        onMounted(() => load(1));

        return {
            galaxies, total, totalPages, page, searchQ, pageLoading, loadingMap,
            load, importAll, onSearchInput,
            pickGalaxy, clusters, pickLoading, pickSearch, selected, importing,
            filteredClusters, availableCount, allSelected,
            openPick, closePick, toggleCluster, isSelected, selectAll, deselectAll, importSelected,
            mapIcon, truncateText,
        };
    },
    template: `
        <div>
            <!-- ── Galaxy list ─────────────────────────────────────────────── -->
            <div v-if="!pickGalaxy">
                <div class="d-flex gap-2 align-items-center mb-3">
                    <div class="input-group input-group-sm flex-grow-1">
                        <span class="input-group-text bg-transparent border-end-0">
                            <i class="fas fa-search text-muted"></i>
                        </span>
                        <input type="text" v-model="searchQ" class="form-control border-start-0"
                               placeholder="Search galaxies…"
                               @keyup.enter="load(1)" @input="onSearchInput">
                        <button class="btn btn-sm btn-primary" @click="load(1)">Search</button>
                    </div>
                    <span class="badge rounded-pill bg-light text-dark border px-3 py-2 text-nowrap">
                        <i class="fas fa-atom me-1" style="color:#9b7ede"></i>
                        <strong>{{ total }}</strong> galaxies
                    </span>
                </div>

                <div class="table-responsive">
                    <table class="table table-sm align-middle">
                        <thead>
                            <tr>
                                <th>Galaxy</th>
                                <th>Description</th>
                                <th>Clusters</th>
                                <th class="text-end">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-if="pageLoading">
                                <td colspan="4" class="text-center py-4">
                                    <div class="spinner-border spinner-border-sm" style="color:#9b7ede"></div>
                                </td>
                            </tr>
                            <template v-else>
                                <tr v-for="g in galaxies" :key="g.uuid">
                                    <td>
                                        <span class="tag-split shadow-sm">
                                            <span class="tag-left" v-html="mapIcon(g.icon)"></span>
                                            <span class="tag-right" style="background:#9b7ede; color:#fff">{{ g.name }}</span>
                                        </span>
                                    </td>
                                    <td class="text-muted small" style="max-width:280px">{{ truncateText(g.description, 80) }}</td>
                                    <td><span class="badge rounded-pill bg-secondary">{{ g.count }}</span></td>
                                    <td class="text-end">
                                        <div class="d-inline-flex gap-1">
                                            <!-- Cherry-pick -->
                                            <button
                                                class="btn btn-sm btn-outline-primary rounded-pill"
                                                @click="openPick(g)"
                                                title="Pick specific clusters"
                                            >
                                                <i class="fas fa-hand-pointer me-1"></i>Pick
                                            </button>
                                            <!-- Import all -->
                                            <button
                                                class="btn btn-sm rounded-pill"
                                                style="background:#9b7ede; color:#fff; border-color:#9b7ede"
                                                :disabled="loadingMap[g.uuid]"
                                                @click="importAll(g)"
                                                title="Import all clusters"
                                            >
                                                <span v-if="loadingMap[g.uuid]" class="spinner-border spinner-border-sm me-1"></span>
                                                <i v-else class="fas fa-download me-1"></i>All
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <tr v-if="!galaxies.length && !pageLoading">
                                    <td colspan="4" class="text-center text-muted py-4">
                                        <i class="fas fa-atom fa-2x d-block mb-2 opacity-25"></i>
                                        No galaxies available
                                    </td>
                                </tr>
                            </template>
                        </tbody>
                    </table>
                </div>
                <browser-pagination :current="page" :total="totalPages" @change="load"></browser-pagination>
            </div>

            <!-- ── Cherry-pick panel ───────────────────────────────────────── -->
            <div v-else>

                <!-- Panel header -->
                <div class="d-flex align-items-center gap-3 mb-3 pb-3 border-bottom">
                    <button class="btn btn-sm btn-outline-secondary rounded-pill" @click="closePick">
                        <i class="fas fa-arrow-left me-1"></i>Back
                    </button>
                    <div>
                        <h6 class="fw-bold mb-0" style="color: var(--text-color)">
                            <span class="tag-split shadow-sm me-2">
                                <span class="tag-left" v-html="mapIcon(pickGalaxy.icon)"></span>
                                <span class="tag-right" style="background:#9b7ede; color:#fff">{{ pickGalaxy.name }}</span>
                            </span>
                            Pick clusters to import
                        </h6>
                        <small class="text-muted">
                            {{ clusters.length }} total ·
                            {{ availableCount }} available ·
                            {{ clusters.length - availableCount }} already imported
                        </small>
                    </div>
                </div>

                <!-- Loading -->
                <div v-if="pickLoading" class="text-center py-5">
                    <div class="spinner-border text-primary mb-2"></div>
                    <p class="text-muted small">Loading clusters…</p>
                </div>

                <template v-else>
                    <!-- Toolbar -->
                    <div class="d-flex gap-2 align-items-center mb-2 flex-wrap">
                        <div class="input-group input-group-sm" style="max-width:320px">
                            <span class="input-group-text bg-transparent border-end-0">
                                <i class="fas fa-search text-muted"></i>
                            </span>
                            <input type="text" v-model="pickSearch" class="form-control border-start-0" placeholder="Filter clusters…">
                        </div>

                        <label class="d-flex align-items-center gap-2 small ms-1" style="cursor:pointer">
                            <input type="checkbox" class="form-check-input m-0"
                                :checked="allSelected"
                                @change="allSelected ? deselectAll() : selectAll()">
                            <span style="color: var(--text-color)">Select all visible</span>
                        </label>

                        <span class="text-muted small ms-auto">
                            {{ selected.length }} selected
                        </span>

                        <button
                            class="btn btn-sm btn-primary rounded-pill px-3"
                            :disabled="!selected.length || importing"
                            @click="importSelected"
                        >
                            <span v-if="importing" class="spinner-border spinner-border-sm me-1"></span>
                            <i v-else class="fas fa-download me-1"></i>
                            Import {{ selected.length || '' }} selected
                        </button>
                    </div>

                    <!-- Cluster list -->
                    <div style="max-height:480px; overflow-y:auto" class="border rounded-3">
                        <div v-if="filteredClusters.length === 0" class="text-center text-muted py-5 small">
                            <i class="fas fa-search fa-2x d-block mb-2 opacity-25"></i>No clusters match.
                        </div>
                        <table v-else class="table table-sm align-middle mb-0">
                            <thead class="sticky-top" style="background: var(--card-bg-color)">
                                <tr>
                                    <th style="width:36px"></th>
                                    <th>Cluster</th>
                                    <th>Description</th>
                                    <th style="width:100px">Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="c in filteredClusters" :key="c.uuid"
                                    :class="{
                                        'opacity-50': c.already_imported,
                                        'table-active': isSelected(c.uuid)
                                    }"
                                    style="cursor:pointer"
                                    @click="!c.already_imported && toggleCluster(c.uuid)"
                                >
                                    <td>
                                        <input type="checkbox" class="form-check-input m-0"
                                            :checked="isSelected(c.uuid)"
                                            :disabled="c.already_imported"
                                            @change="toggleCluster(c.uuid)"
                                            @click.stop>
                                    </td>
                                    <td class="fw-semibold small">{{ c.value }}</td>
                                    <td class="text-muted small">{{ truncateText(c.description, 90) }}</td>
                                    <td>
                                        <span v-if="c.already_imported"
                                              class="badge rounded-pill bg-success-subtle text-success">
                                            <i class="fas fa-check me-1"></i>Imported
                                        </span>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </template>
            </div>
        </div>
    `
};

export default GalaxyBrowser;