/**
 * multiAttackFilter.js — Multi-select ATT&CK technique filter
 * Same UX pattern as multiTagFilter: trigger pill → dropdown → tactic folders → techniques
 */

const TACTIC_COLORS = {
    'reconnaissance':       '#1d4ed8',
    'resource-development': '#6d28d9',
    'initial-access':       '#be185d',
    'execution':            '#92400e',
    'persistence':          '#065f46',
    'privilege-escalation': '#9a3412',
    'defense-evasion':      '#374151',
    'credential-access':    '#991b1b',
    'discovery':            '#0c4a6e',
    'lateral-movement':     '#86198f',
    'collection':           '#064e3b',
    'command-and-control':  '#881337',
    'exfiltration':         '#7c2d12',
    'impact':               '#7f1d1d',
};

const TACTIC_BG = {
    'reconnaissance':       '#e7f0ff',
    'resource-development': '#ede9fe',
    'initial-access':       '#fce7f3',
    'execution':            '#fef3c7',
    'persistence':          '#d1fae5',
    'privilege-escalation': '#ffedd5',
    'defense-evasion':      '#f3f4f6',
    'credential-access':    '#fee2e2',
    'discovery':            '#e0f2fe',
    'lateral-movement':     '#fdf4ff',
    'collection':           '#ecfdf5',
    'command-and-control':  '#fff1f2',
    'exfiltration':         '#fff7ed',
    'impact':               '#fef2f2',
};

const TACTIC_ORDER = [
    'reconnaissance','resource-development','initial-access','execution','persistence',
    'privilege-escalation','defense-evasion','credential-access','discovery',
    'lateral-movement','collection','command-and-control','exfiltration','impact',
];

function tacticLabel(key) {
    return (key || '').replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

const MultiAttackFilter = {
    name: 'MultiAttackFilter',
    props: {
        modelValue:  { type: Array,  default: () => [] },
        placeholder: { type: String, default: 'Filter by ATT&CK technique…' },
        apiEndpoint: { type: String, default: '/attack/techniques/usage' },
        // Query string of every OTHER currently active RuleList filter — keeps
        // these counts scoped to what's actually visible.
        filterContext: { type: String, default: '' },
    },
    emits: ['update:modelValue', 'change'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const { ref, computed, watch, onMounted } = Vue;

        const allTechniques   = ref([]);
        const search          = ref('');
        const loading         = ref(false);
        const selected        = ref([...props.modelValue]);
        const activeTactic    = ref(null);   // null = show tactic folder list
        const tacticMap       = ref({});     // tactic key → [{id, name, count}]

        watch(() => props.modelValue, v => { selected.value = [...v]; }, { deep: true });

        async function fetchTechniques() {
            loading.value = true;
            try {
                const url = props.filterContext ? `${props.apiEndpoint}?${props.filterContext}` : props.apiEndpoint;
                const res  = await fetch(url);
                const data = await res.json();
                allTechniques.value = data.techniques || [];

                // Build tactic map in TACTIC_ORDER
                const map = {};
                allTechniques.value.forEach(t => {
                    const keys = t.tactic_keys && t.tactic_keys.length ? t.tactic_keys : ['unknown'];
                    keys.forEach(k => {
                        if (!map[k]) map[k] = [];
                        map[k].push(t);
                    });
                });
                tacticMap.value = map;
            } catch { allTechniques.value = []; }
            finally  { loading.value = false; }
        }
        onMounted(fetchTechniques);
        watch(() => props.filterContext, fetchTechniques);

        // Ordered tactic list for folder view
        const tacticList = computed(() => {
            const out = [];
            TACTIC_ORDER.forEach(k => {
                if (tacticMap.value[k]) out.push({ key: k, label: tacticLabel(k), techniques: tacticMap.value[k] });
            });
            if (tacticMap.value['unknown']) out.push({ key: 'unknown', label: 'Unknown', techniques: tacticMap.value['unknown'] });
            return out;
        });

        // Flat search results
        const searchResults = computed(() => {
            const q = search.value.toLowerCase().trim();
            if (!q) return null;
            return allTechniques.value.filter(t =>
                t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
            );
        });

        // Selected technique objects (for chips in pill)
        const selectedObjects = computed(() =>
            allTechniques.value.filter(t => selected.value.includes(t.id))
        );

        function toggle(id) {
            const i = selected.value.indexOf(id);
            if (i > -1) selected.value.splice(i, 1);
            else         selected.value.push(id);
            emit('update:modelValue', [...selected.value]);
            emit('change', [...selected.value]);
        }

        function clearAll() {
            selected.value = [];
            emit('update:modelValue', []);
            emit('change', []);
        }

        function isSelected(id) { return selected.value.includes(id); }

        // Color helpers
        function chipBg(tacticKeys)     { return TACTIC_BG[(tacticKeys || [])[0]] || '#f3f4f6'; }
        function chipColor(tacticKeys)  { return TACTIC_COLORS[(tacticKeys || [])[0]] || '#374151'; }
        function tacticColor(key)       { return TACTIC_COLORS[key] || '#6c757d'; }
        function tacticBg(key)          { return TACTIC_BG[key] || '#f3f4f6'; }

        return {
            allTechniques, search, loading, selected, activeTactic, tacticMap,
            tacticList, searchResults, selectedObjects,
            toggle, clearAll, isSelected,
            chipBg, chipColor, tacticColor, tacticBg, tacticLabel,
        };
    },
    template: `
<div class="dropdown multi-tag-filter w-100">

    <!-- ── Trigger pill ─────────────────────────────────────────────── -->
    <div class="form-control d-flex flex-wrap gap-2 align-items-center p-2 shadow-sm border-secondary-subtle"
         data-bs-toggle="dropdown" data-bs-auto-close="outside"
         style="cursor:pointer; min-height:48px; border-radius:12px;">
        <i class="fa-solid fa-crosshairs opacity-75 ms-1 me-1" style="color:#e67e22;"></i>
        <span v-if="selectedObjects.length === 0" class="text-muted small fw-bold">[[ placeholder ]]</span>
        <span v-for="t in selectedObjects" :key="t.id"
              class="badge rounded-pill d-inline-flex align-items-center gap-1"
              :style="{ background: chipBg(t.tactic_keys), color: chipColor(t.tactic_keys), border: '1px solid ' + chipColor(t.tactic_keys) + '44', fontSize: '.72rem', padding: '.22rem .55rem' }">
            <span style="font-family:monospace; font-weight:700;">[[ t.id ]]</span>
            <span class="opacity-60">·</span>
            <span style="max-width:100px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">[[ t.name ]]</span>
            <i class="fa-solid fa-circle-xmark ms-1 opacity-75" @click.stop="toggle(t.id)" style="cursor:pointer;"></i>
        </span>
        <i class="fa-solid fa-chevron-down ms-auto me-1 text-muted small"></i>
    </div>

    <!-- ── Dropdown panel ───────────────────────────────────────────── -->
    <div class="dropdown-menu shadow-lg border-0 w-100 p-3 mt-2"
         style="max-height:600px; border-radius:15px; z-index:1060; min-width:380px;">

        <!-- Search -->
        <div class="d-flex align-items-center mb-2">
            <button v-if="activeTactic !== null && !search"
                    @click="activeTactic = null"
                    class="btn btn-sm btn-outline-primary border-0 me-2 rounded-circle d-flex align-items-center justify-content-center"
                    style="width:30px; height:30px; flex-shrink:0;">
                <i class="fa-solid fa-arrow-left"></i>
            </button>
            <div class="input-group input-group-sm">
                <span class="input-group-text bg-light border-0"><i class="fa-solid fa-magnifying-glass"></i></span>
                <input type="text" v-model="search"
                       class="form-control bg-light border-0 shadow-none"
                       placeholder="Search by ID or name…">
            </div>
        </div>

        <!-- Loading -->
        <div v-if="loading" class="text-center py-3 text-muted small">
            <div class="spinner-border spinner-border-sm me-2"></div>Loading…
        </div>

        <!-- Empty DB -->
        <div v-else-if="!allTechniques.length" class="text-center py-4">
            <i class="fa-solid fa-crosshairs fa-3x text-muted opacity-25 mb-2 d-block"></i>
            <h6 class="text-muted fw-bold">No ATT&amp;CK data</h6>
            <small class="text-muted">Run the update job in Admin → Settings → ATT&amp;CK.</small>
        </div>

        <div v-else class="pe-1" style="max-height:420px; overflow-y:auto; overflow-x:hidden;">

            <!-- ① Search results (flat list) -->
            <div v-if="search" class="d-flex flex-column gap-1">
                <div v-if="!searchResults || searchResults.length === 0" class="text-center py-4">
                    <i class="fa-solid fa-magnifying-glass fa-2x text-muted opacity-25 mb-2 d-block"></i>
                    <span class="text-muted small">No match for "[[ search ]]"</span>
                </div>
                <div v-for="t in searchResults" :key="t.id"
                     @click="toggle(t.id)"
                     class="p-2 rounded border d-flex align-items-center justify-content-between"
                     :class="{ 'border-primary bg-primary-subtle': isSelected(t.id) }"
                     style="cursor:pointer;">
                    <div class="d-flex align-items-center gap-2">
                        <span class="badge rounded-pill"
                              :style="{ background: chipBg(t.tactic_keys), color: chipColor(t.tactic_keys), fontFamily: 'monospace', fontSize: '.72rem', border: '1px solid ' + chipColor(t.tactic_keys) + '44' }">
                            [[ t.id ]]
                        </span>
                        <span class="small fw-bold text-truncate" style="max-width:200px; color:var(--text-color);">[[ t.name ]]</span>
                    </div>
                    <div class="d-flex align-items-center gap-2">
                        <span class="badge rounded-pill border" style="font-size:.65rem; background:var(--light-bg-color); color:var(--text-color);">[[ t.count ]]</span>
                        <i v-if="isSelected(t.id)" class="fa-solid fa-check-circle text-primary"></i>
                    </div>
                </div>
            </div>

            <!-- ② Tactic folder list -->
            <div v-else-if="activeTactic === null" class="d-flex flex-column gap-2">
                <div v-for="tac in tacticList" :key="tac.key"
                     @click="activeTactic = tac.key"
                     class="p-2 px-3 rounded-3 border d-flex align-items-center justify-content-between"
                     style="cursor:pointer; min-height:50px;">
                    <div class="d-flex align-items-center gap-2">
                        <span class="d-inline-flex align-items-center justify-content-center rounded-circle"
                              :style="{ background: tacticBg(tac.key), width: '28px', height: '28px', flexShrink: 0 }">
                            <i class="fa-solid fa-crosshairs" :style="{ color: tacticColor(tac.key), fontSize: '.65rem' }"></i>
                        </span>
                        <span class="fw-bold" style="color:var(--text-color); font-size:.85rem;">[[ tac.label ]]</span>
                    </div>
                    <div class="d-flex align-items-center gap-3">
                        <span class="small fw-bold text-nowrap" style="color:var(--subtle-text-color);">[[ tac.techniques.length ]] techniques</span>
                        <i class="fa-solid fa-chevron-right opacity-50 small"></i>
                    </div>
                </div>
            </div>

            <!-- ③ Techniques inside a tactic -->
            <div v-else>
                <div class="px-2 mb-2 d-flex justify-content-between align-items-center">
                    <small class="fw-bold text-uppercase" :style="{ color: tacticColor(activeTactic) }">[[ tacticLabel(activeTactic) ]]</small>
                    <small style="color:var(--subtle-text-color);">[[ (tacticMap[activeTactic] || []).length ]] techniques</small>
                </div>
                <div class="d-flex flex-column gap-1">
                    <div v-for="t in (tacticMap[activeTactic] || [])" :key="t.id"
                         @click="toggle(t.id)"
                         class="p-2 rounded-3 border d-flex align-items-center justify-content-between"
                         :class="{ 'border-primary bg-primary-subtle': isSelected(t.id) }"
                         style="cursor:pointer;">
                        <div class="d-flex align-items-center gap-2">
                            <i class="fa-solid" :class="isSelected(t.id) ? 'fa-square-check text-primary' : 'fa-square'"
                               style="font-size:.75rem; flex-shrink:0;"></i>
                            <span class="badge rounded-pill"
                                  :style="{ background: tacticBg(activeTactic), color: tacticColor(activeTactic), fontFamily: 'monospace', fontSize: '.72rem', border: '1px solid ' + tacticColor(activeTactic) + '44', flexShrink: 0 }">
                                [[ t.id ]]
                            </span>
                            <span class="small fw-bold text-truncate" style="max-width:190px; color:var(--text-color);">[[ t.name ]]</span>
                        </div>
                        <div class="d-flex align-items-center gap-2">
                            <span class="badge rounded-pill border" style="font-size:.65rem; background:var(--light-bg-color); color:var(--text-color);">[[ t.count ]]</span>
                            <i v-if="isSelected(t.id)" class="fa-solid fa-check-circle text-primary"></i>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </div>
</div>
`,
};

export default MultiAttackFilter;
