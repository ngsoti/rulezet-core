const MultiLicenseFilter = {
    props: {
        modelValue: { type: Array, default: () => [] },
        placeholder: { type: String, default: 'Filter by licenses...' },
        apiEndpoint: { type: String, default: '/rule/get_rules_licenses_usage' },
        userId: { type: Number, default: null },
        // Added sourceRules prop to allow scoping by source
        sourceRules: { type: String, default: '' }
    },
    emits: ['update:modelValue', 'change'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const list_licenses = Vue.ref([]);
        const searchCtx = Vue.ref('');
        const selectedNames = Vue.ref([...props.modelValue]);
        const activePrefix = Vue.ref(null);

        Vue.watch(() => props.modelValue, (newVal) => {
            selectedNames.value = [...newVal];
        }, { deep: true });

        const fetchLicenses = async () => {
            try {
                let url = props.apiEndpoint;
                const params = new URLSearchParams();
                
                if (props.userId !== null && !isNaN(props.userId)) {
                    params.append('user_id', props.userId.toString());
                }

                // If a source scope is provided, add it to the request
                if (props.sourceRules) {
                    params.append('sources', props.sourceRules);
                }

                if (params.toString()) {
                    url += (url.includes('?') ? '&' : '?') + params.toString();
                }

                const response = await fetch(url);
                if (response.ok) {
                    const data = await response.json();
                    list_licenses.value = Array.isArray(data) ? data : (data.licenses || []);
                }
            } catch (e) {
                console.error("Error loading filter licenses", e);
            }
        };

        // Refresh the list whenever the source scope changes
        Vue.watch(() => props.sourceRules, () => {
            fetchLicenses();
        });

        const groupedLicenses = Vue.computed(() => {
            const groups = {};
            list_licenses.value.forEach(l => {
                const name = l.name.toUpperCase();
                let prefix = 'OTHER';
                if (name.includes('MIT')) prefix = 'MIT';
                else if (name.includes('APACHE')) prefix = 'APACHE';
                else if (name.includes('GPL')) prefix = 'GPL';
                else if (name.includes('BSD')) prefix = 'BSD';
                
                if (!groups[prefix]) groups[prefix] = [];
                groups[prefix].push(l);
            });
            return groups;
        });

        const filteredList = Vue.computed(() => {
            if (!searchCtx.value) return null;
            const q = searchCtx.value.toLowerCase();
            return list_licenses.value.filter(l => l.name.toLowerCase().includes(q));
        });

        const toggleLicense = (name) => {
            const index = selectedNames.value.indexOf(name);
            if (index > -1) {
                selectedNames.value.splice(index, 1);
            } else {
                selectedNames.value.push(name);
            }
            emit('update:modelValue', [...selectedNames.value]);
            emit('change', [...selectedNames.value]);
        };

        const getLicenseColor = (name) => {
            const n = name.toUpperCase();
            if (n.includes("MIT")) return "bg-success text-white";
            if (n.includes("APACHE")) return "bg-info text-white";
            if (n.includes("GPL")) return "bg-danger text-white";
            return "bg-secondary text-white";
        };

        const getLicenseIcon = (name) => {
            return "fas fa-scale-balanced";
        };

        Vue.onMounted(fetchLicenses);

        return {
            searchCtx, groupedLicenses, selectedNames, activePrefix,
            toggleLicense, filteredList, getLicenseColor, getLicenseIcon,
            clearAll: () => { 
                selectedNames.value = []; 
                emit('update:modelValue', []); 
                emit('change', []);
            }
        };
    },
    template: `
    <div class="dropdown multi-license-filter w-100">
        <div class="form-control d-flex flex-wrap gap-2 align-items-center p-2 shadow-sm border-secondary-subtle" 
             data-bs-toggle="dropdown" data-bs-auto-close="outside" 
             style="cursor: pointer; min-height: 48px; border-radius: 12px;">
            
            <i class="fa-solid fa-scale-balanced text-info opacity-75 ms-1 me-1"></i>
            <span v-if="selectedNames.length === 0" class="text-muted small fw-bold">[[ placeholder ]]</span>

            <span v-for="name in selectedNames" :key="name" 
                  class="d-flex align-items-center rounded-2 shadow-sm animate__animated animate__fadeInSmall" 
                  :class="getLicenseColor(name)" style="font-size: 0.75rem; overflow: hidden;">
                <div class="px-2 py-1 bg-black bg-opacity-10 border-end border-white border-opacity-10">
                    <i :class="getLicenseIcon(name)"></i>
                </div>
                <div class="px-2 py-1 d-flex align-items-center">
                    <span class="fw-bold me-2">[[ name ]]</span>
                    <i class="fa-solid fa-circle-xmark opacity-75 ms-1 hover-scale" @click.stop="toggleLicense(name)" style="cursor: pointer;"></i>
                </div>
            </span>
            <i class="fa-solid fa-chevron-down ms-auto me-1 text-muted small"></i>
        </div>

        <div class="dropdown-menu shadow-lg border-0 w-100 p-3 mt-2 animate__animated animate__fadeIn" 
             style="max-height: 550px; border-radius: 15px; z-index: 1060; min-width: 350px;">
            
            <div class="d-flex align-items-center mb-3">
                <button v-if="activePrefix && !searchCtx" @click="activePrefix = null" 
                        class="btn btn-sm btn-outline-primary border-0 me-2 rounded-circle d-flex align-items-center justify-content-center"
                        style="width: 30px; height: 30px;">
                    <i class="fa-solid fa-arrow-left"></i>
                </button>
                <div class="input-group input-group-sm">
                    <span class="input-group-text bg-light border-0"><i class="fa-solid fa-magnifying-glass"></i></span>
                    <input type="text" v-model="searchCtx" class="form-control bg-light border-0 shadow-none" placeholder="Search license...">
                </div>
            </div>

            <div class="custom-tag-scroll pe-2" style="max-height: 400px; overflow-y: auto;">
                <div v-if="searchCtx" class="d-flex flex-column gap-1">
                    <div v-for="l in filteredList" :key="l.name" 
                         @click="toggleLicense(l.name)" 
                         class="p-2 rounded border d-flex align-items-center justify-content-between tag-item-hover"
                         :class="{'border-primary bg-primary-subtle shadow-sm': selectedNames.includes(l.name)}"
                         style="cursor:pointer;">
                         <div class="d-flex align-items-center">
                            <i :class="[getLicenseIcon(l.name), 'me-2']" style="color: var(--text-color)"></i>
                            <span class="small fw-bold" style="color: var(--text-color)">[[ l.name ]]</span>
                         </div>
                         <span class="badge rounded-pill bg-light border " style="font-size: 0.65rem; color: var(--text-color);">[[ l.count || l.usage_count ]]</span>
                    </div>
                </div>

                <div v-else-if="!activePrefix" class="d-flex flex-column gap-2">
                    <div v-for="(items, prefix) in groupedLicenses" :key="prefix" 
                         @click="activePrefix = prefix"
                         class="p-2 px-3 rounded-3 border d-flex align-items-center justify-content-between tag-item-hover shadow-xs" 
                         style="cursor: pointer; min-height: 50px;">
                        <div class="d-flex align-items-center">
                            <div class="bg-info bg-opacity-10 p-2 rounded-circle me-3">
                                <i class="fa-solid fa-file-contract text-info"></i>
                            </div>
                            <span class="fw-bold" style="color: var(--text-color)">[[ prefix ]]</span>
                        </div>
                        <div class="d-flex align-items-center gap-3 text-muted">
                            <span class="extra-small fw-bold" style="color: var(--text-color)">[[ items.length ]] licenses</span>
                            <i class="fa-solid fa-chevron-right opacity-50 small" style="color: var(--text-color);"></i>
                        </div>
                    </div>
                </div>

                <div v-else class="animate__animated animate__fadeInUpSmall">
                    <div class="px-2 mb-2 d-flex justify-content-between align-items-center border-bottom pb-2">
                        <small class="fw-black text-info text-uppercase">[[ activePrefix ]] Family</small>
                        <small class="small" style="color: var(--text-color)">[[ groupedLicenses[activePrefix].length ]] items</small>
                    </div>
                    
                    <div class="d-flex flex-column gap-2 mt-2">
                        <div v-for="l in groupedLicenses[activePrefix]" :key="l.name" 
                             @click="toggleLicense(l.name)" 
                             class="p-2 rounded-3 border d-flex align-items-center justify-content-between tag-item-hover"
                             :class="selectedNames.includes(l.name) ? 'border-primary bg-primary-subtle' : ''"
                             style="cursor:pointer;">
                            <div class="d-flex align-items-center">
                                <div class="d-flex align-items-center rounded-2 overflow-hidden" :class="getLicenseColor(l.name)" style="font-size: 0.75rem;">
                                    <div class="px-2 py-1 bg-black bg-opacity-10 border-end border-white border-opacity-10">
                                        <i :class="getLicenseIcon(l.name)"></i>
                                    </div>
                                    <div class="px-2 py-1 fw-bold">[[ l.name ]]</div>
                                </div>
                            </div>
                            <div class="d-flex align-items-center gap-2">
                                <span class="badge rounded-pill border" style="font-size: 0.65rem; color: var(--text-color);">[[ l.count || l.usage_count ]]</span>
                                <i v-if="selectedNames.includes(l.name)" class="fa-solid fa-check-circle text-primary"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    `
};

export default MultiLicenseFilter;