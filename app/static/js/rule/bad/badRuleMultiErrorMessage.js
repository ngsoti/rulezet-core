const BadRuleMultiErrorMessage = {
    props: {
        modelValue: { type: Array, default: () => [] },
        placeholder: { type: String, default: 'Filter by error messages...' },
        apiEndpoint: { type: String, default: '/rule/get_bad_rules_error_messages_usage' },
        userId: { type: Number, default: null },
    },
    emits: ['update:modelValue', 'change'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const list_errors = Vue.ref([]);
        const searchCtx = Vue.ref('');
        const selectedNames = Vue.ref([...props.modelValue]);
        const isLoading = Vue.ref(false);

        Vue.watch(() => props.modelValue, (newVal) => {
            selectedNames.value = [...newVal];
        }, { deep: true });

        const fetchErrors = async () => {
            isLoading.value = true;
            try {
                let url = props.apiEndpoint;
                if (props.userId !== null && !isNaN(props.userId)) {
                    const params = new URLSearchParams();
                    params.append('user_id', props.userId.toString());
                    url += `?${params.toString()}`;
                }

                const response = await fetch(url);
                if (response.ok) {
                    const data = await response.json();
                    list_errors.value = Array.isArray(data) ? data : (data.errors || []);
                }
            } finally {
                isLoading.value = false;
            }
        };

        const filteredList = Vue.computed(() => {
            if (!searchCtx.value) return list_errors.value;
            const q = searchCtx.value.toLowerCase();
            return list_errors.value.filter(e => e.name.toLowerCase().includes(q));
        });

        const toggleError = (name) => {
            const index = selectedNames.value.indexOf(name);
            if (index > -1) {
                selectedNames.value.splice(index, 1);
            } else {
                selectedNames.value.push(name);
            }
            emit('update:modelValue', [...selectedNames.value]);
            emit('change', [...selectedNames.value]);
        };

        const truncateError = (text, length = 60) => {
            return text.length > length ? text.substring(0, length) + '...' : text;
        };

        Vue.onMounted(fetchErrors);

        return {
            searchCtx,
            selectedNames,
            list_errors,
            toggleError,
            filteredList,
            isLoading,
            truncateError,
            clearAll: () => {
                selectedNames.value = [];
                emit('update:modelValue', []);
                emit('change', []);
            }
        };
    },
    template: `
    <div class="dropdown multi-error-filter w-100">
        <div class="form-control d-flex flex-wrap gap-2 align-items-center p-2 shadow-sm "
             data-bs-toggle="dropdown" data-bs-auto-close="outside"
             style="cursor: pointer; min-height: 48px; border-radius: 12px;">

            <i class="fa-solid fa-bug text-danger opacity-75 ms-1 me-1"></i>
            <span v-if="selectedNames.length === 0" class="text-muted small fw-bold">[[ placeholder ]]</span>

            <span v-for="name in selectedNames" :key="name"
                  class="d-flex align-items-center rounded-2 shadow-sm bg-danger-subtle border border-danger"
                  style="font-size: 0.75rem; overflow: hidden;">
                <div class="px-2 py-1 d-flex align-items-center">
                    <span class="fw-bold me-2">[[ truncateError(name, 30) ]]</span>
                    <i class="fa-solid fa-circle-xmark opacity-75 ms-1 hover-scale" @click.stop="toggleError(name)" style="cursor: pointer;"></i>
                </div>
            </span>
            <i class="fa-solid fa-chevron-down ms-auto me-1 text-muted small"></i>
        </div>

        <div class="dropdown-menu shadow-lg border-0 w-100 p-3 mt-2 animate__animated animate__fadeIn"
             style="max-height: 550px; border-radius: 15px; z-index: 1060; min-width: 350px;">

            <div class="input-group input-group-sm mb-3">
                <span class="input-group-text bg-light border-0"><i class="fa-solid fa-magnifying-glass"></i></span>
                <input type="text" v-model="searchCtx" class="form-control bg-light border-0 shadow-none" placeholder="Search error...">
            </div>

            <div class="custom-tag-scroll pe-2" style="max-height: 400px; overflow-y: auto;">

                <div v-if="(!isLoading && list_errors.length === 0) || (searchCtx && filteredList.length === 0)"
                     class="text-center py-4 animate__animated animate__fadeIn" style="color: var(--text-color)">
                    <div class="mb-2">
                        <i class="fa-solid fa-magnifying-glass-chart fa-3x text-muted opacity-25"></i>
                    </div>
                    <h6 class="text-muted fw-bold">No errors found</h6>
                </div>

                <div v-else class="d-flex flex-column gap-2">
                    <div v-for="error in filteredList" :key="error.name"
                         @click="toggleError(error.name)"
                         class="p-2 rounded border d-flex align-items-center justify-content-between tag-item-hover"
                         :class="{'border-danger bg-danger-subtle': selectedNames.includes(error.name)}"
                         style="cursor:pointer;">
                        <div class="d-flex align-items-center flex-grow-1">
                            <i class="fa-solid fa-bug me-2 text-danger" style="font-size: 0.85rem;"></i>
                            <span class="small fw-bold" style="color: var(--text-color);">[[ truncateError(error.name) ]]</span>
                        </div>
                        <span class="badge rounded-pill bg-light border" style="font-size: 0.65rem; color: var(--text-color);">[[ error.count ]]</span>
                    </div>
                </div>
            </div>
        </div>
    </div>
    `
};

export default BadRuleMultiErrorMessage;