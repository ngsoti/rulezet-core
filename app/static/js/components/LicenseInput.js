/**
 * LicenseInput — searchable single-select license picker.
 *
 * Props:
 *   modelValue  (String)  — the selected SPDX license identifier, '' if none
 *   label       (String)  — field label (default 'License')
 *   placeholder (String)  — input placeholder
 *
 * Emits: update:modelValue (String)
 *
 * Options come from GET /rule/get_license (reads licenses.txt server-side).
 * Cached at module scope so mounting this component more than once on the
 * same page (Manual / GitHub / ZIP tabs on the rule-create page) only
 * fetches the list once.
 *
 * Usage (Vue template):
 *   <license-input v-model="manualLicense" />
 */

const { defineComponent, ref, computed, onMounted } = Vue;

let _licenseCache = null;
let _licenseFetchPromise = null;

function fetchLicenses() {
    if (_licenseCache) return Promise.resolve(_licenseCache);
    if (_licenseFetchPromise) return _licenseFetchPromise;
    _licenseFetchPromise = fetch('/rule/get_license')
        .then(r => r.ok ? r.json() : { licenses: [] })
        .then(data => {
            _licenseCache = Array.isArray(data.licenses) ? data.licenses : [];
            return _licenseCache;
        })
        .catch(() => {
            _licenseCache = [];
            return _licenseCache;
        });
    return _licenseFetchPromise;
}

const LicenseInput = defineComponent({
    name: 'LicenseInput',
    delimiters: ['[[', ']]'],
    props: {
        modelValue:  { type: String, default: '' },
        label:       { type: String, default: 'License' },
        placeholder: { type: String, default: 'Search a license (e.g. MIT, GPL-3.0)…' },
        required:    { type: Boolean, default: false },
    },
    emits: ['update:modelValue'],

    setup(props, { emit }) {
        const rootEl        = ref(null);
        const licenses       = ref([]);
        const isLoading      = ref(false);
        const isDropdownOpen = ref(false);
        const searchQuery    = ref('');

        const filtered = computed(() => {
            const q = searchQuery.value.trim().toLowerCase();
            if (!q) return licenses.value;
            return licenses.value.filter(l => l.toLowerCase().includes(q));
        });

        function open() {
            isDropdownOpen.value = true;
            if (!licenses.value.length && !isLoading.value) {
                isLoading.value = true;
                fetchLicenses().then(list => { licenses.value = list; isLoading.value = false; });
            }
        }
        function close() { isDropdownOpen.value = false; }

        function select(license) {
            emit('update:modelValue', license);
            searchQuery.value = '';
            close();
        }

        function clear() {
            emit('update:modelValue', '');
            searchQuery.value = '';
        }

        onMounted(() => {
            document.addEventListener('mousedown', (e) => {
                if (rootEl.value && !rootEl.value.contains(e.target)) close();
            });
        });

        return {
            rootEl, licenses, isLoading, isDropdownOpen, searchQuery,
            filtered, open, close, select, clear,
        };
    },

    template: `
<div class="license-input" ref="rootEl">
    <div class="d-flex align-items-center gap-1 mb-1">
        <label class="form-label-styled mb-0">[[ label ]]</label>
        <span v-if="required" class="req-badge">required</span>
        <span v-else class="opt-badge">optional</span>
    </div>

    <div v-if="modelValue && !isDropdownOpen" class="license-input__selected" @click="open">
        <i class="fas fa-scale-balanced"></i>
        <span>[[ modelValue ]]</span>
        <button type="button" class="license-input__clear" @click.stop="clear" aria-label="Clear license">
            <i class="fas fa-xmark"></i>
        </button>
    </div>

    <div v-else class="input-group shadow-sm rounded-3 border license-input__group">
        <span class="input-group-text border-0 license-input__icon">
            <i class="fas fa-search small"></i>
        </span>
        <input type="text" v-model="searchQuery" @focus="open"
               class="form-control border-0 shadow-none px-2 license-input__field"
               :placeholder="placeholder">
        <div v-if="isLoading" class="input-group-text border-0 license-input__icon">
            <div class="spinner-border spinner-border-sm text-primary"></div>
        </div>
    </div>

    <div v-if="isDropdownOpen" @click.stop class="license-input__dropdown shadow-lg">
        <div v-for="item in filtered" :key="item" class="license-input__option"
             :class="{ 'license-input__option--active': item === modelValue }"
             @click.stop="select(item)">
            <i class="fas fa-scale-balanced"></i>
            <span>[[ item ]]</span>
            <i v-if="item === modelValue" class="fas fa-check-circle ms-auto text-primary"></i>
        </div>
        <div v-if="!isLoading && filtered.length === 0" class="license-input__empty">
            No license matches “[[ searchQuery ]]”.
        </div>
    </div>
</div>
`,
});

export default LicenseInput;
