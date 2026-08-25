const TagFilterBar = {
    props: {
        modelValue: { type: Object, required: true },
        total: { type: Number, default: 0 },
        selectedCount: { type: Number, default: 0 },
    },
    emits: [
        'update:modelValue',
        'search',
        'export-selected', 'export-all',
        'delete-selected',
        'clear-selection',
        'select-all-visible',
        'set-public-selected', 'set-private-selected',
        'activate-selected', 'deactivate-selected',
    ],
    setup(props, { emit }) {
        const { ref, computed } = Vue;
        const showAdvanced = ref(false);

        const sourceOptions = [
            { value: 'all', label: 'All', icon: 'fa-layer-group', color: '#6c757d' },
            { value: 'Taxonomy', label: 'Taxonomy', icon: 'fa-list', color: '#0d6efd' },
            { value: 'Galaxy', label: 'Galaxy', icon: 'fa-atom', color: '#9b7ede' },
            { value: 'Manual', label: 'Manual', icon: 'fa-tag', color: '#198754' },
        ];

        const activeChips = computed(() => {
            const chips = [];
            const v = props.modelValue;
            if (v.visibility !== 'all') chips.push({ key: 'visibility', label: v.visibility === 'public' ? 'Public' : 'Private' });
            if (v.is_active !== 'all') chips.push({ key: 'is_active', label: v.is_active === 'active' ? 'Active only' : 'Inactive only' });
            if (v.sort_order !== 'desc') chips.push({ key: 'sort_order', label: 'Oldest first' });
            if (v.show_namespace === false) chips.push({ key: 'show_namespace', label: 'No namespace' });
            return chips;
        });

        function update(key, value) {
            emit('update:modelValue', { ...props.modelValue, [key]: value });
            if (key !== 'search') emit('search');
        }

        function removeChip(key) {
            const defaults = { visibility: 'all', is_active: 'all', sort_order: 'desc', show_namespace: true };
            update(key, defaults[key]);
        }

        function onInput(e) {
            update('search', e.target.value);
            if (!e.target.value.trim()) emit('search');
        }

        function onEnter(e) {
            if (e.key === 'Enter') emit('search');
        }

        return { showAdvanced, sourceOptions, activeChips, update, removeChip, onInput, onEnter };
    },
    template: `
        <div class="tag-filter-bar mb-3">

            <!-- Search + actions -->
            <div class="d-flex gap-2 align-items-center mb-2 flex-wrap">
                <div class="input-group input-group-sm flex-grow-1" style="min-width:200px; max-width:420px;">
                    <span class="input-group-text bg-transparent border-end-0 pe-1">
                        <i class="fa-solid fa-magnifying-glass text-muted"></i>
                    </span>
                    <input
                        type="text"
                        :value="modelValue.search"
                        class="form-control border-start-0 ps-0"
                        placeholder="Search tags…"
                        @keyup="onEnter"
                        @input="onInput"
                    >
                </div>

                <button
                    class="btn btn-sm btn-outline-secondary position-relative"
                    :class="{ active: showAdvanced }"
                    @click="showAdvanced = !showAdvanced"
                >
                    <i class="fa-solid fa-sliders me-1"></i>Filters <i class="fas fa-caret-down ms-1"></i>
                    <span
                        v-if="activeChips.length"
                        class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger"
                        style="font-size:0.55rem;"
                    >{{ activeChips.length }}</span>
                </button>

                <!-- Export -->
                <div class="dropdown">
                    <button class="btn btn-sm btn-outline-primary dropdown-toggle" data-bs-toggle="dropdown">
                        <i class="fa-solid fa-download me-1"></i>Export
                    </button>
                    <ul class="dropdown-menu shadow border-0 rounded-3">
                        <li>
                            <button class="dropdown-item small" @click="$emit('export-all')">
                                <i class="fas fa-tags me-2 text-primary"></i>All tags ({{ total }})
                            </button>
                        </li>
                        <li v-if="selectedCount > 0">
                            <button class="dropdown-item small" @click="$emit('export-selected')">
                                <i class="fas fa-check-square me-2 text-success"></i>Selected ({{ selectedCount }})
                            </button>
                        </li>
                    </ul>
                </div>

                <!-- Bulk actions on selection -->
                <div v-if="selectedCount > 0" class="d-flex gap-1 align-items-center">
                    <span class="badge bg-primary-subtle text-primary border border-primary rounded-pill px-2 py-1">
                        <i class="fas fa-check-square me-1"></i>{{ selectedCount }} selected
                    </span>

                    <!-- Visibility dropdown -->
                    <div class="dropdown">
                        <button class="btn btn-sm btn-outline-primary dropdown-toggle" data-bs-toggle="dropdown" title="Change visibility">
                            <i class="fas fa-eye me-1"></i>Visibility
                        </button>
                        <ul class="dropdown-menu shadow border-0 rounded-3">
                            <li>
                                <button class="dropdown-item small" @click="$emit('set-public-selected')">
                                    <i class="fas fa-eye me-2 text-primary"></i>Make public
                                </button>
                            </li>
                            <li>
                                <button class="dropdown-item small" @click="$emit('set-private-selected')">
                                    <i class="fas fa-eye-slash me-2 text-secondary"></i>Make private
                                </button>
                            </li>
                        </ul>
                    </div>

                    <!-- Status dropdown -->
                    <div class="dropdown">
                        <button class="btn btn-sm btn-outline-success dropdown-toggle" data-bs-toggle="dropdown" title="Change status">
                            <i class="fas fa-toggle-on me-1"></i>Status
                        </button>
                        <ul class="dropdown-menu shadow border-0 rounded-3">
                            <li>
                                <button class="dropdown-item small" @click="$emit('activate-selected')">
                                    <i class="fas fa-check-circle me-2 text-success"></i>Activate
                                </button>
                            </li>
                            <li>
                                <button class="dropdown-item small" @click="$emit('deactivate-selected')">
                                    <i class="fas fa-ban me-2 text-danger"></i>Deactivate
                                </button>
                            </li>
                        </ul>
                    </div>

                    <!-- Delete -->
                    <button class="btn btn-sm btn-outline-danger rounded-pill px-3" @click="$emit('delete-selected')" title="Delete selected">
                        <i class="fas fa-trash me-1"></i>Delete
                    </button>

                    <!-- Clear -->
                    <button class="btn btn-sm btn-outline-secondary" @click="$emit('clear-selection')" title="Clear selection">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>

            <!-- Source tabs -->
            <div class="d-flex gap-2 flex-wrap mb-2">
                <button
                    v-for="opt in sourceOptions" :key="opt.value"
                    class="btn btn-sm source-chip"
                    :class="modelValue.source === opt.value ? 'active' : ''"
                    :style="modelValue.source === opt.value ? { background: opt.color, borderColor: opt.color, color: '#fff' } : {}"
                    @click="update('source', opt.value)"
                >
                    <i :class="'fa-solid ' + opt.icon + ' me-1'"></i>{{ opt.label }}
                </button>
            </div>

            <!-- Advanced panel -->
            <transition name="slide-down">
                <div v-if="showAdvanced" class="advanced-filters border rounded-3 p-3 mb-2">
                    <div class="row g-2 align-items-end">
                        <div class="col-6 col-md-3">
                            <label class="form-label small fw-semibold mb-1">Sort</label>
                            <select class="form-select form-select-sm" :value="modelValue.sort_order" @change="update('sort_order', $event.target.value)">
                                <option value="desc">Newest first</option>
                                <option value="asc">Oldest first</option>
                            </select>
                        </div>
                        <div class="col-6 col-md-3">
                            <label class="form-label small fw-semibold mb-1">Visibility</label>
                            <select class="form-select form-select-sm" :value="modelValue.visibility" @change="update('visibility', $event.target.value)">
                                <option value="all">All</option>
                                <option value="public">Public</option>
                                <option value="private">Private</option>
                            </select>
                        </div>
                        <div class="col-6 col-md-3">
                            <label class="form-label small fw-semibold mb-1">Status</label>
                            <select class="form-select form-select-sm" :value="modelValue.is_active" @change="update('is_active', $event.target.value)">
                                <option value="all">All</option>
                                <option value="active">Active</option>
                                <option value="inactive">Inactive</option>
                            </select>
                        </div>
                        <div class="col-6 col-md-3">
                            <label class="form-label small fw-semibold mb-1">Per page</label>
                            <select class="form-select form-select-sm" :value="modelValue.per_page" @change="update('per_page', parseInt($event.target.value))">
                                <option value="20">20</option>
                                <option value="50">50</option>
                                <option value="100">100</option>
                            </select>
                        </div>
                        <div class="col-12 col-md-6">
                            <label class="form-check small fw-semibold mb-0 d-flex align-items-center gap-2 mt-2">
                                <input
                                    type="checkbox" class="form-check-input m-0"
                                    :checked="modelValue.show_namespace"
                                    @change="update('show_namespace', $event.target.checked)"
                                >
                                Show namespace prefix in tag display
                            </label>
                        </div>
                    </div>
                </div>
            </transition>

            <!-- Active chips + count -->
            <div class="d-flex align-items-center gap-2 flex-wrap">
                <span class="badge rounded-pill bg-light text-dark border px-3 py-2 shadow-sm">
                    <i class="fa-solid fa-tags me-1 text-primary"></i>
                    <strong>{{ total }}</strong> tags
                </span>
                <span
                    v-for="chip in activeChips" :key="chip.key"
                    class="badge rounded-pill border px-2 py-1 filter-chip"
                    @click="removeChip(chip.key)" style="cursor:pointer; color: var(--text-color);"
                >
                    {{ chip.label }} <i class="fas fa-times ms-1"></i>
                </span>
            </div>
        </div>
    `
};

export default TagFilterBar;