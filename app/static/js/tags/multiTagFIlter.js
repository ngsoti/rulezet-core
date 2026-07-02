import { getTextColor, mapIcon } from './utils/galaxie.js';

const MultiTagFilter = {
    props: {
        modelValue: { type: Array, default: () => [] },
        placeholder: { type: String, default: 'Filter by tags…' },
        apiEndpoint: { type: String, default: '/bundle/get_all_tags_usage' },
        showNamespace: { type: Boolean, default: true },
        // Query string of every OTHER currently active RuleList filter — keeps
        // these counts scoped to what's actually visible.
        filterContext: { type: String, default: '' },
    },
    emits: ['update:modelValue', 'change'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const listTags = Vue.ref([]);
        const tagSearchQuery = Vue.ref('');
        const selectedTagNames = Vue.ref([...props.modelValue]);
        const activeNamespace = Vue.ref(null);
        const activeSource = Vue.ref('all');   // 'all' | 'Taxonomy' | 'Galaxy' | 'Manual'
        const isLoading = Vue.ref(false);

        const sourceOptions = [
            { value: 'all', label: 'All', icon: 'fa-layer-group', color: '#6c757d' },
            { value: 'Taxonomy', label: 'Taxonomy', icon: 'fa-list', color: '#0d6efd' },
            { value: 'Galaxy', label: 'Galaxy', icon: 'fa-atom', color: '#8b5cf6' },
            { value: 'Manual', label: 'Manual', icon: 'fa-tag', color: '#198754' },
        ];

        function namespaceOf(name) {
            if (!name || !name.includes(':')) return '';
            if (name.startsWith('misp-galaxy:') && name.includes('=')) return name.split(':')[1].split('=')[0];
            return name.split(':')[0];
        }
        function valueOf(name) {
            if (!name) return '';
            const m = name.match(/="(.+)"$/);
            if (m) return m[1];
            if (name.includes(':')) return name.split(':').slice(1).join(':');
            return name;
        }
        function tagLabel(name) {
            const ns = namespaceOf(name);
            const val = valueOf(name);
            if (props.showNamespace && ns) return `${ns}:${val}`;
            return val;
        }

        const isNameSelected = (name) =>
            selectedTagNames.value.some(n => n.toLowerCase() === name.toLowerCase());

        // Vue.watch(() => props.modelValue, (val) => { selectedTagNames.value = [...val]; });
        Vue.watch(() => props.modelValue, (val) => {
            if (val && val.length > 0) selectedTagNames.value = [...val];
        });

        async function fetchTags() {
            isLoading.value = true;
            try {
                const url = props.filterContext ? `${props.apiEndpoint}?${props.filterContext}` : props.apiEndpoint;
                const res = await fetch(url);
                if (res.ok) {
                    const data = await res.json();
                    listTags.value = data.tags || [];
                    if (props.modelValue && props.modelValue.length > 0) {
                        selectedTagNames.value = [...props.modelValue];
                    }
                }
            } catch (e) {
                console.error('MultiTagFilter fetch error:', e);
            } finally {
                isLoading.value = false;
            }
        }

        // tags filtered by active source
        const sourcedTags = Vue.computed(() => {
            if (activeSource.value === 'all') return listTags.value;
            return listTags.value.filter(t => t.source === activeSource.value);
        });

        const groupedTags = Vue.computed(() => {
            const groups = {};
            sourcedTags.value.forEach(tag => {
                const ns = namespaceOf(tag.name)?.toUpperCase() || 'OTHER';
                if (!groups[ns]) groups[ns] = [];
                groups[ns].push(tag);
            });
            return groups;
        });

        const filteredTagsList = Vue.computed(() => {
            if (!tagSearchQuery.value) return null;
            const q = tagSearchQuery.value.toLowerCase();
            return sourcedTags.value.filter(t =>
                t.name.toLowerCase().includes(q)
            );
        });

        const selectedTagsObjects = Vue.computed(() =>
            listTags.value.filter(t => isNameSelected(t.name))
        );

        function setSource(src) {
            activeSource.value = src;
            activeNamespace.value = null;
            tagSearchQuery.value = '';
        }

        function toggleTag(tagName) {
            const i = selectedTagNames.value.findIndex(n => n.toLowerCase() === tagName.toLowerCase());
            if (i > -1) selectedTagNames.value.splice(i, 1);
            else selectedTagNames.value.push(tagName);
            emit('update:modelValue', [...selectedTagNames.value]);
            emit('change', [...selectedTagNames.value]);
        }

        Vue.onMounted(fetchTags);
        Vue.watch(() => props.filterContext, fetchTags);

        return {
            listTags, tagSearchQuery, selectedTagNames, activeNamespace, activeSource, isLoading,
            sourceOptions, sourcedTags, groupedTags, filteredTagsList, selectedTagsObjects,
            isNameSelected, toggleTag, tagLabel, setSource,
            getTextColor, mapIcon,
            clearAll: () => {
                selectedTagNames.value = [];
                emit('update:modelValue', []);
                emit('change', []);
            }
        };
    },
    template: `
        <div class="dropdown multi-tag-filter w-100">

            <!-- Trigger pill -->
            <div class="form-control d-flex flex-wrap gap-2 align-items-center p-2 shadow-sm border-secondary-subtle"
                 data-bs-toggle="dropdown" data-bs-auto-close="outside"
                 style="cursor:pointer; min-height:48px; border-radius:12px;">
                <i class="fa-solid fa-tags text-primary opacity-75 ms-1 me-1"></i>
                <span v-if="selectedTagsObjects.length === 0" class="text-muted small fw-bold">[[ placeholder ]]</span>
                <span v-for="tag in selectedTagsObjects" :key="tag.name" class="tag-split shadow-sm m-0">
                    <span class="tag-left" v-html="mapIcon(tag.icon)"></span>
                    <span class="tag-right" :style="{ backgroundColor: tag.color || '#6c757d' }">
                        <span :style="{ color: getTextColor(tag.color || '#6c757d') }" class="me-2" style="font-size:0.75rem">
                            [[ tagLabel(tag.name) ]]
                        </span>
                        <i class="fa-solid fa-circle-xmark opacity-75 ms-1" @click.stop="toggleTag(tag.name)"
                           :style="{ color: getTextColor(tag.color || '#6c757d'), cursor: 'pointer' }"></i>
                    </span>
                </span>
                <i class="fa-solid fa-chevron-down ms-auto me-1 text-muted small"></i>
            </div>

            <!-- Dropdown panel -->
            <div class="dropdown-menu shadow-lg border-0 w-100 p-3 mt-2"
                 style="max-height:600px; border-radius:15px; z-index:1060; min-width:350px;">

                <!-- Search -->
                <div class="d-flex align-items-center mb-2">
                    <button v-if="activeNamespace && !tagSearchQuery"
                            @click="activeNamespace = null"
                            class="btn btn-sm btn-outline-primary border-0 me-2 rounded-circle d-flex align-items-center justify-content-center"
                            style="width:30px; height:30px;">
                        <i class="fa-solid fa-arrow-left"></i>
                    </button>
                    <div class="input-group input-group-sm">
                        <span class="input-group-text bg-light border-0"><i class="fa-solid fa-magnifying-glass"></i></span>
                        <input type="text" v-model="tagSearchQuery"
                               class="form-control bg-light border-0 shadow-none"
                               placeholder="Search tags…">
                    </div>
                </div>

                <!-- Source filter chips -->
                <div v-if="!activeNamespace" class="d-flex gap-1 flex-wrap mb-2">
                    <button
                        v-for="opt in sourceOptions" :key="opt.value"
                        class="btn btn-xs rounded-pill px-2 py-1"
                        :style="activeSource === opt.value
                            ? { background: opt.color, borderColor: opt.color, color: '#fff', fontSize: '0.72rem' }
                            : { fontSize: '0.72rem' }"
                        :class="activeSource === opt.value ? '' : 'btn-outline-secondary'"
                        @click.stop="setSource(opt.value)"
                    >
                        <i :class="'fa-solid ' + opt.icon + ' me-1'"></i>[[ opt.label ]]
                    </button>
                </div>

                <div class="pe-1" style="max-height:380px; overflow-y:auto; overflow-x:hidden;">

                    <!-- Empty state -->
                    <div v-if="(!isLoading && sourcedTags.length === 0) || (tagSearchQuery && filteredTagsList && filteredTagsList.length === 0)"
                         class="text-center py-4">
                        <i class="fa-solid fa-tags fa-3x text-muted opacity-25 mb-2 d-block"></i>
                        <h6 class="text-muted fw-bold">No tags found</h6>
                    </div>

                    <!-- Search results -->
                    <div v-else-if="tagSearchQuery" class="d-flex flex-column gap-1">
                        <div v-for="tag in filteredTagsList" :key="tag.name"
                             @click="toggleTag(tag.name)"
                             class="p-2 rounded border d-flex align-items-center justify-content-between"
                             :class="{ 'border-primary bg-primary-subtle': isNameSelected(tag.name) }"
                             style="cursor:pointer">
                            <span class="tag-split shadow-sm">
                                <span class="tag-left" v-html="mapIcon(tag.icon)"></span>
                                <span class="tag-right" :style="{ backgroundColor: tag.color || '#6c757d' }">
                                    <span :style="{ color: getTextColor(tag.color || '#6c757d') }" class="small fw-bold">
                                        [[ tagLabel(tag.name) ]]
                                    </span>
                                </span>
                            </span>
                            <span class="badge rounded-pill border" style="background:var(--light-bg-color); color:var(--text-color)">
                                [[ tag.usage_count ]]
                            </span>
                        </div>
                    </div>

                    <!-- Namespace list -->
                    <div v-else-if="!activeNamespace" class="d-flex flex-column gap-2">
                        <div v-for="(tags, ns) in groupedTags" :key="ns"
                             @click="activeNamespace = ns"
                             class="p-2 px-3 rounded-3 border d-flex align-items-center justify-content-between"
                             style="cursor:pointer; min-height:50px;">
                            <div class="d-flex align-items-center">
                                <i class="fa-solid fa-folder text-primary me-3 opacity-75"></i>
                                <span class="fw-bold text-truncate" style="max-width:180px; color:var(--text-color)">[[ ns ]]</span>
                            </div>
                            <div class="d-flex align-items-center gap-3">
                                <span class="small fw-bold text-nowrap" style="color:var(--subtle-text-color)">[[ tags.length ]] tags</span>
                                <i class="fa-solid fa-chevron-right opacity-50 small"></i>
                            </div>
                        </div>
                    </div>

                    <!-- Tags in namespace -->
                    <div v-else>
                        <div class="px-2 mb-2 d-flex justify-content-between align-items-center">
                            <small class="fw-bold text-primary text-uppercase">[[ activeNamespace ]]</small>
                            <small style="color:var(--subtle-text-color)">[[ groupedTags[activeNamespace]?.length ]] items</small>
                        </div>
                        <div class="d-flex flex-column gap-2">
                            <div v-for="tag in groupedTags[activeNamespace]" :key="tag.name"
                                 @click="toggleTag(tag.name)"
                                 class="p-2 rounded-3 border d-flex align-items-center justify-content-between"
                                 :class="{ 'border-primary bg-primary-subtle': isNameSelected(tag.name) }"
                                 style="cursor:pointer">
                                <span class="tag-split shadow-sm">
                                    <span class="tag-left" v-html="mapIcon(tag.icon)"></span>
                                    <span class="tag-right" :style="{ backgroundColor: tag.color || '#6c757d' }">
                                        <span :style="{ color: getTextColor(tag.color || '#6c757d') }">
                                            [[ tagLabel(tag.name) ]]
                                        </span>
                                    </span>
                                </span>
                                <div class="d-flex align-items-center gap-2">
                                    <span class="badge rounded-pill border" style="font-size:0.65rem; background:var(--light-bg-color); color:var(--text-color)">
                                        [[ tag.usage_count ]]
                                    </span>
                                    <i v-if="isNameSelected(tag.name)" class="fa-solid fa-check-circle text-primary"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `
};

export default MultiTagFilter;