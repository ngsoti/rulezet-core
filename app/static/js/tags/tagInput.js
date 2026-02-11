const TagInput = {
    props: {
        modelValue: { type: Array, default: () => [] }, 
        placeholder: { type: String, default: 'Search or select tags...' },
        label: { type: String, default: 'Associated Tags' },
        userId: { type: [Number, String], default: null },
        cssPath: { type: String, default: '/static/css/tag/tags.css' }
    },
    emits: ['update:modelValue'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const searchQuery = Vue.ref('');
        const availableTags = Vue.ref([]); 
        const isLoading = Vue.ref(false);
        const isDropdownOpen = Vue.ref(false);
        const activeType = Vue.ref(null);
        const activeNamespace = Vue.ref(null);

        if (props.cssPath && !document.querySelector(`link[href="${props.cssPath}"]`)) {
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = props.cssPath;
            document.head.appendChild(link);
        }

        const getContrastYIQ = (hex) => {
            if (!hex) return '#fff';
            const r = parseInt(hex.substr(1, 2), 16), 
                  g = parseInt(hex.substr(3, 2), 16), 
                  b = parseInt(hex.substr(5, 2), 16);
            return ((r * 299) + (g * 587) + (b * 114)) / 1000 >= 128 ? '#000' : '#fff';
        };

        const fetchAvailableTags = async () => {
            isLoading.value = true;
            try {
                const params = new URLSearchParams();
                if (props.userId) params.append('user_id', props.userId.toString());
                const url = `/tags/get_all_tags?${params.toString()}`;
                const response = await fetch(url); 
                if (response.ok) {
                    const data = await response.json();
                    availableTags.value = Array.isArray(data) ? data : (data.tags || []);
                }
            } catch (error) {
                console.error("Fetch error:", error);
            } finally {
                isLoading.value = false;
            }
        };

        const sortedGroupedTags = Vue.computed(() => {
            const groups = { 'Public': {}, 'Private': {} };
            availableTags.value.forEach(tag => {
                const type = tag.visibility === 'public' ? 'Public' : 'Private';
                let ns = 'General';
                let displayName = tag.name;
                if (tag.name.includes(':')) {
                    const parts = tag.name.split(':');
                    ns = parts[0].trim().toUpperCase();
                    displayName = parts.slice(1).join(':').trim();
                } else if (tag.namespace) {
                    ns = tag.namespace.toUpperCase();
                }
                if (!groups[type][ns]) groups[type][ns] = [];
                groups[type][ns].push({ ...tag, displayName: displayName });
            });
            if (Object.keys(groups['Private']).length === 0) delete groups['Private'];
            if (Object.keys(groups['Public']).length === 0) delete groups['Public'];
            return groups;
        });

        const filteredSuggestions = Vue.computed(() => {
            const query = searchQuery.value.toLowerCase().trim();
            return availableTags.value.filter(tag => {
                return tag.name.toLowerCase().includes(query);
            });
        });

        const isTagSelected = (tagId) => {
            return props.modelValue.some(t => t.id === tagId);
        };

        const toggleTag = (tag) => {
            if (isTagSelected(tag.id)) {
                const updatedValue = props.modelValue.filter(t => t.id !== tag.id);
                emit('update:modelValue', updatedValue);
            } else {
                emit('update:modelValue', [...props.modelValue, tag]);
            }
        };

        const toggleDropdown = () => {
            if (!isDropdownOpen.value && availableTags.value.length === 0) fetchAvailableTags();
            isDropdownOpen.value = !isDropdownOpen.value;
        };

        Vue.watch(searchQuery, (newVal) => {
            if (newVal) {
                activeType.value = null;
                activeNamespace.value = null;
            }
        });

        Vue.onMounted(() => {
            window.addEventListener('click', (e) => {
                if (!e.target.closest('.tag-input-container')) isDropdownOpen.value = false;
            });
        });

        return { 
            searchQuery, filteredSuggestions, isLoading, isDropdownOpen,
            toggleTag, isTagSelected, toggleDropdown, getContrastYIQ,
            sortedGroupedTags, activeType, activeNamespace
        };
    },
    template: `
    <div class="tag-input-container text-start position-relative">
        <label class="form-label fw-bold text-muted small text-uppercase">[[ label ]]</label>
        
        <div class="input-group shadow-sm rounded-3 border bg-white" style="border-width: 2px;">
            <span class="input-group-text border-0" style="cursor: pointer; background-color: var(--bg-color)">
                <i class="fas fa-search" style="font-size: 0.8rem; color: var(--text-color)"></i>
            </span>
            <input type="text" v-model="searchQuery" @focus="toggleDropdown"
                class="form-control border-0 shadow-none px-2" :placeholder="placeholder" style="height: 46px;">
            <div v-if="isLoading" class="input-group-text border-0 bg-transparent">
                <div class="spinner-border spinner-border-sm text-primary"></div>
            </div>
        </div>

        <div v-if="isDropdownOpen" 
             @click.stop
             class="dropdown-menu show shadow-lg border-0 p-3 w-100 mt-1"
             style="max-height: 450px; overflow-y: auto; z-index: 1060; min-width: 350px;">
            
            <div v-if="searchQuery">
                <div v-for="tag in filteredSuggestions" :key="tag.id" @click.stop="toggleTag(tag)"
                     class="dropdown-item rounded-2 py-2 d-flex align-items-center justify-content-between cursor-pointer mb-1 border"
                     :class="{'border-primary bg-primary-subtle': isTagSelected(tag.id)}">
                    <span class="tag-split">
                        <span class="tag-left bg-dark"><i :class="['fas', tag.icon || 'fa-tag']"></i></span>
                        <span class="tag-right" :style="{ backgroundColor: tag.color || '#6c757d' }">
                            <span :style="{ color: getContrastYIQ(tag.color) }" class="fw-bold">[[ tag.name ]]</span>
                        </span>
                    </span>
                    <div class="d-flex align-items-center gap-2">
                        <i v-if="isTagSelected(tag.id)" class="fas fa-check-circle text-primary"></i>
                        <small :class="tag.visibility === 'public' ? 'text-success' : 'text-danger'">
                            <i :class="['fas fa-sm', tag.visibility === 'public' ? 'fa-globe' : 'fa-lock']"></i>
                        </small>
                    </div>
                </div>
                <div v-if="filteredSuggestions.length === 0" class="text-center py-4">
                    <i class="fas fa-search mb-2 opacity-25" style="font-size: 2rem; color: var(--text-color)"></i>
                    <p class="fw-bold" style="color: var(--text-color)">No tags found for this search.</p>
                </div>
            </div>

            <div v-else-if="!activeType">
                <div v-for="(namespaces, type) in sortedGroupedTags" :key="type" 
                     @click.stop="activeType = type"
                     class="p-2 rounded border d-flex align-items-center justify-content-between mb-2 cursor-pointer hover-bg-light">
                    <div class="d-flex align-items-center">
                        <i :class="type === 'Public' ? 'fa-globe text-success' : 'fa-lock text-danger'" class="fas me-3"></i>
                        <span class="fw-bold" style="color: var(--text-color)">[[ type ]] Tags</span>
                    </div>
                    <i class="fas fa-chevron-right small opacity-50" style="color: var(--text-color)"></i>
                </div>
                <div v-if="Object.keys(sortedGroupedTags).length === 0 && !isLoading" class="text-center py-4">
                    <p class="text-muted small fw-bold">No tags available.</p>
                </div>
            </div>

            <div v-else-if="!activeNamespace">
                <div class="mb-2">
                    <button @click.stop="activeType = null" class="btn btn-sm text-primary p-0 fw-bold">
                        <i class="fas fa-chevron-left me-1"></i> Back to Types
                    </button>
                </div>
                <div v-for="(tags, ns) in sortedGroupedTags[activeType]" :key="ns" 
                     @click.stop="activeNamespace = ns"
                     class="p-2 rounded border d-flex align-items-center justify-content-between mb-2 cursor-pointer hover-bg-light">
                    <div class="d-flex align-items-center">
                        <i class="fas fa-folder text-primary opacity-75 me-3"></i>
                        <span class="fw-bold" style="color: var(--text-color)">[[ ns ]]</span>
                    </div>
                    <span class="badge bg-light text-dark border rounded-pill">[[ tags.length ]]</span>
                </div>
            </div>

            <div v-else>
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <button @click.stop="activeNamespace = null" class="btn btn-sm text-primary p-0 fw-bold">
                        <i class="fas fa-chevron-left me-1"></i> Back to [[ activeType ]]
                    </button>
                    <small class="text-uppercase fw-bold text-muted">[[ activeNamespace ]]</small>
                </div>
                <div v-for="tag in sortedGroupedTags[activeType][activeNamespace]" :key="tag.id" 
                     @click.stop="toggleTag(tag)"
                     class="dropdown-item rounded border mb-2 p-2 d-flex align-items-center justify-content-between cursor-pointer"
                     :class="{'border-primary bg-primary-subtle shadow-sm': isTagSelected(tag.id)}">
                    <span class="tag-split">
                        <span class="tag-left bg-dark"><i :class="['fas', tag.icon || 'fa-tag']"></i></span>
                        <span class="tag-right" :style="{ backgroundColor: tag.color || '#6c757d' }">
                            <span :style="{ color: getContrastYIQ(tag.color) }">[[ tag.displayName ]]</span>
                        </span>
                    </span>
                    <i :class="isTagSelected(tag.id) ? 'fas fa-check-circle text-primary' : 'fas fa-plus-circle text-muted'"></i>
                </div>
            </div>
        </div>

        <div class="d-flex flex-wrap gap-2 mt-3">
            <div v-for="tag in modelValue" :key="tag.id" class="d-inline-block">
                <span class="tag-split shadow-sm">
                    <span class="tag-left bg-dark"><i :class="['fas', tag.icon || 'fa-tag']"></i></span>
                    <span class="tag-right" :style="{ backgroundColor: tag.color || '#6c757d' }">
                        <span :style="{ color: getContrastYIQ(tag.color) }" class="fw-bold me-2">[[ tag.name ]]</span>
                        <i class="fas fa-times-circle cursor-pointer" style="color: black;" @click.stop="toggleTag(tag)"></i>
                    </span>
                </span>
            </div>
        </div>
    </div>
    `
};

export default TagInput;