const MultiTagFilter = {
    props: {
        modelValue: { type: Array, default: () => [] },
        placeholder: { type: String, default: 'Filter by tags...' },
        apiEndpoint: { type: String, default: '/bundle/get_all_tags_usage' }
    },
    emits: ['update:modelValue', 'change'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const list_tags = Vue.ref([]);
        const tagSearchQuery = Vue.ref('');
        const selectedTagIds = Vue.ref([...props.modelValue]);
        const activeNamespace = Vue.ref(null);

        const fetchTags = async () => {
            try {
                const response = await fetch(props.apiEndpoint);
                if (response.ok) {
                    const data = await response.json();
                    list_tags.value = data.tags || [];
                }
            } catch (e) { console.error("Error loading filter tags", e); }
        };

        const groupedTags = Vue.computed(() => {
            const groups = {};
            list_tags.value.forEach(tag => {
                const parts = tag.name.split(':');
                const ns = parts.length > 1 ? parts[0].trim().toUpperCase() : 'OTHER';
                if (!groups[ns]) groups[ns] = [];
                groups[ns].push(tag);
            });
            return groups;
        });

        const filteredTagsList = Vue.computed(() => {
            if (!tagSearchQuery.value) return null;
            const q = tagSearchQuery.value.toLowerCase();
            return list_tags.value.filter(t => t.name.toLowerCase().includes(q));
        });

        const selectedTagsObjects = Vue.computed(() => {
            return list_tags.value.filter(t => selectedTagIds.value.includes(t.id));
        });

        const toggleTag = (tagId) => {
            const index = selectedTagIds.value.indexOf(tagId);
            if (index > -1) {
                selectedTagIds.value.splice(index, 1);
            } else {
                selectedTagIds.value.push(tagId);
            }
            emit('update:modelValue', selectedTagIds.value);
            emit('change', selectedTagIds.value);
        };

        const getContrastYIQ = (hex) => {
            if (!hex) return '#000';
            const r = parseInt(hex.substr(1, 2), 16), g = parseInt(hex.substr(3, 2), 16), b = parseInt(hex.substr(5, 2), 16);
            return ((r * 299) + (g * 587) + (b * 114)) / 1000 >= 128 ? '#000' : '#fff';
        };

        Vue.onMounted(fetchTags);

        return {
            tagSearchQuery, groupedTags, selectedTagIds, activeNamespace,
            selectedTagsObjects, toggleTag, getContrastYIQ, filteredTagsList,
            clearAll: () => { selectedTagIds.value = []; emit('update:modelValue', []); }
        };
    },
template: `
    <div class="dropdown multi-tag-filter w-100">
        <div class="form-control d-flex flex-wrap gap-2 align-items-center p-2  shadow-sm border-secondary-subtle" 
             data-bs-toggle="dropdown" data-bs-auto-close="outside" 
             style="cursor: pointer; min-height: 48px; border-radius: 12px;">
            
            <i class="fa-solid fa-tags text-primary opacity-75 ms-1 me-1"></i>
            <span v-if="selectedTagIds.length === 0" class="text-muted small fw-bold">[[ placeholder ]]</span>

            <span v-for="tag in selectedTagsObjects" :key="tag.id" class="tag-split animate__animated animate__fadeInSmall shadow-sm m-0">
                <span class="tag-left" style="padding: 0.2rem 0.4rem; background-color: #212529;">
                    <i :class="['fas', tag.icon || 'fa-tag']"></i>
                </span>
                <span class="tag-right" :style="{ backgroundColor: tag.color, padding: '0.2rem 0.5rem' }">
                    <span :style="{ color: getContrastYIQ(tag.color) }" class="me-2" style="font-size: 0.75rem;">[[ tag.name ]]</span>
                    <i class="fa-solid fa-circle-xmark opacity-75 ms-1" @click.stop="toggleTag(tag.id)" style="cursor: pointer;"></i>
                </span>
            </span>
            <i class="fa-solid fa-chevron-down ms-auto me-1 text-muted small"></i>
        </div>

        <div class="dropdown-menu shadow-lg border-0 w-100 p-3 mt-2 animate__animated animate__fadeIn" 
             style="max-height: 550px; border-radius: 15px; z-index: 1060; min-width: 350px;">
            
            <div class="d-flex align-items-center mb-3">
                <button v-if="activeNamespace && !tagSearchQuery" @click="activeNamespace = null" 
                        class="btn btn-sm btn-outline-primary border-0 me-2 rounded-circle d-flex align-items-center justify-content-center"
                        style="width: 30px; height: 30px;">
                    <i class="fa-solid fa-arrow-left"></i>
                </button>
                <div class="input-group input-group-sm">
                    <span class="input-group-text bg-light border-0"><i class="fa-solid fa-magnifying-glass"></i></span>
                    <input type="text" v-model="tagSearchQuery" class="form-control bg-light border-0 shadow-none" placeholder="Quick search...">
                </div>
            </div>

            <div class="custom-tag-scroll pe-2" style="max-height: 400px; overflow-y: auto; overflow-x: hidden;">
                
                <div v-if="tagSearchQuery" class="d-flex flex-column gap-1">
                    <div v-for="tag in filteredTagsList" :key="tag.id" 
                         @click="toggleTag(tag.id)" 
                         class="p-2 rounded border d-flex align-items-center justify-content-between tag-item-hover "
                         :class="{'border-primary bg-primary-subtle': selectedTagIds.includes(tag.id)}">
                         <div class="d-flex align-items-center">
                            <i :class="['fas', tag.icon || 'fa-tag', 'me-2 ']" style="font-size: 0.8rem; color: var(--text-color);"></i>
                            <span class="small fw-bold" style="color: var(--text-color);">[[ tag.name ]]</span>
                         </div>
                         <span class="badge rounded-pill bg-light text-dark border" style="color: var(--text-color);">[[ tag.usage_count ]]</span>
                    </div>
                </div>

                <div v-else-if="!activeNamespace" class="d-flex flex-column gap-2">
                    <div v-for="(tags, ns) in groupedTags" :key="ns" 
                         @click="activeNamespace = ns"
                         class="p-2 px-3 rounded-3 border  d-flex align-items-center justify-content-between tag-item-hover shadow-xs" 
                         style="cursor: pointer; min-height: 50px;">
                        <div class="d-flex align-items-center">
                            <i class="fa-solid fa-tags text-primary me-3"></i>
                            <span class="fw-bold text-truncate" style="max-width: 180px; color: var(--text-color);">[[ ns ]]</span>
                        </div>
                        <div class="d-flex align-items-center gap-3">
                            <span class="extra-small fw-bold text-nowrap" style="color: var(--text-color);">[[ tags.length ]] tags</span>
                            <i class="fa-solid fa-chevron-right  opacity-50 small" style="color: var(--text-color);"></i>
                        </div>
                    </div>
                </div>

                <div v-else class="animate__animated animate__fadeInUpSmall">
                    <div class="px-2 mb-2 d-flex justify-content-between align-items-center">
                        <small class="fw-black text-primary text-uppercase">[[ activeNamespace ]]</small>
                        <small style="color: var(--text-color);">[[ groupedTags[activeNamespace].length ]] items</small>
                    </div>
                    
                    <div class="d-flex flex-column gap-2">
                        <div v-for="tag in groupedTags[activeNamespace]" :key="tag.id" 
                             @click="toggleTag(tag.id)" 
                             class="p-2 rounded-3 border d-flex align-items-center justify-content-between transition-all tag-item-hover "
                             :class="selectedTagIds.includes(tag.id) ? 'border-primary bg-primary-subtle' : ''">
                            
                            <div class="d-flex align-items-center">
                                <span class="tag-split m-0 shadow-none" style="font-size: 0.75rem;">
                                    <span class="tag-left" style="background-color: #343a40; padding: 0.15rem 0.4rem;">
                                        <i :class="['fas', tag.icon || 'fa-tag']"></i>
                                    </span>
                                    <span class="tag-right" :style="{ backgroundColor: tag.color, padding: '0.15rem 0.5rem' }">
                                        <span :style="{ color: getContrastYIQ(tag.color) }">[[ tag.name ]]</span>
                                    </span>
                                </span>
                            </div>
                            
                            <div class="d-flex align-items-center gap-2">
                                <span class="badge rounded-pill bg-light  border" style="font-size: 0.65rem; color: var(--text-color);">
                                    [[ tag.usage_count ]]
                                </span>
                                <i v-if="selectedTagIds.includes(tag.id)" class="fa-solid fa-check-circle text-primary"></i>
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