const tagsDisplaysList = {
    props: {
        objectId: { type: [Number, String], required: true },
        objectType: { type: String, required: true, validator: v => ['bundle', 'rule'].includes(v) },
        maxVisible: { type: Number, default: 5 },
        sectionTitle: { type: String, default: '' },
    },
    delimiters: ['[[', ']]'],
    setup(props) {
        const tags = Vue.ref([]);
        const loading = Vue.ref(false);

        const fetchTags = async () => {
            loading.value = true;
            try {
                const response = await fetch(`/${props.objectType}/get_tags/${props.objectId}`);
                if (response.ok) {
                    const data = await response.json();
                    tags.value = data.tags || [];
                }
            } catch (e) {
                console.error("Error fetching tags:", e);
            } finally {
                loading.value = false;
            }
        };

        const getContrastYIQ = (hex) => {
            if (!hex) return '#000';
            const r = parseInt(hex.substr(1, 2), 16), g = parseInt(hex.substr(3, 2), 16), b = parseInt(hex.substr(5, 2), 16);
            return ((r * 299) + (g * 587) + (b * 114)) / 1000 >= 128 ? '#000' : '#fff';
        };

        Vue.onMounted(() => {
        fetchTags();
    });

        Vue.watch(() => props.objectId, fetchTags);

        return { tags, loading, getContrastYIQ };
    },
    data() {
        return { isCollapsed: false, isShowingAll: false };
    },
template: `
    <div class="tag-display-container">
        <div v-if="sectionTitle" class="d-flex align-items-center mb-2 mt-1">
            <div class="bg-primary rounded-pill me-2" style="width: 3px; height: 14px;"></div>
            <span class="text-uppercase fw-bold text-muted" style="font-size: 0.65rem; letter-spacing: 0.05rem;">
                [[ sectionTitle ]]
            </span>
        </div>

        <div v-if="loading" class="d-flex gap-1 py-1">
            <div class="spinner-grow spinner-grow-sm text-primary opacity-25" role="status"></div>
            <div class="spinner-grow spinner-grow-sm text-primary opacity-25" role="status" style="animation-delay: 0.1s"></div>
        </div>

        <div v-else class="d-flex flex-wrap gap-2 align-items-center">
            <div v-for="tag in visibleTags" :key="tag.id" class="tag-wrapper">
                
                <span class="tag-split shadow-sm on-hover-zoom">
                    <span class="tag-left">
                        <i :class="['fas', tag.icon || 'fa-tag']"></i>
                    </span>
                    <span class="tag-right" :style="{ backgroundColor: tag.color }">
                        <span :style="{ color: getContrastYIQ(tag.color) }">
                            [[ tag.name ]]
                        </span>
                    </span>
                </span>
                
                <div class="tag-tooltip animate__animated animate__fadeIn">
                    <div class="hover-bridge"></div> 
                    
                    <div class="tooltip-header" :style="{ borderLeft: '4px solid ' + tag.color }">
                        <i :class="['fas', tag.icon || 'fa-tag', 'me-2 text-primary']"></i>
                        <strong class="text-white">[[ tag.name ]]</strong>
                    </div>

                    <div class="tooltip-body">
                        <div class="description-container">
                            <div class="description-scroll">
                                [[ tag.description || 'No description available for this tag.' ]]
                            </div>
                        </div>
                        
                        <div class="d-flex justify-content-between mt-2 pt-2 border-top border-white border-opacity-10" style="font-size: 0.7rem;">
                            <span class="text-white-50">
                                <i class="fas fa-fingerprint me-1"></i> ID: [[ tag.id ]]
                            </span>
                            <span v-if="tag.created_at" class="text-white-50">
                                <i class="far fa-calendar-alt me-1"></i> [[ tag.created_at ]]
                            </span>
                        </div>
                    </div>
                    <div class="tooltip-arrow"></div>
                </div>
            </div>

            <button v-if="tags.length > maxVisible" 
                @click.stop="isShowingAll = !isShowingAll" 
                class="btn btn-sm border rounded-pill bg-white text-primary fw-bold shadow-sm transition-all"
                style="font-size: 0.7rem; padding: 2px 10px; height: 26px;">
                [[ isShowingAll ? 'Collapse' : '+' + (tags.length - maxVisible) ]]
            </button>

           
        </div>
    </div>
`,
    computed: {
        visibleTags() {
            return this.isShowingAll ? this.tags : this.tags.slice(0, this.maxVisible);
        }
    }
};
export default tagsDisplaysList;