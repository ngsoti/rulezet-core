import SingleTagDisplay from './singleTagDisplay.js'; 
const tagsDisplaysList = {
    components: {
        'single-tag-display': SingleTagDisplay
    },
    props: {
        objectId: { type: [Number, String], required: true },
        objectType: { type: String, required: true, validator: v => ['bundle', 'rule'].includes(v) },
        maxVisible: { type: Number, default: 5 },
        sectionTitle: { type: String, default: '' },
        user_id: { type: Number, default: null }
    },
    delimiters: ['[[', ']]'],
    setup(props) {
        const tags = Vue.ref([]);
        const loading = Vue.ref(false);

        const fetchTags = async () => {
            loading.value = true;
            try {
                let url = `/${props.objectType}/get_tags/${props.objectId}`;
                if (props.user_id !== null && !isNaN(props.user_id)) {
                    url += `?user_id=${props.user_id}`;
                }
                const response = await fetch(url);
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

        Vue.onMounted(fetchTags);
        Vue.watch(() => props.objectId, fetchTags);

        return { tags, loading };
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
            
            <single-tag-display 
                v-for="tag in visibleTags" 
                :key="tag.id" 
                :tag="tag">
            </single-tag-display>

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