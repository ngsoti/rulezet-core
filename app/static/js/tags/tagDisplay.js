const TagDisplay = {
    props: {
        tags: { type: Array, required: true },
        loading: { type: Boolean, default: false },
        maxVisible: { type: Number, default: 10 },
        sectionTitle: { type: String, default: 'Included Tags' },
        cssPath: { type: String, default: '/static/css/tag/tags.css' }
    },
    delimiters: ['[[', ']]'],
    setup(props) {
        if (props.cssPath && !document.querySelector(`link[href="${props.cssPath}"]`)) {
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = props.cssPath;
            document.head.appendChild(link);
        }
    },
    data() {
        return { isCollapsed: false, isShowingAll: false };
    },
    template: `
    <div class="mt-4">
        <div @click="isCollapsed = !isCollapsed" style="cursor: pointer;" class="user-select-none">
            <div class="d-flex justify-content-between align-items-center">
                <h4 class="fw-bold mb-0 text-dark d-flex align-items-center">
                    <span class="text-primary me-2">|</span>[[ sectionTitle ]]
                    <i class="fas fa-chevron-down ms-2 small opacity-50 transition-all"
                        :style="{ transform: isCollapsed ? 'rotate(0deg)' : 'rotate(180deg)', transition: '0.3s' }"></i>
                </h4>
                <span v-if="!isCollapsed" class="badge bg-light text-primary border rounded-pill px-3 shadow-sm">
                    [[ tags.length ]] tags
                </span>
            </div>
            <div v-if="isCollapsed" class="text-muted small mt-1" style="padding-left: 1.5rem;">
                <i class="fas fa-info-circle me-1"></i> Summary: <strong>[[ tags.length ]] tags</strong> hidden. Click to expand.
            </div>
        </div>

        <div v-show="!isCollapsed" class="mt-3 animate__animated animate__fadeIn">
            <div class="d-flex flex-wrap gap-2 p-3 bg-light rounded-3 shadow-sm border border-dashed">
                
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
                    
                    <div class="tag-tooltip">
                        <div class="hover-bridge"></div>
                        <div class="tooltip-header" :style="{ borderLeft: '4px solid ' + tag.color }">
                            <i :class="['fas', tag.icon || 'fa-tag', 'me-2 text-primary']"></i>
                            <strong class="text-white">[[ tag.name ]]</strong>
                        </div>
                        <div class="tooltip-body">
                            <div class="description-container">
                                <div class="description-scroll text-white-50">
                                    [[ tag.description || 'No description provided.' ]]
                                </div>
                            </div>
                            <div class="d-flex justify-content-between mt-2 pt-2 border-top border-white border-opacity-10 small">
                                <span class="text-white-50">
                                    <i :class="['fas', tag.visibility === 'public' ? 'fa-globe' : 'fa-lock', 'me-1']"></i>
                                    [[ tag.visibility ]]
                                </span>
                                <span v-if="tag.created_at" class="text-white-50">
                                    <i class="fas fa-calendar-alt me-1"></i>
                                    [[ tag.created_at ]]
                                </span>
                            </div>
                        </div>
                        <div class="tooltip-arrow"></div>
                    </div>
                </div>

                <button v-if="tags.length > maxVisible" 
                        @click.stop="isShowingAll = !isShowingAll" 
                        class="btn btn-sm btn-outline-primary rounded-pill px-3 fw-bold shadow-sm transition-all bg-white"
                        style="font-size: 0.75rem;">
                    [[ isShowingAll ? 'Show Less' : '+ ' + (tags.length - maxVisible) + ' more tags' ]]
                </button>

                <div v-if="tags.length === 0 && !loading" class="text-muted small fst-italic py-1">
                    <i class="fas fa-slash me-1 opacity-50"></i> No tags assigned.
                </div>
                <div v-if="loading" class="d-flex align-items-center gap-2 py-1">
                    <div class="spinner-border spinner-border-sm text-primary"></div>
                    <small class="text-muted">Loading tags...</small>
                </div>
            </div>
        </div>
    </div>
    `,
    computed: {
        visibleTags() {
            return this.isShowingAll ? this.tags : this.tags.slice(0, this.maxVisible);
        }
    },
    methods: {
        getContrastYIQ(hex) {
            if (!hex) return '#000';
            const r = parseInt(hex.substr(1, 2), 16), g = parseInt(hex.substr(3, 2), 16), b = parseInt(hex.substr(5, 2), 16);
            return ((r * 299) + (g * 587) + (b * 114)) / 1000 >= 128 ? '#000' : '#fff';
        }
    }
};
export default TagDisplay;