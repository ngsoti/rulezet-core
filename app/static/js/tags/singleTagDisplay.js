const SingleTagDisplay = {
    props: {
        tag: { 
            type: Object, 
            required: true,
            default: () => ({
                id: null,
                name: '',
                color: '#6c757d',
                icon: 'fa-tag',
                description: '',
                created_at: null,
                visibility: 'Private'
            })
        },
        cssPath: { type: String, default: '/static/css/tag/tags.css' }
    },
    delimiters: ['[[', ']]'],
    setup(props) {
        // Chargement du CSS si nécessaire
        if (props.cssPath && !document.querySelector(`link[href="${props.cssPath}"]`)) {
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = props.cssPath;
            document.head.appendChild(link);
        }

        const getContrastYIQ = (hex) => {
            if (!hex) return '#000';
            const r = parseInt(hex.substr(1, 2), 16), 
                  g = parseInt(hex.substr(3, 2), 16), 
                  b = parseInt(hex.substr(5, 2), 16);
            return ((r * 299) + (g * 587) + (b * 114)) / 1000 >= 128 ? '#000' : '#fff';
        };

        return { getContrastYIQ };
    },
    template: `
    <div class="tag-wrapper d-inline-block">
        <span class="tag-split shadow-sm on-hover-zoom">
            <span class="tag-left">
                <i :class="['fas', tag.icon || 'fa-tag']"></i>
            </span>
            <span class="tag-right" :style="{ backgroundColor: tag.color || '#6c757d' }">
                <span :style="{ color: getContrastYIQ(tag.color) }" class="fw-bold">
                    [[ tag.name ]]
                </span>
            </span>
        </span>
        
        <div class="tag-tooltip animate__animated animate__fadeIn">
            <div class="hover-bridge"></div> 
            
            <div class="tooltip-header" :style="{ borderLeft: '4px solid ' + (tag.color || '#6c757d') }">
                <i :class="['fas', tag.icon || 'fa-tag', 'me-2 text-white']"></i>
                <strong class="text-white">[[ tag.name ]]</strong>
            </div>

            <div class="tooltip-body">
                <div class="description-container">
                    <div class="description-scroll text-white-50">
                        [[ tag.description || 'No description available for this tag.' ]]
                    </div>
                </div>
                
                <div class="d-flex justify-content-between mt-2 pt-2 border-top border-white border-opacity-10" style="font-size: 0.7rem;">
                    <span class="text-white-50">
                        <i :class="['fas', tag.visibility === 'Public' ? 'fa-globe' : 'fa-lock', 'me-1']"></i>
                        [[ tag.visibility || 'Private' ]]
                    </span>
                    <span v-if="tag.created_at" class="text-white-50">
                        <i class="far fa-calendar-alt me-1"></i> [[ tag.created_at ]]
                    </span>
                </div>
            </div>
            <div class="tooltip-arrow"></div>
        </div>
    </div>
    `
};

export default SingleTagDisplay;