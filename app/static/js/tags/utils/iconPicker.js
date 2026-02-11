const IconPicker = {
    props: {
        modelValue: { type: String, default: 'fa-tag' }
    },
    emits: ['update:modelValue'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const searchQuery = Vue.ref('');
        const isOpen = Vue.ref(false);
        
        const icons = [
            'fa-tag', 'fa-tags', 'fa-bookmark', 'fa-flag', 'fa-star', 'fa-heart',
            'fa-user', 'fa-users', 'fa-folder', 'fa-file', 'fa-archive', 'fa-box',
            'fa-shield-halved', 'fa-lock', 'fa-key', 'fa-eye', 'fa-bell', 'fa-bolt',
            'fa-camera', 'fa-image', 'fa-video', 'fa-music', 'fa-microphone',
            'fa-globe', 'fa-map-pin', 'fa-location-dot', 'fa-briefcase', 'fa-building',
            'fa-house', 'fa-gear', 'fa-wrench', 'fa-hammer', 'fa-pen', 'fa-check-double',
            'fa-circle-info', 'fa-triangle-exclamation', 'fa-fire', 'fa-leaf', 'fa-cloud'
        ];

        const filteredIcons = Vue.computed(() => {
            return icons.filter(icon => icon.includes(searchQuery.value.toLowerCase()));
        });

        const selectIcon = (icon) => {
            emit('update:modelValue', icon);
            isOpen.value = false;
            searchQuery.value = '';
        };

        return { searchQuery, filteredIcons, isOpen, selectIcon };
    },
    template: `
    <div class="icon-picker-container position-relative">
        <label class="form-label fw-bold small text-muted text-uppercase mb-1">Icon</label>
        <div class="input-group shadow-sm rounded-3 cursor-pointer" @click="isOpen = !isOpen">
            <span class="input-group-text border-0 bg-light">
                <i :class="['fas', modelValue || 'fa-tag']" class="text-primary"></i>
            </span>
            <input type="text" class="form-control border-0 bg-light cursor-pointer" 
                :value="modelValue" readonly style="height: 45px;">
            <span class="input-group-text border-0 bg-light">
                <i class="fas" :class="isOpen ? 'fa-chevron-up' : 'fa-chevron-down'" style="font-size: 0.8rem;"></i>
            </span>
        </div>

        <div v-if="isOpen" class="card shadow-lg border-0 position-absolute w-100 mt-1 z-3 rounded-4 overflow-hidden" 
             style="max-height: 250px; min-width: 200px;">
            <div class="p-2 bg-white sticky-top border-bottom">
                <div class="input-group input-group-sm">
                    <span class="input-group-text border-0 bg-light"><i class="fas fa-search opacity-50"></i></span>
                    <input type="text" v-model="searchQuery" class="form-control border-0 bg-light" 
                        placeholder="Search icon..." @click.stop>
                </div>
            </div>
            <div class="p-2 overflow-y-auto bg-white custom-scrollbar" style="max-height: 180px;">
                <div class="row g-1 m-0">
                    <div v-for="icon in filteredIcons" :key="icon" class="col-3 p-1 text-center">
                        <button type="button" 
                            class="btn btn-light border-0 w-100 p-2 rounded-3 transition-all"
                            :class="{ 'bg-primary text-white': modelValue === icon }"
                            @click.stop="selectIcon(icon)"
                            :title="icon">
                            <i :class="['fas', icon]" style="font-size: 1.1rem;"></i>
                        </button>
                    </div>
                    <div v-if="filteredIcons.length === 0" class="text-center py-3 text-muted small">
                        No icons found.
                    </div>
                </div>
            </div>
        </div>
    </div>
    `
};
export default IconPicker;