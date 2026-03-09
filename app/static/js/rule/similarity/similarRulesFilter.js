const SimilarRulesFilter = {
    name: 'SimilarRulesFilter',
    props: {
        score: { type: Number, default: 0.80 },
        format: { type: String, default: '' },
    },
    emits: ['update:score', 'update:format', 'filter'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const formats = Vue.ref([]);
        const isEditing = Vue.ref(false);
        
        const fetchFormats = async () => {
            try {
                const res = await fetch('/rule/get_rules_formats');
                const data = await res.json();
                formats.value = data.formats || [];
            } catch (e) { console.error(e); }
        };

        const onInputText = (e) => {
            let val = parseInt(e.target.value);
            if (isNaN(val)) return;
            if (val < 0) val = 0;
            if (val > 100) val = 100;
            emit('update:score', parseFloat((val / 100).toFixed(2)));
        };

        const stopEditing = () => {
            isEditing.value = false;
            emit('filter');
        };

        const startEditing = () => {
            isEditing.value = true;
            // On attend que le DOM s'actualise pour mettre le focus
            Vue.nextTick(() => {
                const input = document.getElementById('scoreInput');
                if (input) input.focus();
            });
        };

        const apply = () => emit('filter');

        const reset = () => {
            emit('update:score', 0.80);
            emit('update:format', '');
            setTimeout(() => emit('filter'), 0);
        };

        Vue.onMounted(fetchFormats);

        return { formats, apply, reset, onInputText, isEditing, stopEditing, startEditing };
    },
    template: `
    <div class="card border-0 shadow-sm rounded-4 mb-4" style="background-color: var(--card-bg-color);">
        <div class="card-body p-4">
            <div class="row g-4 align-items-center">
                <div class="col-md-8">
                    <label class="small fw-bold text-muted mb-2 text-uppercase d-block">
                        <i class="fa-solid fa-chart-line me-1 text-primary"></i> Min. Similarity
                    </label>
                    <div class="d-flex align-items-center gap-3 p-2 px-3 rounded-pill border" style="background-color: var(--bar-bg-color);">
                        <input type="range" 
                            class="form-range flex-grow-1" 
                            min="0.00" 
                            max="1.00" 
                            step="0.01" 
                            :value="score" 
                            @input="$emit('update:score', parseFloat($event.target.value))" 
                            @change="apply">
                        
                        <div @click="startEditing" 
                             class="d-flex align-items-center justify-content-center bg-primary rounded-pill shadow-sm cursor-pointer" 
                             style="width: 75px; height: 32px; min-width: 75px; cursor: pointer; transition: transform 0.2s;">
                            
                            <template v-if="!isEditing">
                                <span class=" fw-bold" style="font-size: 0.9rem;">
                                    [[ (score * 100).toFixed(0) ]] %
                                </span>
                            </template>
                            
                            <template v-else>
                                <div class="d-flex align-items-center justify-content-center">
                                    <input id="scoreInput"
                                        type="number" 
                                        class="border-0   text-center fw-bold" 
                                        :value="(score * 100).toFixed(0)"
                                        @input="onInputText"
                                        @blur="stopEditing"
                                        @keyup.enter="stopEditing"
                                        style="outline: none; font-size: 0.9rem; width: 40px; -moz-appearance: textfield;">
                                    <span class=" fw-bold" style="font-size: 0.8rem; margin-left: -5px;">%</span>
                                </div>
                            </template>
                        </div>
                    </div>
                </div>

                <div class="col-md-3">
                    <label class="small fw-bold text-muted mb-2 text-uppercase d-block">
                        <i class="fa-solid fa-file-code me-1 text-success"></i> Rule Format
                    </label>
                    <select :value="format" @change="$emit('update:format', $event.target.value); apply()" 
                            class="form-select form-select-sm border-0  shadow-none" 
                            style="height: 48px; border-radius: 50px; padding-left: 20px;">
                        <option value="">All Formats</option>
                        <option v-for="f in formats" :key="f.id" :value="f.name">[[ f.name.toUpperCase() ]]</option>
                    </select>
                </div>

                <div class="col-md-1 text-end">
                    <button class="btn btn-outline-secondary border-0 rounded-circle" @click="reset" style="width: 40px; height: 40px;">
                        <i class="fa-solid fa-rotate-left"></i>
                    </button>
                </div>
            </div>
        </div>
    </div>
    `
};

export default SimilarRulesFilter;