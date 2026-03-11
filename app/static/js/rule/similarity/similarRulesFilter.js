const SimilarRulesFilter = {
    name: 'SimilarRulesFilter',
    props: {
        score: { type: Number, default: 0.80 },
        format: { type: String, default: '' },
        sourceMode: { type: String, default: 'all' }, // New: all, same, different
        authorMode: { type: String, default: 'all' }  // New: all, same, different
    },
    emits: ['update:score', 'update:format', 'update:sourceMode', 'update:authorMode', 'filter'],
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
            val = Math.max(0, Math.min(100, val));
            emit('update:score', parseFloat((val / 100).toFixed(2)));
        };

        const stopEditing = () => {
            isEditing.value = false;
            emit('filter');
        };

        const startEditing = () => {
            isEditing.value = true;
            Vue.nextTick(() => {
                const input = document.getElementById('scoreInput');
                if (input) input.focus();
            });
        };

        const apply = () => emit('filter');

        const reset = () => {
            emit('update:score', 0.80);
            emit('update:format', '');
            emit('update:sourceMode', 'all');
            emit('update:authorMode', 'all');
            setTimeout(() => emit('filter'), 0);
        };

        Vue.onMounted(fetchFormats);

        return { formats, apply, reset, onInputText, isEditing, stopEditing, startEditing };
    },
    template: `
    <div class="card border-0 shadow-sm rounded-4 mb-4" style="background-color: var(--card-bg-color);">
        <div class="card-body p-4">
            <div class="row g-3 align-items-end">
                <div class="col-md-7">
                    <label class="small fw-bold text-muted mb-2 text-uppercase d-block">
                        <i class="fa-solid fa-chart-line me-1 text-primary"></i> Min. Similarity
                    </label>
                    <div class="d-flex align-items-center gap-3 p-2 px-3 rounded-pill border">
                        <input type="range" class="range flex-grow-1" min="0.00" max="1.00" step="0.01" 
                            :value="score" @input="$emit('update:score', parseFloat($event.target.value))" @change="apply">
                        <div @click="startEditing" class="d-flex align-items-center justify-content-center bg-primary text-white rounded-pill shadow-sm" 
                             style="width: 70px; height: 32px; cursor: pointer;">
                            <span v-if="!isEditing" class="fw-bold" style="font-size: 0.85rem;">[[ (score * 100).toFixed(0) ]]%</span>
                            <input v-else id="scoreInput" type="number" class="bg-transparent border-0 text-white text-center fw-bold w-100" 
                                :value="(score * 100).toFixed(0)" @input="onInputText" @blur="stopEditing" @keyup.enter="stopEditing">
                        </div>
                    </div>
                </div>

                <div class="col-md-5">
                    <label class="small fw-bold text-muted mb-2 text-uppercase d-block">Rule Format</label>
                    <select :value="format" @change="$emit('update:format', $event.target.value); apply()" class="form-select rounded-pill border shadow-none">
                        <option value="">All Formats</option>
                        <option v-for="f in formats" :key="f.id" :value="f.name">[[ f.name.toUpperCase() ]]</option>
                    </select>
                </div>

                <div class="col-md-5">
                    <label class="small fw-bold text-muted mb-2 text-uppercase d-block">Source Origin</label>
                    <select :value="sourceMode" @change="$emit('update:sourceMode', $event.target.value); apply()" class="form-select rounded-pill border shadow-none">
                        <option value="all">Any Source</option>
                        <option value="same">Same Source</option>
                        <option value="different">Different Source</option>
                    </select>
                </div>

                <div class="col-md-5">
                    <label class="small fw-bold text-muted mb-2 text-uppercase d-block">Creator</label>
                    <select :value="authorMode" @change="$emit('update:authorMode', $event.target.value); apply()" class="form-select rounded-pill border shadow-none">
                        <option value="all">Any Creator</option>
                        <option value="same">Same Creator</option>
                        <option value="different">Different Creator</option>
                    </select>
                </div>

                <div class="col-md-2 text-end">
                    <button class="btn btn-light rounded-pill px-4 border" @click="reset">
                        <i class="fa-solid fa-rotate-left me-1"></i> Reset
                    </button>
                </div>
            </div>
        </div>
    </div>
    `
};
export default SimilarRulesFilter;