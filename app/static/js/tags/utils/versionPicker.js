const VersionPicker = {
    props: {
        modelValue: { type: String, default: '1.0' },
        label: { type: String, default: 'Version' }
    },
    emits: ['update:modelValue'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const changeVersion = (step) => {
            let current = props.modelValue || "1.0";
            if (!current.includes('.')) current += '.0';

            let [major, minor] = current.split('.').map(num => parseInt(num) || 0);
            minor += step;

            if (minor >= 10) {
                minor = 0;
                major++;
            } else if (minor < 0) {
                if (major > 1) {
                    minor = 9;
                    major--;
                } else {
                    major = 1;
                    minor = 0;
                }
            }

            if (major < 1) { major = 1; minor = 0; }
            emit('update:modelValue', `${major}.${minor}`);
        };

        return { changeVersion };
    },
    template: `
    <div class="form-group">
        <label class="form-label fw-bold text-dark mb-1">[[ label ]]</label>
        <div class="input-group shadow-sm  rounded-3 overflow-hidden">
            <button @click="changeVersion(-1)" 
                class="btn btn-dark rounded-0 border-0 " 
                type="button"
                :disabled="modelValue === '1.0'">
                <i class="fas fa-minus"></i>
            </button>
            <input type="text" 
                :value="modelValue" 
                class="form-control border-0 text-center fw-bold shadow-none"  style="background-color: var(--bg-color)"
                readonly>   
            <button @click="changeVersion(1)" 
                class="btn btn-primary rounded-0 border-0" 
                type="button">
                <i class="fas fa-plus"></i>
            </button>
        </div>
    </div>
    `
};

export default VersionPicker;