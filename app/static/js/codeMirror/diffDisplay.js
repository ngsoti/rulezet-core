import '/static/js/codeMirror/diffLibrary.js'; 

const DiffDisplay = {
    props: {
        uniqueId: { type: String, required: true },
        oldText: { type: String, default: '' },
        newText: { type: String, default: '' },
        oldName: { type: String, default: 'Original' },
        newName: { type: String, default: 'Modified' },
        displayMode: { type: String, default: 'side-by-side' },
        maxHeight: { type: String, default: 'none' }
    },
    delimiters: ['[[', ']]'],
    setup(props) {
        // État pour la visibilité des couleurs
        const showColors = Vue.ref(true);

        const isIdentical = Vue.computed(() => {
            return (props.oldText || "").trim() === (props.newText || "").trim();
        });

        const toggleColors = () => {
            showColors.value = !showColors.value;
        };

        const renderUI = () => {
            Vue.nextTick(() => {
                const target = document.getElementById(`diff-target-${props.uniqueId}`);
                
                if (!target || typeof Diff2HtmlUI === 'undefined' || typeof Diff === 'undefined') {
                    console.warn("Diff libraries not fully loaded yet.");
                    return;
                }

                target.innerHTML = "";

                if (isIdentical.value) {
                    const container = document.createElement('div');
                    container.className = "identical-code-view p-3";
                    
                    const alert = document.createElement('div');
                    alert.className = "alert alert-success-light border-0 py-2 px-3 mb-3 small d-flex align-items-center";
                    alert.innerHTML = `<i class="fas fa-check-double me-2"></i> <strong>Exact Match:</strong> This logic is 100% identical.`;
                    
                    const pre = document.createElement('pre');
                    pre.className = "hljs p-3 rounded bg-gray-50 border shadow-inner mb-0";
                    pre.style.fontSize = "0.85rem";
                    pre.style.overflow = "auto";
                    pre.textContent = props.oldText;

                    container.appendChild(alert);
                    container.appendChild(pre);
                    target.appendChild(container);
                } else {
                    const patch = Diff.createPatch(
                        props.newName, 
                        props.oldText || "", 
                        props.newText || "", 
                        props.oldName, 
                        props.newName
                    );

                    const ui = new Diff2HtmlUI(target, patch, {
                        outputFormat: props.displayMode,
                        drawFileList: false,
                        matching: "lines", 
                        synchronisedScroll: true, 
                        highlight: true,
                        renderNothingWhenEmpty: false
                    });
                    
                    ui.draw();
                    ui.highlightCode();
                }
            });
        };

        Vue.onMounted(renderUI);
        Vue.watch(() => [props.oldText, props.newText, props.displayMode], renderUI);

        return { isIdentical, showColors, toggleColors };
    },
    template: `
    <div class="diff-outer-container shadow-sm border rounded d-flex flex-column" 
         :class="{ 'hide-diff-colors': !showColors }"
         :style="{ maxHeight: maxHeight, minHeight: '200px' }">
        
        <div class="diff-header-info d-flex justify-content-between align-items-center px-3 py-2 bg-light border-bottom small fw-bold text-secondary">
            <div class="d-flex align-items-center gap-3">
                <span><i class="fas fa-file-alt me-1"></i> [[ oldName ]]</span>
                
                <button @click="toggleColors" class="btn btn-sm btn-outline-secondary py-0 px-2" style="font-size: 0.7rem;">
                    <i :class="showColors ? 'fas fa-eye-slash' : 'fas fa-eye'"></i>
                    <span class="ms-1">[[ showColors ? 'Hide Colors' : 'Show Colors' ]]</span>
                </button>
            </div>

            <span v-if="isIdentical"><i class="fas fa-equals me-1"></i> IDENTICAL CONTENT</span>
            
            <span>[[ newName ]] <i class="fas fa-file-edit ms-1"></i></span>
        </div>
        
        <div class="flex-grow-1 overflow-auto">
            <div :id="'diff-target-' + uniqueId" >
                <div class="text-center p-3 text-muted italic">
                    <i class="fas fa-spinner fa-spin me-2"></i> Loading comparison...
                </div>
            </div>
        </div>

        
    </div>
    `
};

export default DiffDisplay;