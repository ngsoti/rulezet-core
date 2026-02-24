import '/static/js/codeMirror/diffLibrary.js'; 

const DiffDisplay = {
    props: {
        uniqueId: { type: String, required: true },
        oldText: { type: String, default: '' },
        newText: { type: String, default: '' },
        oldName: { type: String, default: 'Original' },
        newName: { type: String, default: 'Modified' },
        displayMode: { type: String, default: 'side-by-side' },
        maxHeight: { type: String, default: '850px' }
    },
    delimiters: ['[[', ']]'],
    setup(props) {
        const renderUI = () => {
            Vue.nextTick(() => {
                const target = document.getElementById(`diff-target-${props.uniqueId}`);
                
                if (!target || typeof Diff2HtmlUI === 'undefined' || typeof Diff === 'undefined') {
                    console.warn("Diff libraries not fully loaded yet.");
                    return;
                }

                const patch = Diff.createPatch(
                    props.newName, 
                    props.oldText || "", 
                    props.newText || "", 
                    props.oldName, 
                    props.newName
                );

                target.innerHTML = "";

                const ui = new Diff2HtmlUI(target, patch, {
                    outputFormat: props.displayMode,
                    drawFileList: false,
                    matching: "lines", 
                    synchronisedScroll: true, 
                    highlight: true,
                    renderNothingWhenEmpty: false,
                    // colorScheme: "auto"
                    
                });
                
                ui.draw();
                ui.highlightCode();

                const isIdentical = (props.oldText || "").trim() === (props.newText || "").trim();
                if (isIdentical) {
                    const msgDiv = document.createElement('div');
                    msgDiv.className = "alert alert-success mx-3 my-2 text-center shadow-sm";
                    msgDiv.innerHTML = `<i class="fas fa-check-circle me-2"></i> <strong>No changes found:</strong> These rules are identical.`;
                    target.prepend(msgDiv);
                }
            });
        };

        Vue.onMounted(renderUI);
        Vue.watch(() => [props.oldText, props.newText, props.displayMode], renderUI);

        return {};
    },
    template: `
    <div class="diff-outer-container shadow-sm border rounded d-flex flex-column" :style="{ maxHeight: maxHeight, minHeight: '200px' }">
        <div class="diff-header-info d-flex justify-content-between px-3 py-2 bg-light border-bottom small fw-bold text-secondary">
            <span><i class="fas fa-file-alt me-1"></i> [[ oldName ]]</span>
            <span>[[ newName ]] <i class="fas fa-file-edit ms-1"></i></span>
        </div>
        
        <div class="modern-diff-view-scroll-wrapper bg-white flex-grow-1">
            <div :id="'diff-target-' + uniqueId" class="modern-diff-view-content">
                <div class="text-center p-3 text-muted italic">
                    <i class="fas fa-spinner fa-spin me-2"></i> Loading comparison...
                </div>
            </div>
        </div>

        <style>

        </style>
    </div>
    `
};

export default DiffDisplay;