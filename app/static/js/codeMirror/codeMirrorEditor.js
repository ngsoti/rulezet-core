const CodeMirrorEditor = {
    props: {
        modelValue: { type: String, default: '' },
        mode: { type: String, default: 'yaml' },
        theme: { type: String, default: 'monokai' },
        height: { type: String, default: '450px' }
    },
    emits: ['update:modelValue'],
    setup(props, { emit }) {
        const textareaRef = Vue.ref(null);
        let editor = null;

      
        const cleanValue = (val) => {
            if (!val) return '';
            let cleaned = val;
          
            if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
                cleaned = cleaned.substring(1, cleaned.length - 1);
            }
            
           
            return cleaned.replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\'/g, "'");
        };

        Vue.onMounted(() => {
            if (textareaRef.value) {
                const initialContent = cleanValue(props.modelValue);
                console.log(initialContent);
                textareaRef.value.value = initialContent;

                editor = CodeMirror.fromTextArea(textareaRef.value, {
                    lineNumbers: true,
                    mode: props.mode,
                    theme: props.theme,
                    lineWrapping: true,
                    autoRefresh: true
                });

                editor.setSize("100%", props.height);

                if (initialContent) {
                    editor.setValue(initialContent);
                }

                editor.on("change", (cm) => {
                  
                    emit('update:modelValue', cm.getValue());
                });

                setTimeout(() => {
                    editor.refresh();
                }, 200);
            } 
        });

        Vue.watch(() => props.modelValue, (newVal) => {     
            if (editor) {
                const currentVal = editor.getValue();
                const incomingVal = cleanValue(newVal);
                if (incomingVal !== currentVal) {
                    editor.setValue(incomingVal);
                }
            }
        });

        return { textareaRef };
    },
    template: `
        <div class="codemirror-container border rounded shadow-sm">
            <textarea ref="textareaRef"></textarea>
        </div>
    `
};

export default CodeMirrorEditor;