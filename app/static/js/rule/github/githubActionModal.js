const GithubActionModal = {
    props: {
        modalId: { type: String, default: 'githubActionModal' },
        title: { type: String, default: 'Confirm Action' },
        icon: { type: String, default: 'fa-gear' },
        variant: { type: String, default: 'primary' },
        confirmText: { type: String, default: 'Confirm' },
        selectedCount: { type: Number, default: 0 },
        actionType: { type: String, required: true },
        payload: { type: Object, default: () => ({}) },
        endpoint: { type: String, required: true },
        csrfToken: { type: String, required: true }
    },
    emits: ['success', 'error'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const status = Vue.ref('idle');
        const message = Vue.ref('');

        const runAction = async () => {
            status.value = 'loading';
            
            try {
                const response = await fetch(props.endpoint, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json', 
                        'X-CSRFToken': props.csrfToken 
                    },
                    body: JSON.stringify({
                        action: props.actionType,
                        ...props.payload
                    })
                });

                if (!response.ok) {
                    // If the response is not 200/202, try to get the error message from JSON
                    const errorData = await response.json();
                    throw new Error(errorData.message || 'An error occurred');
                }

                // --- LOGIC FOR EXPORT (ZIP DOWNLOAD) ---
                if (props.actionType === 'export') {
                    const blob = await response.blob();
                    
                    // Create a hidden link to trigger the browser download
                    const url = window.URL.createObjectURL(blob);
                    const link = document.createElement('a');
                    link.href = url;
                    
                    // Format filename with current date
                    const date = new Date().toISOString().split('T')[0];
                    link.setAttribute('download', `github_export_${date}.zip`);
                    
                    document.body.appendChild(link);
                    link.click();
                    
                    // Cleanup
                    link.parentNode.removeChild(link);
                    window.URL.revokeObjectURL(url);

                    status.value = 'success';
                    message.value = 'Your ZIP archive is downloading...';
                } 
                // --- LOGIC FOR DELETE OR OTHER JSON ACTIONS ---
                else {
                    const result = await response.json();
                    status.value = 'success';
                    message.value = result.message || 'Action completed successfully';
                }

                // Finalize and close modal
                setTimeout(() => {
                    const modalEl = document.getElementById(props.modalId);
                    const modal = bootstrap.Modal.getInstance(modalEl);
                    if (modal) modal.hide();
                    
                    emit('success', { type: props.actionType });
                    setTimeout(() => { status.value = 'idle'; }, 500);
                }, 2000);

            } catch (err) {
                status.value = 'error';
                message.value = err.message;
                emit('error', err);
            }
        };

        return { status, message, runAction };
    },
    template: `
    <teleport to="body">
        <div class="modal fade" :id="modalId" tabindex="-1" aria-hidden="true" style="z-index: 2050;">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content border-0 shadow-lg" style="border-radius: 20px;">
                    <div class="modal-header border-0 pb-0">
                        <h5 class="modal-title fw-bold" :class="'text-' + variant">
                            <i class="fa-solid me-2" :class="icon"></i> [[ title ]]
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" :disabled="status === 'loading'"></button>
                    </div>
                    <div class="modal-body p-4 text-center">
                        <div v-if="status === 'idle'">
                            <div class="rounded-circle p-4 d-inline-block mb-3" :class="'bg-' + variant + '-subtle text-' + variant">
                                <i class="fa-solid fa-2xl" :class="icon"></i>
                            </div>
                            <h5 class="fw-bold mb-2">Confirm this action?</h5>
                            <p class="text-muted">
                                You are applying this to 
                                <span class="badge bg-dark rounded-pill px-3">[[ selectedCount ]]</span> 
                                items.
                            </p>
                            <slot name="description"></slot>
                            <div class="d-grid gap-2 mt-4">
                                <button @click="runAction" class="btn rounded-pill py-2 fw-bold shadow-sm" :class="'btn-' + variant">
                                    [[ confirmText ]]
                                </button>
                                <button class="btn btn-link text-muted text-decoration-none small" data-bs-dismiss="modal">
                                    Cancel
                                </button>
                            </div>
                        </div>
                        <div v-if="status === 'loading'" class="py-4 animate__animated animate__fadeIn">
                            <div class="spinner-border mb-3" :class="'text-' + variant" style="width: 3rem; height: 3rem;" role="status"></div>
                            <h6 class="fw-bold text-uppercase">[[ actionType === 'export' ? 'Generating ZIP...' : 'Processing Request...' ]]</h6>
                            <p class="text-muted small">Please wait while we notify the server.</p>
                        </div>
                        <div v-if="status === 'success'" class="py-4 animate__animated animate__zoomIn">
                            <div class="bg-success-subtle text-success rounded-circle p-4 d-inline-block mb-3">
                                <i class="fa-solid fa-check fa-2xl"></i>
                            </div>
                            <h5 class="fw-bold text-success">Done!</h5>
                            <p class="text-muted">[[ message ]]</p>
                        </div>
                        <div v-if="status === 'error'" class="py-4">
                            <div class="bg-danger-subtle text-danger rounded-circle p-4 d-inline-block mb-3">
                                <i class="fa-solid fa-xmark fa-2xl"></i>
                            </div>
                            <h5 class="fw-bold text-danger">Action Failed</h5>
                            <p class="text-muted">[[ message ]]</p>
                            <button @click="status = 'idle'" class="btn btn-outline-secondary btn-sm rounded-pill px-4">Try Again</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </teleport>
    `
};

export default GithubActionModal;