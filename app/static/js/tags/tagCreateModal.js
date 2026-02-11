import IconPicker from './utils/iconPicker.js';

const TagCreateModal = {
    components: { IconPicker },
    props: {
        csrf: {
            type: String,
            required: true
        }
    },
    emits: ['tag-created'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const initialState = {
            name: '',
            source: 'Manual', 
            external_id: '',
            description: '',
            color: '#3b82f6',
            icon: 'fa-tag',
            visibility: 'Private'
        };

        const newTag = Vue.ref({ ...initialState });
        const isSubmitting = Vue.ref(false);
        const errorMessage = Vue.ref('');

        const resetForm = () => {
            newTag.value = { ...initialState };
            errorMessage.value = '';
        };

        const saveNewTag = async () => {
            if (!newTag.value.name.trim()) return;
            
            isSubmitting.value = true;
            errorMessage.value = '';
            
            try {
                const response = await fetch('/tags/create_tag', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',  
                        'X-CSRFToken': props.csrf
                    },
                    body: JSON.stringify(newTag.value)
                });

                const result = await response.json();

                if (response.ok) {
                    const modalElement = document.getElementById('add_tag_modal_');
                    const modalInstance = bootstrap.Modal.getOrCreateInstance(modalElement);
                    if (modalInstance) modalInstance.hide();

                    emit('tag-created', result.tag);
                    resetForm();
                } else {
                    errorMessage.value = result.message || "Failed to create tag.";
                }
            } catch (error) {
                errorMessage.value = "Connection error. Please try again.";
            } finally {
                isSubmitting.value = false;
            }
        };

        return {
            newTag,
            saveNewTag,
            isSubmitting,
            resetForm,
            errorMessage
        };
    },
    template: `
    <div class="modal fade" id="add_tag_modal_" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered modal-lg">
            <div class="modal-content border-0 shadow-lg rounded-4">
                
                <div class="modal-header border-0 pb-0 pt-4 px-4">
                    <div class="d-flex align-items-center gap-3">
                        <div class="rounded-circle d-flex align-items-center justify-content-center shadow-sm"
                            :style="{ backgroundColor: newTag.color, width: '52px', height: '52px', color: 'white', transition: 'all 0.3s ease' }">
                            <i :class="['fa', newTag.icon || 'fa-tag']" style="font-size: 1.4rem;"></i>
                        </div>
                        <div>
                            <h5 class="modal-title fw-bold mb-0">Create New Tag</h5>
                            <p class="text-muted small mb-0">Classify and organize your resources</p>
                        </div>
                    </div>
                    <button type="button" class="btn-close shadow-none" data-bs-dismiss="modal" @click="resetForm"></button>
                </div>

                <div class="modal-body p-4">
                    <div v-if="errorMessage" class="alert alert-warning border-0 shadow-sm d-flex align-items-center mb-3 py-2 small">
                        <i class="fas fa-exclamation-triangle me-2"></i> [[ errorMessage ]]
                    </div>

                    <div class="row g-3">
                        <div class="col-md-7">
                            <label class="form-label fw-bold small text-muted text-uppercase mb-1">Tag Name <span class="text-danger">*</span></label>
                            <div class="input-group shadow-sm rounded-3">
                                <span class="input-group-text border-0 bg-light"><i class="fa-solid fa-signature text-muted"></i></span>
                                <input type="text" class="form-control border-0 bg-light" required
                                    v-model="newTag.name" placeholder="Enter tag name..." style="height: 45px;">
                            </div>
                        </div>

                        <div class="col-md-5">
                            <icon-picker v-model="newTag.icon"></icon-picker>
                        </div>

                        <div class="col-md-12">
                            <label class="form-label fw-bold small text-muted text-uppercase mb-1">Source Context</label>
                            <input type="text" class="form-control border-0 bg-light-subtle text-muted rounded-3 px-3 shadow-none" 
                                v-model="newTag.source" readonly style="height: 45px; cursor: not-allowed; border-left: 4px solid #dee2e6 !important;">
                        </div>

                        <div class="col-12">
                            <label class="form-label fw-bold small text-muted text-uppercase mb-1">Description</label>
                            <textarea class="form-control border-0 bg-light rounded-3 p-3 shadow-sm" 
                                rows="3" v-model="newTag.description" placeholder="Briefly describe what this tag represents..."></textarea>
                        </div>

                        <div class="col-md-12">
                            <label class="form-label fw-bold small text-muted text-uppercase mb-1">Brand Color</label>
                            <div class="d-flex align-items-center bg-light rounded-3 p-1 shadow-sm">
                                <input type="color" class="form-control form-control-color border-0 bg-transparent" 
                                    v-model="newTag.color" style="width: 45px; height: 35px;">
                                <input type="text" class="form-control border-0 bg-transparent py-0 small text-muted font-monospace" v-model="newTag.color">
                            </div>
                        </div>
                    </div>
                </div>

                <div class="modal-footer border-0 p-4 pt-0">
                    <button class="btn btn-link text-decoration-none fw-bold text-muted px-4" 
                        data-bs-dismiss="modal" @click="resetForm">Cancel</button>
                    <button class="btn btn-primary rounded-pill px-5 fw-bold shadow" 
                        @click="saveNewTag" :disabled="!newTag.name || isSubmitting">
                        <span v-if="isSubmitting" class="spinner-border spinner-border-sm me-2"></span>
                        <i v-else class="fas fa-check-circle me-2"></i> Create Tag
                    </button>
                </div>

            </div>
        </div>
    </div>
    `
};

export default TagCreateModal;