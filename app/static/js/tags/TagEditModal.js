import IconPicker from './utils/iconPicker.js'; 

const TagEditModal = {
    components: { IconPicker },
    props: {
        csrf: { type: String, required: true },
        tagData: { type: Object, default: null }
    },
    emits: ['tag-updated', 'server-message'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const editTag = Vue.ref({ ...props.tagData });
        const isSubmitting = Vue.ref(false);
        const errorMessage = Vue.ref('');

        Vue.watch(() => props.tagData, (newVal) => {
            if (newVal) {
                editTag.value = { ...newVal };
                errorMessage.value = '';
            }
        });

        const updateTag = async () => {
            if (!editTag.value.name?.trim()) {
                errorMessage.value = "Tag name cannot be empty.";
                return;
            }

            errorMessage.value = '';
            isSubmitting.value = true;
            try {
                const response = await fetch(`/tags/edit_tag/${editTag.value.id}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrf },
                    body: JSON.stringify(editTag.value)
                });

                const result = await response.json();

                if (response.status === 200) {
                    const modalElement = document.getElementById('edit_tag_modal_');
                    const modal = bootstrap.Modal.getOrCreateInstance(modalElement);
                    modal.hide();
                    emit('tag-updated', { tag: result.tag || editTag.value, message: result.message, type: 'success-subtle' });
                } else {
                    errorMessage.value = result.message || "An error occurred.";
                }
            } catch (e) {
                errorMessage.value = "Connection error.";
            } finally {
                isSubmitting.value = false;
            }
        };

        return { editTag, updateTag, isSubmitting, errorMessage };
    },
    template: `
    <div class="modal fade" id="edit_tag_modal_" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered modal-lg">
            <div class="modal-content border-0 shadow-lg rounded-4">
                <div class="modal-header border-0 pb-0 pt-4 px-4">
                    <div class="d-flex align-items-center gap-3">
                        <div class="rounded-circle d-flex align-items-center justify-content-center shadow-sm"
                            :style="{ backgroundColor: editTag.color, width: '52px', height: '52px', color: 'white' }">
                            <i :class="['fa', editTag.icon || 'fa-tag']" style="font-size: 1.4rem;"></i>
                        </div>
                        <div>
                            <h5 class="modal-title fw-bold mb-0">Edit Tag</h5>
                            <p class="text-muted small mb-0">[[ editTag.name ]]</p>
                        </div>
                    </div>
                    <button type="button" class="btn-close shadow-none" data-bs-dismiss="modal"></button>
                </div>

                <div class="modal-body p-4">
                    <div v-if="errorMessage" class="alert alert-warning border-0 shadow-sm d-flex align-items-center mb-3 py-2 small">
                        <i class="fas fa-exclamation-triangle me-2"></i> [[ errorMessage ]]
                    </div>

                    <div class="row g-3">
                        <div class="col-md-7">
                            <label class="form-label fw-bold small text-muted text-uppercase mb-1">Tag Name</label>
                            <div class="input-group shadow-sm rounded-3">
                                <span class="input-group-text border-0 bg-light"><i class="fas fa-signature text-muted"></i></span>
                                <input type="text" class="form-control border-0 bg-light" v-model="editTag.name" style="height: 45px;">
                            </div>
                        </div>

                        <div class="col-md-5">
                            <icon-picker v-model="editTag.icon"></icon-picker>
                        </div>

                        <div class="col-12">
                            <label class="form-label fw-bold small text-muted text-uppercase mb-1">Description</label>
                            <textarea class="form-control border-0 bg-light rounded-3 p-3 shadow-sm" rows="3" v-model="editTag.description"></textarea>
                        </div>

                        <div class="col-md-12">
                            <label class="form-label fw-bold small text-muted text-uppercase mb-1">Color</label>
                            <div class="d-flex align-items-center bg-light rounded-3 p-1 shadow-sm">
                                <input type="color" class="form-control form-control-color border-0 bg-transparent" v-model="editTag.color" style="width: 45px; height: 35px;">
                                <input type="text" class="form-control border-0 bg-transparent py-0 small text-muted font-monospace" v-model="editTag.color">
                            </div>
                        </div>
                    </div>
                </div>

                <div class="modal-footer border-0 p-4 pt-0">
                    <button class="btn btn-link text-decoration-none fw-bold text-muted px-4" data-bs-dismiss="modal">Cancel</button>
                    <button class="btn btn-primary rounded-pill px-5 fw-bold shadow" @click="updateTag" :disabled="isSubmitting">
                        <span v-if="isSubmitting" class="spinner-border spinner-border-sm me-2"></span>
                        <i v-else class="fas fa-save me-2"></i> Save Changes
                    </button>
                </div>
            </div>
        </div>
    </div>
    `
};
export default TagEditModal;