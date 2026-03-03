import { message_list, create_message } from '/static/js/toaster.js';

const DeleteRuleModal = {
    name: 'DeleteRuleModal',
    props: {
        rule: { type: Object, required: true },
        modalId: { type: String, required: true }
    },
    delimiters: ['[[', ']]'],
    emits: ['deleted'],
    setup(props, { emit }) {
        const isDeleting = Vue.ref(false);

        const confirmDelete = async () => {
            if (isDeleting.value) return;
            isDeleting.value = true;
            
            try {
                const response = await fetch(`/rule/delete_rule?id=${props.rule.id}`, {
                    method: 'GET' 
                });

                if (response.ok) {
                    
                    const modalEl = document.getElementById(props.modalId);
                    let modalInstance = bootstrap.Modal.getInstance(modalEl);
                    
                  
                    if (!modalInstance) {
                        modalInstance = new bootstrap.Modal(modalEl);
                    }
                    
                    modalInstance.hide();

                    //create_message("Rule deleted successfully", "success-subtle");
                    

                    setTimeout(() => {
                        emit('deleted', props.rule.id);
                    }, 300);

                } else {
                    const errorData = await response.json();
                    //create_message(errorData.message || "Error", "danger-subtle");
                }
            } catch (error) {
                
                //create_message("Connection error. Please try again.", "danger-subtle");
            } finally {
                isDeleting.value = false;
            }
        };

        return {
            confirmDelete,
            isDeleting,
            message_list
        };
    },
    template: `
    
    <div class="modal fade" :id="modalId" tabindex="-1" aria-hidden="true" data-bs-backdrop="static">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content border-0 shadow-lg" style="border-radius: 15px;">
                <div class="modal-header border-0 pb-0">
                    <h5 class="modal-title fw-bold">Confirm Deletion</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" :disabled="isDeleting"></button>
                </div>
                <div class="modal-body py-4 text-center">
                    <div class="text-danger mb-3">
                        <i v-if="isDeleting" class="fas fa-spinner fa-spin fa-3x"></i>
                        <i v-else class="fas fa-exclamation-triangle fa-3x"></i>
                    </div>
                    <p class="mb-0 text-dark">
                        Are you sure you want to delete <br>
                        <strong class="text-danger">[[ rule.title || rule.component_name ]]</strong>?
                    </p>
                </div>
                <div class="modal-footer border-0 pt-0 justify-content-center pb-4">
                    <button type="button" class="btn btn-light rounded-pill px-4 border" 
                            data-bs-dismiss="modal" :disabled="isDeleting">
                        Cancel
                    </button>
                    <button class="btn btn-danger rounded-pill px-4 shadow-sm fw-bold" 
                            @click="confirmDelete" :disabled="isDeleting">
                        <span v-if="isDeleting">
                            <i class="fas fa-spinner fa-spin me-1"></i>
                        </span>
                        <span v-else>Confirm Delete</span>
                    </button>
                </div>
            </div>
        </div>
    </div>
    `
};

export default DeleteRuleModal;