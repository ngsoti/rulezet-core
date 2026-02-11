import TagCreateModal from './tagCreateModal.js';

const ListMyTags = {
    components: {
        'tag-create-modal': TagCreateModal
    },
    props: {
        csrf: { type: String, required: true }
    },
    emits: ['edit-tag', 'tag-deleted', 'tag-created-success'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const tags = Vue.ref([]);
        const loading = Vue.ref(false);
        const searchQuery = Vue.ref('');
        const tagToDelete = Vue.ref(null);
        const isDeleting = Vue.ref(false);

       

        const fetchMyTags = async () => {
            loading.value = true;
            try {
                const response = await fetch('/tags/get_my_tags');
                if (response.ok) {
                    tags.value = await response.json();
                }
            } finally {
                loading.value = false;
            }
        };

        const openCreateModal = () => {
            const modalElement = document.getElementById('add_tag_modal_');
            if (modalElement) {
                const modalInstance = bootstrap.Modal.getOrCreateInstance(modalElement);
                modalInstance.show();
            }
        };

        const handleTagCreated = (newTag) => {
            fetchMyTags(); 
            emit('tag-created-success'); 
        };

        const confirmDelete = (tag) => {
            tagToDelete.value = tag;
            const modalElement = document.getElementById('delete_tag_modal_');
            if (modalElement) {
                const modalInstance = bootstrap.Modal.getOrCreateInstance(modalElement);
                modalInstance.show();
            }
        };

        const executeDelete = async () => {
            if (!tagToDelete.value) return;
            isDeleting.value = true;
            try {
                const response = await fetch(`/tags/delete_tag/${tagToDelete.value.id}`, {
                    method: 'POST',
                    headers: { 'X-CSRFToken': props.csrf }
                });
                if (response.ok) {
                    const deletedId = tagToDelete.value.id;
                    const modalElement = document.getElementById('delete_tag_modal_');
                    const modalInstance = bootstrap.Modal.getInstance(modalElement);
                    if (modalInstance) modalInstance.hide();
                    tags.value = tags.value.filter(t => t.id !== deletedId);
                    emit('tag-deleted', deletedId);
                }
            } catch (error) {
                console.error(error);
            } finally {
                isDeleting.value = false;
                tagToDelete.value = null;
            }
        };

        const getContrastYIQ = (hex) => {
            if (!hex) return '#000';
            const r = parseInt(hex.substr(1, 2), 16), g = parseInt(hex.substr(3, 2), 16), b = parseInt(hex.substr(5, 2), 16);
            return ((r * 299) + (g * 587) + (b * 114)) / 1000 >= 128 ? '#000' : '#fff';
        };

        const filteredTags = Vue.computed(() => {
            return tags.value.filter(t => t.name.toLowerCase().includes(searchQuery.value.toLowerCase()));
        });

        Vue.onMounted(fetchMyTags);

        return { 
            tags, loading, searchQuery, filteredTags, 
            confirmDelete, executeDelete, tagToDelete, isDeleting,
            getContrastYIQ, fetchMyTags, openCreateModal, handleTagCreated 
        };
    },
    template: `
    <div class="card border-0 shadow-lg p-4 mb-4" style="border-radius: 12px;">
        <div class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-4">
            <div class="d-flex align-items-center gap-3 flex-grow-1" style="max-width: 500px;">
                <div class="input-group shadow-sm rounded-pill">
                    <span class="input-group-text border-0 bg-white ps-3"><i class="fas fa-search text-muted"></i></span>
                    <input type="text" v-model="searchQuery" class="form-control border-0 bg-white shadow-none" placeholder="Search my tags...">
                </div>
            </div>
            
            <button class="btn btn-primary rounded-pill px-4 shadow-sm fw-bold" @click="openCreateModal">
                <i class="fas fa-plus me-2"></i> Add New Tag
            </button>
        </div>

        <div class="table-responsive" style="overflow: visible;">
            <table class="table align-middle">
                <thead class="text-secondary small text-uppercase">
                    <tr>
                        <th class="border-0">Tag Appearance</th>
                        <th class="border-0">Description</th>
                        <th class="border-0">Created At</th>
                        <th class="border-0">Visibility</th>
                        <th class="border-0 text-end">Actions</th>
                    </tr>
                </thead>
                <tbody class="border-top-0">
                    <tr v-if="loading">
                        <td colspan="5" class="text-center py-5">
                            <div class="spinner-border text-primary mb-2" role="status"></div>
                            <p class="text-muted small">Loading your tags...</p>
                        </td>
                    </tr>
                    <tr v-else v-for="tag in filteredTags" :key="tag.id">
                        <td>
                            <div class="tag-wrapper">
                                <span class="tag-split shadow-sm on-hover-zoom">
                                    <span class="tag-left">
                                        <i :class="['fas', tag.icon || 'fa-tag']"></i>
                                    </span>
                                    <span class="tag-right" :style="{ backgroundColor: tag.color }">
                                        <span :style="{ color: getContrastYIQ(tag.color) }">
                                            [[ tag.name ]]
                                        </span>
                                    </span>
                                </span>
                                
                                <div class="tag-tooltip">
                                    <div class="hover-bridge"></div>
                                    <div class="tooltip-header" :style="{ borderLeft: '4px solid ' + tag.color }">
                                        <i :class="['fas', tag.icon || 'fa-tag', 'me-2 text-white']"></i>
                                        <strong class="text-white">[[ tag.name ]]</strong>
                                    </div>
                                    <div class="tooltip-body">
                                        <div class="description-container">
                                            <div class="description-scroll text-white-50">
                                                [[ tag.description || 'No description provided.' ]]
                                            </div>
                                        </div>
                                        <div class="d-flex justify-content-between mt-2 pt-2 border-top border-white border-opacity-10 small">
                                            <span class="text-white-50">
                                                <i :class="['fas', tag.visibility === 'Public' ? 'fa-globe' : 'fa-lock', 'me-1']"></i>
                                                [[ tag.visibility ]]
                                            </span>
                                            <span v-if="tag.created_at" class="text-white-50">
                                                <i class="fas fa-calendar-alt me-1"></i>
                                                [[ tag.created_at ]]
                                            </span>
                                        </div>
                                    </div>
                                    <div class="tooltip-arrow"></div>
                                </div>
                            </div>
                        </td>
                        <td>
                            <small class="text-muted d-inline-block text-truncate" style="max-width: 200px;">
                                [[ tag.description || 'No description' ]]
                            </small>
                        </td>
                        <td><small class="text-muted small">[[ tag.created_at ]]</small></td>
                        <td>
                            <span :class="['badge rounded-pill shadow-sm px-3', tag.visibility === 'Public' ? 'bg-success text-white' : 'bg-danger text-white']">
                                [[ tag.visibility ]]
                            </span>
                        </td>
                        <td class="text-end">
                            <button class="btn btn-sm btn-light rounded-circle border shadow-sm me-1" @click="$emit('edit-tag', tag)" title="Edit">
                                <i class="fas fa-edit text-primary"></i>
                            </button>
                            <button class="btn btn-sm btn-light rounded-circle border shadow-sm" @click="confirmDelete(tag)" title="Delete">
                                <i class="fas fa-trash text-danger"></i>
                            </button>
                        </td>
                    </tr>
                    <tr v-if="!loading && filteredTags.length === 0">
                        <td colspan="5" class="text-center py-5 text-muted small">No tags found.</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <tag-create-modal :csrf="csrf" @tag-created="handleTagCreated"></tag-create-modal>

        <div class="modal fade" id="delete_tag_modal_" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered modal-sm">
                <div class="modal-content border-0 shadow-lg rounded-4">
                    <div class="modal-body p-4 text-center">
                        <div class="mb-3 text-danger">
                            <i class="fas fa-exclamation-circle fa-3x animate__animated animate__pulse animate__infinite"></i>
                        </div>
                        <h5 class="fw-bold">Confirm Deletion</h5>
                        <p class="text-muted small">
                            Delete <span v-if="tagToDelete" class="fw-bold" :style="{ color: tagToDelete.color }">[[ tagToDelete.name ]]</span>?
                        </p>
                        <div class="d-flex gap-2 mt-4">
                            <button type="button" class="btn btn-light rounded-pill w-100 fw-bold border" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-danger rounded-pill w-100 fw-bold shadow-sm" @click="executeDelete" :disabled="isDeleting">
                                <span v-if="isDeleting" class="spinner-border spinner-border-sm me-1"></span>
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    `
};

export default ListMyTags;