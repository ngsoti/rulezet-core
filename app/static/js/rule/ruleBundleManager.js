const RuleBundleManager = {
    props: {
        totalRules: Number,
        isOverLimit: Boolean,
        maxLimit: Number,
        filters: Object,
        csrf: String
    },
    emits: ['processing', 'completed', 'error'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const userBundles = Vue.ref([]);
        const bundleMode = Vue.ref('existing'); 
        const selectedBundleId = Vue.ref(null);
        
        const bundleForm = Vue.reactive({
            name: '',
            description: '',
            isPrivate: false 
        });

        const fetchUserBundles = async () => {
            try {
                const response = await fetch('/bundle/my-bundles');
                if (response.ok) {
                    const data = await response.json();
                    userBundles.value = data.bundles || [];
                    if (userBundles.value.length === 0) bundleMode.value = 'create';
                }
            } catch (error) {
                console.error("Error fetching bundles:", error);
            }
        };

        const submitBundle = async () => {
            emit('processing', true);
            const payload = {
                existing_bundle_id: bundleMode.value === 'existing' ? selectedBundleId.value : null,
                new_bundle_name: bundleMode.value === 'create' ? bundleForm.name : '',
                new_bundle_description: bundleForm.description,
                is_public: !bundleForm.isPrivate, 
                filters: props.filters
            };

            try {
                const response = await fetch('/rule/bundle/create-from-filters', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-CSRFToken': props.csrf 
                    },
                    body: JSON.stringify(payload)
                });
                
                if (response.ok) {
                    emit('completed');
                } else {
                    const err = await response.json();
                    emit('error', err.message || "Export failed");
                }
            } catch (error) {
                emit('error', "Server connection error");
            } finally {
                emit('processing', false);
            }
        };

        Vue.onMounted(fetchUserBundles);

        return {
            userBundles,
            bundleMode,
            selectedBundleId,
            bundleForm,
            submitBundle,
        };
    },
    template: `
    <div class="bundle-manager-ui">
        <div v-if="isOverLimit" class="alert alert-danger border-0 rounded-4 shadow-sm text-center">
            <i class="fa-solid fa-triangle-exclamation fa-2xl mb-3 d-block"></i>
            <h6 class="fw-bold">Limit Exceeded</h6>
            <p class="small mb-0">You are trying to bundle [[ totalRules ]] rules, but the limit is [[ maxLimit ]].</p>
        </div>

        <div v-else class="row g-3">
            <div class="col-12">
                <div class="d-flex bg-light p-1 rounded-pill mb-3">
                    <button class="btn flex-grow-1 rounded-pill fw-bold btn-sm transition-all" 
                            :class="bundleMode === 'existing' ? 'btn-white shadow-sm' : 'text-muted'"
                            @click="bundleMode = 'existing'">
                        Existing Bundle
                    </button>
                    <button class="btn flex-grow-1 rounded-pill fw-bold btn-sm transition-all" 
                            :class="bundleMode === 'create' ? 'btn-white shadow-sm' : 'text-muted'"
                            @click="bundleMode = 'create'">
                        Create New
                    </button>
                </div>
            </div>

            <div v-if="bundleMode === 'existing'" class="col-12 animate__animated animate__fadeIn">
                <div v-if="userBundles.length > 0" class="bundle-list custom-scrollbar" style="max-height: 250px; overflow-y: auto;">
                    <div v-for="bundle in userBundles" :key="bundle.id" 
                         @click="selectedBundleId = bundle.id"
                         class="p-3 border rounded-4 mb-2 cursor-pointer transition-all d-flex align-items-center"
                         :class="selectedBundleId === bundle.id ? 'border-primary bg-primary-subtle ring-primary' : ' shadow-sm-hover'">
                        
                        <div class="bundle-icon me-3">
                            <div class="rounded-circle  shadow-sm d-flex align-items-center justify-content-center position-relative" style="width: 40px; height: 40px;">
                                <i class="fa-solid fa-folder-open text-primary"></i>
                                <span class="position-absolute top-0 start-100 translate-middle badge rounded-pill border border-light" 
                                      :class="bundle.access ? 'bg-success' : 'bg-danger'" 
                                      style="padding: 0.35em; font-size: 0.5rem;">
                                    <i :class="bundle.access ? 'fa-solid fa-earth-americas' : 'fa-solid fa-lock'"></i>
                                </span>
                            </div>
                        </div>
                        
                        <div class="flex-grow-1 text-start">
                            <div class="d-flex align-items-center">
                                <h6 class="mb-0 fw-bold small">[[ bundle.name ]]</h6>
                                <span class="ms-2 badge rounded-pill fw-normal" :class="bundle.access ? 'text-success bg-success-subtle' : 'text-danger bg-danger-subtle'" style="font-size: 0.65rem;">
                                    [[ bundle.access ? 'Public' : 'Private' ]]
                                </span>
                            </div>
                            <small class="text-muted">[[ bundle.number_of_rules ]] rules • [[ bundle.updated_at ]]</small>
                        </div>

                        <div v-if="selectedBundleId === bundle.id" class="text-primary">
                            <i class="fa-solid fa-circle-check"></i>
                        </div>
                    </div>
                </div>
                <div v-else class="text-center py-4 bg-light rounded-4">
                    <i class="fa-solid fa-ghost text-muted mb-2"></i>
                    <p class="small text-muted mb-0">No bundles found.</p>
                </div>
            </div>

            <div v-if="bundleMode === 'create'" class="col-12 animate__animated animate__fadeIn">
                <div class="bundle-creation-form  p-3 rounded-4 border shadow-sm text-start">
                    <label class="ls-1 small fw-bold text-primary text-uppercase mb-3 d-flex align-items-center">
                        <i class="fa-solid fa-id-card me-2"></i> Bundle Identity
                    </label>
                    
                    <div class="input-group mb-3">
                        <span class="input-group-text bg-light border-2 border-end-0 rounded-start-4">
                            <i class="fa-solid fa-tag text-muted"></i>
                        </span>
                        <input type="text" 
                            class="form-control form-control-lg rounded-end-4 border-2 shadow-none fs-6" 
                            v-model="bundleForm.name" 
                            placeholder="Name your collection...">
                    </div>

                    <div class="mb-3">
                        <textarea class="form-control rounded-4 border-2 shadow-none p-3" 
                                rows="3"
                                v-model="bundleForm.description" 
                                placeholder="Description (Optional)"></textarea>
                    </div>

                    <div class="d-flex align-items-center justify-content-between p-3 rounded-4"
                        style="border: 2px dashed #dee2e6;"
                        :class="bundleForm.isPrivate ? 'bg-danger-subtle' : 'bg-light'">
                        <div class="d-flex align-items-center text-start">
                            <div class="privacy-icon me-3">
                                <i v-if="bundleForm.isPrivate" class="fa-solid fa-lock text-danger fa-lg"></i>
                                <i v-else class="fa-solid fa-earth-americas text-success fa-lg"></i>
                            </div>
                            <div>
                                <h6 class="mb-0 fw-bold small">Visibility</h6>
                                <small class="text-muted">
                                    [[ bundleForm.isPrivate ? 'Only you can see this' : 'Visible to everyone' ]]
                                </small>
                            </div>
                        </div>
                        <div class="form-check form-switch m-0">
                            <input class="form-check-input h5 mb-0 cursor-pointer" 
                                type="checkbox" 
                                role="switch" 
                                id="bundlePrivacy" 
                                v-model="bundleForm.isPrivate">
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-12 mt-3">
                <button class="btn btn-success w-100 fw-bold rounded-pill py-3 shadow-sm" 
                        @click="submitBundle" 
                        :disabled="(bundleMode === 'existing' && !selectedBundleId) || (bundleMode === 'create' && !bundleForm.name)">
                    <i class="fa-solid fa-magic-wand-sparkles me-2"></i>
                    [[ bundleMode === 'existing' ? 'Confirm Addition' : 'Create & Save Bundle' ]]
                </button>
            </div>
        </div>
    </div>
    `
};

export default RuleBundleManager;