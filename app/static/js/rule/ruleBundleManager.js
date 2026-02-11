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
        const isLoading = Vue.ref(false);
        
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
            isLoading.value = true;

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
                    emit('error', err.message || "Operation failed");
                }
            } catch (error) {
                emit('error', "Connection to server failed");
            } finally {
                emit('processing', false);
                isLoading.value = false;
            }
        };

        Vue.onMounted(fetchUserBundles);

        return {
            userBundles,
            bundleMode,
            selectedBundleId,
            bundleForm,
            submitBundle,
            isLoading
        };
    },
    template: `
    <div class="bundle-manager-ui position-relative">
        <div v-if="isLoading" class="position-absolute w-100 h-100 d-flex align-items-center justify-content-center bg-white bg-opacity-75" style="z-index: 10;">
            <div class="spinner-border text-success" role="status"></div>
        </div>

        <div v-if="isOverLimit" class="alert alert-danger border-0 rounded-4 shadow-sm text-center animate__animated animate__shakeX">
            <i class="fa-solid fa-triangle-exclamation fa-2xl mb-3 d-block text-danger"></i>
            <h6 class="fw-bold">Limit Exceeded</h6>
            <p class="small mb-0">You are trying to bundle <strong>[[ totalRules ]]</strong> rules, but the limit is <strong>[[ maxLimit ]]</strong>.</p>
        </div>

        <div v-else class="row g-3">
            <div class="col-12">
                <div class="d-flex bg-light p-1 rounded-pill mb-3 border shadow-sm">
                    <button class="btn flex-grow-1 rounded-pill fw-bold btn-sm transition-all" 
                            :class="bundleMode === 'existing' ? 'btn-white shadow-sm border text-primary' : 'text-muted border-0 bg-transparent'"
                            @click="bundleMode = 'existing'">
                        Existing Bundle
                    </button>
                    <button class="btn flex-grow-1 rounded-pill fw-bold btn-sm transition-all" 
                            :class="bundleMode === 'create' ? 'btn-white shadow-sm border text-primary' : 'text-muted border-0 bg-transparent'"
                            @click="bundleMode = 'create'">
                        Create New
                    </button>
                </div>
            </div>

            <div v-if="bundleMode === 'existing'" class="col-12 animate__animated animate__fadeIn">
                <div v-if="userBundles.length > 0" class="bundle-list custom-scrollbar pe-2" style="max-height: 250px; overflow-y: auto;">
                    <div v-for="bundle in userBundles" :key="bundle.id" 
                         @click="selectedBundleId = bundle.id"
                         class="p-3 border rounded-4 mb-2 cursor-pointer transition-all d-flex align-items-center"
                         :class="selectedBundleId === bundle.id ? 'border-primary bg-primary-subtle ring-primary' : 'shadow-sm-hover bg-white'">
                        
                        <div class="bundle-icon me-3">
                            <div class="rounded-circle shadow-sm d-flex align-items-center justify-content-center position-relative bg-white" style="width: 40px; height: 40px;">
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
                                <h6 class="mb-0 fw-bold small text-dark">[[ bundle.name ]]</h6>
                                <span class="ms-2 badge rounded-pill fw-normal" :class="bundle.access ? 'text-success bg-success-subtle' : 'text-danger bg-danger-subtle'" style="font-size: 0.65rem;">
                                    [[ bundle.access ? 'Public' : 'Private' ]]
                                </span>
                            </div>
                            <small class="text-muted">[[ bundle.number_of_rules ]] rules • [[ bundle.updated_at ]]</small>
                        </div>

                        <div v-if="selectedBundleId === bundle.id" class="text-primary animate__animated animate__scaleIn">
                            <i class="fa-solid fa-circle-check fa-lg"></i>
                        </div>
                    </div>
                </div>
                <div v-else class="text-center py-5 bg-light rounded-4 border border-dashed">
                    <i class="fa-solid fa-folder-tree text-muted mb-3 fa-2x opacity-25"></i>
                    <p class="small text-muted mb-0 fw-bold">No bundles found in your account.</p>
                </div>
            </div>

            <div v-if="bundleMode === 'create'" class="col-12 animate__animated animate__fadeIn">
                <div class="bundle-creation-form p-3 rounded-4 border shadow-sm text-start bg-white">
                    <label class="ls-1 small fw-bold text-primary text-uppercase mb-3 d-flex align-items-center">
                        <i class="fa-solid fa-id-card me-2"></i> Bundle Identity
                    </label>
                    
                    <div class="input-group mb-3">
                        <span class="input-group-text bg-light border-2 border-end-0 rounded-start-4">
                            <i class="fa-solid fa-tag text-muted small"></i>
                        </span>
                        <input type="text" 
                            class="form-control form-control-lg rounded-end-4 border-2 shadow-none fs-6" 
                            v-model="bundleForm.name" 
                            placeholder="Name your collection...">
                    </div>

                    <div class="mb-3">
                        <textarea class="form-control rounded-4 border-2 shadow-none p-3 small" 
                                rows="3"
                                v-model="bundleForm.description" 
                                placeholder="What is this collection about? (Optional)"></textarea>
                    </div>

                    <div class="d-flex align-items-center justify-content-between p-3 rounded-4 transition-all"
                        style="border: 2px dashed #dee2e6;"
                        :class="bundleForm.isPrivate ? 'bg-danger-subtle border-danger-subtle' : 'bg-light'">
                        <div class="d-flex align-items-center text-start">
                            <div class="privacy-icon me-3">
                                <i v-if="bundleForm.isPrivate" class="fa-solid fa-lock text-danger fa-lg"></i>
                                <i v-else class="fa-solid fa-earth-americas text-success fa-lg"></i>
                            </div>
                            <div>
                                <h6 class="mb-0 fw-bold small">Visibility</h6>
                                <small class="text-muted">
                                    [[ bundleForm.isPrivate ? 'Private collection' : 'Public collection' ]]
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
                <button class="btn btn-success w-100 fw-bold rounded-pill py-3 shadow-sm transition-all hover-lift" 
                        @click="submitBundle" 
                        :disabled="isLoading || (bundleMode === 'existing' && !selectedBundleId) || (bundleMode === 'create' && !bundleForm.name)">
                    <template v-if="!isLoading">
                        <i class="fa-solid fa-magic-wand-sparkles me-2"></i>
                        [[ bundleMode === 'existing' ? 'Add rules to bundle' : 'Create & Add rules' ]]
                    </template>
                    <template v-else>
                        <span class="spinner-border spinner-border-sm me-2"></span> Processing...
                    </template>
                </button>
                <div class="text-center mt-2">
                    <small class="text-muted extra-small">
                        <i class="fa-solid fa-info-circle me-1"></i>
                        This will add <strong>[[ totalRules ]]</strong> rules based on your current filters.
                    </small>
                </div>
            </div>
        </div>
    </div>
    `
};

export default RuleBundleManager;