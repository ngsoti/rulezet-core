const UserProposalsComponent = {
    props: {
        userId: { type: [String, Number], required: true },
        apiEndpoint: { type: String, required: true } // ex: /api/user_edit_proposals/
    },
    delimiters: ['[[', ']]'],
    setup(props) {
        const proposals = Vue.ref([]);
        const loading = Vue.ref(true);
        const stats = Vue.ref({ total: 0, pending: 0, approved: 0, rejected: 0 });

        const fetchProposals = async () => {
            loading.value = true;
            try {
                const response = await fetch(`${props.apiEndpoint}${props.userId}`);
                const data = await response.json();
                proposals.value = data.proposals;
                stats.value = data.stats;
            } catch (err) {
                console.error("Error fetching proposals:", err);
            } finally {
                loading.value = false;
            }
        };

        const getStatusClass = (status) => {
            const classes = {
                'pending': 'bg-warning text-dark',
                'accepted': 'bg-success text-white',
                'rejected': 'bg-danger text-white'
            };
            return classes[status] || 'bg-success';
        };

        const getFormatClass = (format) => {
            return 'bg-primary text-white';
        };

        Vue.onMounted(fetchProposals);

        return { proposals, loading, stats, getStatusClass, getFormatClass };
    },
    template: `
    <div class="edit-proposals-dashboard">
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="card border-0 shadow-sm bg-primary text-white p-3">
                    <small class="text-uppercase opacity-75">Total Contributions</small>
                    <div class="h3 fw-bold mb-0">[[ stats.total ]]</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card border-0 shadow-sm p-3">
                    <small class="text-uppercase text-muted">Pending Review</small>
                    <div class="h3 fw-bold mb-0 text-warning">[[ stats.pending ]]</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card border-0 shadow-sm p-3">
                    <small class="text-uppercase text-muted">Approved</small>
                    <div class="h3 fw-bold mb-0 text-success">[[ stats.accepted ]]</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card border-0 shadow-sm p-3">
                    <small class="text-uppercase text-muted">Rejected</small>
                    <div class="h3 fw-bold mb-0 text-danger">[[ stats.rejected ]]</div>
                </div>
            </div>
        </div>

        <div class="card shadow-sm border-0">
            <div class="card-header bg-white py-3">
                <h5 class="mb-0 fw-bold"><i class="fas fa-edit me-2"></i> My Edit Proposals</h5>
            </div>
            <div class="card-body p-0">
                <div v-if="loading" class="text-center p-5">
                    <div class="spinner-border text-primary" role="status"></div>
                </div>

                <div v-else-if="proposals.length === 0" class="text-center p-5">
                    <i class="fas fa-folder-open fa-3x text-muted mb-3"></i>
                    <p class="text-muted">No edit proposals found yet.</p>
                </div>

                <div v-else class="table-responsive">
                    <table class="table table-hover align-middle mb-0">
                        <thead class="bg-light">
                            <tr>
                                <th class="ps-4">Rule Asset</th>
                                <th>Format</th>
                                <th>Type</th>
                                <th>Date</th>
                                <th>Status</th>
                                <th class="text-end pe-4">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="prop in proposals" :key="prop.id">
                                <td class="ps-4">
                                    <div class="fw-bold text-dark">[[ prop.rule_name ]]</div>
                                    <small class="text-muted">ID: #[[ prop.rule_id ]]</small>
                                </td>
                                <td>
                                    <span class="badge border fw-normal" :class="getFormatClass(prop.rule_format)">
                                        [[ prop.rule_format ]]
                                    </span>
                                </td>
                                <td>
                                    <span class="text-capitalize small">[[ prop.edit_type || 'Update' ]]</span>
                                </td>
                                <td class="text-muted small">
                                    [[ prop.timestamp ]]
                                </td>
                                <td>
                                    <span class="badge rounded-pill px-3" :class="getStatusClass(prop.status)">
                                        [[ prop.status ]]
                                    </span>
                                </td>
                                <td class="text-end pe-4">
                                    <a :href="'/rule/proposal_content_discuss?id=' + prop.id" 
                                       class="btn btn-sm btn-outline-primary rounded-pill px-3">
                                        <i class="fas fa-comments me-1"></i> View Discussion
                                    </a>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    `
};

export default UserProposalsComponent;