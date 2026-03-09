const SimilarRulesDisplay = {
    props: {
        ruleId: { type: Number, required: true },
        number: { type: Number, default: 3 },
        apiEndpoint: { type: String, default: '/similarity' }
    },
    delimiters: ['[[', ']]'],
    emits: ['found-similar-rules'],
    data() {
        return {
            rules: [],
            loading: true,
            error: null
        };
    },
    async mounted() {
        await this.fetchSimilarRules();
    },
    methods: {
        async fetchSimilarRules() {
            this.loading = true;
            try {
                const response = await fetch(`${this.apiEndpoint}?rule_id=${this.ruleId}&number=${this.number}`);
                const data = await response.json();
                if (data.success && data.rules.length > 0) {
                    this.rules = data.rules;
                    this.$emit('found-similar-rules', true);
                } else {
                    this.$emit('found-similar-rules', false);
                }
            } catch (err) {
                this.error = "Correlation engine offline.";
                this.$emit('found-similar-rules', false);
            } finally {
                this.loading = false;
            }
        },
        getSimilarityTheme(score) {
            const percentage = score * 100;
            if (percentage >= 85) {
                return {
                    colorClass: 'text-danger',
                    bgClass: 'bg-danger',
                    accent: '#dc3545',
                    label: 'High Similarity',
                    icon: 'fa-triangle-exclamation'
                };
            }
            return {
                colorClass: 'text-primary',
                bgClass: 'bg-primary',
                accent: '#0d6efd',
                label: 'Related Match',
                icon: 'fa-shield-halved'
            };
        }
    },
    template: `
    <div class="similar-rules-container">
        <div v-if="loading" class="text-center py-4">
            <div class="spinner-border spinner-border-sm text-primary" role="status"></div>
            <div class="small text-muted mt-2">Correlating Intelligence...</div>
        </div>
        
        <div v-else-if="error" class="alert alert-light border-0 text-center small py-3 shadow-sm">
             <i class="fas fa-info-circle me-1 opacity-50"></i> [[ error ]]
        </div>
        
        <div v-else class="row g-3">
            <div v-for="rule in rules" :key="rule.id" class="col-12">
                <div class="card h-100 shadow-sm border-0  position-relative overflow-hidden border rounded-4">
                    
                   

                    <div class="card-watermark-list">
                        <i class="fa-solid" :class="getSimilarityTheme(rule.score).icon"></i>
                    </div>

                    <div class="card-body p-4 z-index-1">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <span class="badge rounded-pill bg-dark pt-1 shadow-sm small">[[ rule.format.toUpperCase() ]]</span>
                            <div class="d-flex align-items-center">
                                <span class="fw-bold h5 mb-0" :class="getSimilarityTheme(rule.score).colorClass">
                                    [[ (rule.score * 100).toFixed(0) ]]%
                                </span>
                            </div>
                        </div>

                        <div class="mb-3">
                            <h6 class="fw-bold mb-1">
                                <a :href="'/rule/detail_rule/' + rule.id" 
                                   class="border-start border-4 ps-3 text-decoration-none d-block custom-rule-link"
                                   :style="{ borderColor: getSimilarityTheme(rule.score).accent + ' !important' }">
                                    [[ rule.name ]]
                                </a>
                            </h6>
                            
                            <div v-if="rule.score >= 0.85" class="d-flex align-items-center gap-1 mt-1 text-danger small fw-bold">
                                <i class="fas fa-triangle-exclamation animate-flicker"></i>
                                [[ getSimilarityTheme(rule.score).label.toUpperCase() ]]
                            </div>
                        </div>

                        <div class="similarity-bar-container mb-3" style="background: #e9ecef; height: 8px; border-radius: 4px; overflow: hidden;">
                            <div class="similarity-bar" 
                                 :class="getSimilarityTheme(rule.score).bgClass"
                                 :style="{ width: (rule.score * 100) + '%', height: '100%' }">
                            </div>
                        </div>

                        <div class="d-flex align-items-center justify-content-between mt-auto pt-2 border-top">
                            <div class="d-flex align-items-center gap-2">
                                <div class="avatar-circle-xs" style="width: 24px; height: 24px; font-size: 0.7rem;">
                                    [[ rule.author ? rule.author[0].toUpperCase() : 'U' ]]
                                </div>
                                <small class="text-muted fw-medium">[[ rule.author ]]</small>
                            </div>
                            <a :href="'/rule/similar_detail_page/' + ruleId + '?compare_with=' + rule.id" 
                            class="btn btn-sm btn-outline-secondary rounded-pill px-3 py-0" 
                            style="font-size: 0.7rem;">
                                Compare <i class="fas fa-arrow-right ms-1"></i>
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="mt-3 text-center" v-if="rules.length > 0">
            <a :href="'/rule/similar_detail_page/' + ruleId" class="btn btn-sm  border rounded-pill px-4  fw-bold shadow-sm">
                VIEW ALL CORRELATIONS <i class="fas fa-expand-arrows-alt ms-1"></i>
            </a>
        </div>
    </div>
    `
};

export default SimilarRulesDisplay;