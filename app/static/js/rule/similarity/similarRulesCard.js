import DiffDisplay from '/static/js/codeMirror/diffDisplay.js';
import DeleteRuleModal from '/static/js/rule/deleteRule.js';

const SimilarRulesCard = {
    name: 'SimilarRulesCard',
    components: { DiffDisplay, DeleteRuleModal },
    props: {
        rule: { type: Object, default: () => ({}) }, // open this rule on load if there is a startOpen flag
        ruleA: { type: Object, required: true },
        ruleB: { type: Object, required: true },
        score: { type: [Number, String], default: 0 },
        type: { type: String, default: 'specific' },
        uniqueId: { type: String, required: true },
        isAdmin: { type: Boolean, default: false }
    },
    emits: ['refresh-list'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const isOpen = Vue.ref(false);

        Vue.onMounted(() => {
            if (props.rule && props.rule.startOpen) {
                toggleOpen();
            }
        });

        const getScoreDetails = (score) => {
            const numScore = parseFloat(score);
            const percentage = (numScore * 100).toFixed(0);
            if (numScore >= 0.99) return { class: 'score-critical', label: 'Duplicate', val: percentage };
            if (numScore > 0.85) return { class: 'score-critical', label: 'Critical', val: percentage };
            if (numScore > 0.6) return { class: 'score-warning', label: 'Significant', val: percentage };
            return { class: 'score-low', label: 'Partial', val: percentage };
        };


        const viewDetails = (id) => {
            window.open(`/rule/detail_rule/${id}`, '_blank');
        };

        const handleDeleted = (id) => {
            emit('refresh-list');
        };
        

        const toggleOpen = () => {
        isOpen.value = !isOpen.value;

        if (isOpen.value) {
            setTimeout(() => {
                const cmInstances = document.querySelectorAll('.CodeMirror');
                cmInstances.forEach(el => {
                    if (el.CodeMirror) {
                        el.CodeMirror.refresh();
                    }
                });
                window.dispatchEvent(new Event('resize'));
            }, 150);
        }
    };

        
        const formatDate = (dateStr) => {
            if (!dateStr) return 'N/A';
            return dateStr.split(' ')[0]; 
        };

        const isIdentical = Vue.computed(() => {
            return props.ruleA.to_string === props.ruleB.to_string;
        });


        return {isIdentical, getScoreDetails, isOpen, formatDate , toggleOpen, viewDetails, handleDeleted };
    },
    template: `
    <div :class="['rule-analysis-wrapper mb-3 shadow-sm border-0', { 'is-open': isOpen }]" 
         @click="isOpen = !isOpen" 
         style="transition: all 0.3s ease; cursor: pointer; border-radius: 8px; overflow: hidden; ">
        
        <div class="rule-header p-3 d-flex align-items-center">
            <div class="me-3">
                <div :class="['score-badge-square shadow-sm', getScoreDetails(score).class]">
                    <span class="pct" style="font-size: 1.1rem; font-weight: 800;">[[ getScoreDetails(score).val ]]%</span>
                    <span class="lbl" style="font-size: 0.6rem; text-transform: uppercase;">[[ getScoreDetails(score).label ]]</span>
                </div>
            </div>

            <div class="flex-grow-1 min-width-0">
                <div class="d-flex align-items-center justify-content-between mb-1">
                    <div class="d-flex align-items-center gap-2 flex-grow-1 min-width-0">
                        <span class="badge bg-secondary-subtle text-secondary border px-2 py-1" style="font-size: 0.65rem;">SOURCE</span>
                        <h6 class="fw-bold mb-0 text-truncate text-dark" style="max-width: 250px;">[[ ruleA.title || 'Untitled Asset' ]]</h6>
                        
                        <i class="fa-solid fa-right-left text-muted opacity-50 mx-1" style="font-size: 0.8rem;"></i>
                        
                        <span class="badge bg-primary-subtle text-primary border px-2 py-1" style="font-size: 0.65rem;">TARGET</span>
                        <h6 class="fw-bold mb-0 text-truncate text-dark" style="max-width: 250px;">[[ ruleB.title || 'Untitled Asset' ]]</h6>
                    </div>
                    
                    <div class="ms-3 flex-shrink-0 d-flex align-items-center gap-3">
                        <span v-if="isIdentical" class="badge rounded-pill bg-danger shadow-sm animate__animated animate__pulse animate__infinite" style="font-size: 0.7rem;">Exact Match Detected</span>
                        <div class="btn-action-chevron">
                            <i :class="['fa-solid fa-chevron-down small transition-icon', { 'rotate-180': isOpen }]"></i>
                        </div>
                    </div>
                </div>
                
                <div class="d-flex align-items-center gap-3 mt-2">
                    <div class="small text-muted d-flex align-items-center gap-1">
                        <i class="fa-solid fa-user-edit opacity-50"></i> [[ ruleA.author || 'Unknown' ]]
                    </div>
                    <div class="small text-muted d-flex align-items-center gap-1">
                        <i class="fa-solid fa-calendar opacity-50"></i> [[ formatDate(ruleA.creation_date) ]]
                    </div>
                    <div class="small text-muted d-flex align-items-center gap-1" v-if="ruleA.version">
                        <i class="fa-solid fa-code-branch opacity-50"></i> v[[ ruleA.version ]]
                    </div>
                </div>
            </div>
        </div>

        <div v-if="isOpen" class="rule-details-area border-top animate__animated animate__fadeIn" @click.stop >
            <div class="row g-0">
                <div class="col-md-3 border-end p-3 bg-light-subtle">
                    <div class="d-flex flex-column gap-4">
                        <div class="meta-group">
                            <label class="text-uppercase fw-bold text-muted mb-2" style="font-size: 0.65rem; letter-spacing: 0.05rem;">Asset Comparison</label>
                            
                            <div class="p-2 rounded border mb-2 shadow-xs">
                                <div class="d-flex justify-content-between align-items-start mb-2">
                                    <span class="fw-bold small text-primary">A: Base Asset</span>
                                    <span class="badge bg-light text-dark border" style="font-size: 0.6rem;">ID: [[ ruleA.id ]]</span>
                                </div>
                                <div class="meta-details d-flex flex-column gap-1 mb-2">
                                    <div class="text-muted small" style="font-size: 0.75rem;"><i class="fa-solid fa-user fa-fw me-1"></i> [[ ruleA.author || 'N/A' ]]</div>
                                    <div class="text-muted small text-truncate" style="font-size: 0.75rem;"><i class="fa-solid fa-link fa-fw me-1"></i> [[ ruleA.source || 'N/A' ]]</div>
                                    <div class="text-muted small" style="font-size: 0.75rem;"><i class="fa-solid fa-calendar-plus fa-fw me-1"></i> [[ formatDate(ruleA.created_at || ruleA.creation_date) ]]</div>
                                    <div class="text-muted small" style="font-size: 0.75rem;"><i class="fa-solid fa-file-code fa-fw me-1"></i> [[ ruleA.format || 'YARA' ]]</div>
                                </div>
                                <div class="d-flex gap-1 border-top pt-2 mt-1">
                                    <button class="btn btn-xs btn-light border flex-grow-1" title="View Details" @click.stop="viewDetails(ruleA.id)" style="font-size: 0.65rem; padding: 2px 5px;">
                                        <i class="fa-solid fa-eye"></i>
                                    </button>
                                    <template v-if="isAdmin">
                                        <button class="btn btn-xs btn-outline-danger flex-grow-1" 
                                                data-bs-toggle="modal" 
                                                :data-bs-target="'#del_a_' + uniqueId">
                                            <i class="fa fa-trash"></i>
                                        </button>
                                        
                                        <delete-rule-modal 
                                            :rule="ruleA" 
                                            :modal-id="'del_a_' + uniqueId"
                                            @deleted="handleDeleted">
                                        </delete-rule-modal>
                                    </template>
                                </div>
                            </div>

                            <div class="p-2 rounded  border shadow-xs">
                                <div class="d-flex justify-content-between align-items-start mb-2">
                                    <span class="fw-bold small text-success">B: Match Found</span>
                                    <span class="badge bg-light text-dark border" style="font-size: 0.6rem;">ID: [[ ruleB.id ]]</span>
                                </div>
                                <div class="meta-details d-flex flex-column gap-1 mb-2">
                                    <div class="text-muted small" style="font-size: 0.75rem;"><i class="fa-solid fa-user fa-fw me-1"></i> [[ ruleB.author || 'N/A' ]]</div>
                                    <div class="text-muted small text-truncate" style="font-size: 0.75rem;"><i class="fa-solid fa-link fa-fw me-1"></i> [[ ruleB.source || 'N/A' ]]</div>
                                    <div class="text-muted small" style="font-size: 0.75rem;"><i class="fa-solid fa-calendar-plus fa-fw me-1"></i> [[ formatDate(ruleB.created_at || ruleB.creation_date) ]]</div>
                                    <div class="text-muted small" style="font-size: 0.75rem;"><i class="fa-solid fa-file-code fa-fw me-1"></i> [[ ruleB.format || 'YARA' ]]</div>
                                </div>
                                <div class="d-flex gap-1 border-top pt-2 mt-1">
                                    <button class="btn btn-xs btn-light border flex-grow-1" title="View Details" @click.stop="viewDetails(ruleB.id)" style="font-size: 0.65rem; padding: 2px 5px;">
                                        <i class="fa-solid fa-eye"></i>
                                    </button>
                                    <template v-if="isAdmin">
                                        <button class="btn btn-xs btn-outline-danger flex-grow-1" 
                                                data-bs-toggle="modal" 
                                                :data-bs-target="'#del_b_' + uniqueId">
                                            <i class="fa fa-trash"></i>
                                        </button>
                                        <delete-rule-modal 
                                            :rule="ruleB" 
                                            :modal-id="'del_b_' + uniqueId"
                                            @deleted="handleDeleted">
                                        </delete-rule-modal>
                                    </template>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-md-9  d-flex flex-column">            
                    <div class="flex-grow-1 diff-scroll-container">
                        <div class="p-0">
                            <diff-display 
                                :unique-id="uniqueId" 
                                :old-text="ruleA.content"
                                :new-text="ruleB.content"
                                displayMode="one-side" max-height="none">
                            </diff-display>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    `
};

export default SimilarRulesCard;