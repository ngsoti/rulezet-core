import DiffViewer from '/static/js/components/diff-viewer.js';
import DeleteRuleModal from '/static/js/rule/deleteRule.js';

const SimilarRulesCard = {
    name: 'SimilarRulesCard',
    components: { DiffViewer, DeleteRuleModal },
    props: {
        rule: { type: Object, default: () => ({}) }, // open this rule on load if there is a startOpen flag
        ruleA: { type: Object, required: true },
        ruleB: { type: Object, required: true },
        score: { type: [Number, String], default: 0 },
        type: { type: String, default: 'specific' },
        uniqueId: { type: String, required: true },
        isAdmin: { type: Boolean, default: false },
        searchTerm: { type: String, default: '' }
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
            if (numScore >= 0.99) return { class: 'dup-score--critical', label: 'Duplicate', val: percentage };
            if (numScore > 0.85) return { class: 'dup-score--critical', label: 'Critical', val: percentage };
            if (numScore > 0.6) return { class: 'dup-score--warning', label: 'Significant', val: percentage };
            return { class: 'dup-score--low', label: 'Partial', val: percentage };
        };

        const viewDetails = (id) => {
            window.open(`/rule/detail_rule/${id}`, '_blank');
        };

        const handleDeleted = (id) => {
            emit('refresh-list');
        };

        const toggleOpen = () => {
            isOpen.value = !isOpen.value;
        };

        const formatDate = (dateStr) => {
            if (!dateStr) return 'N/A';
            return dateStr.split(' ')[0];
        };

        const isIdentical = Vue.computed(() => {
            return props.ruleA.to_string === props.ruleB.to_string;
        });

        function escapeHtml(str) {
            return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }

        const highlight = (text) => {
            const str = escapeHtml(text ?? '');
            const term = props.searchTerm.trim();
            if (!term) return str;
            try {
                const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                return str.replace(new RegExp(`(${escaped})`, 'gi'), m => `<mark class="dup-highlight">${m}</mark>`);
            } catch {
                return str;
            }
        };

        return { isIdentical, getScoreDetails, isOpen, formatDate, toggleOpen, viewDetails, handleDeleted, highlight };
    },
    template: `
    <div :class="['dup-pair-card', { 'dup-pair-card--open': isOpen }]"
         @click="isOpen = !isOpen">

        <div class="dup-pair-card__header">
            <div :class="['dup-score-badge', getScoreDetails(score).class]">
                <span class="dup-score-badge__pct">[[ getScoreDetails(score).val ]]%</span>
                <span class="dup-score-badge__lbl">[[ getScoreDetails(score).label ]]</span>
            </div>

            <div class="dup-pair-card__main">
                <div class="dup-pair-card__titles">
                    <div class="dup-pair-card__titles-row">
                        <span class="dup-side-tag dup-side-tag--source">Source</span>
                        <h6 class="dup-title" :title="ruleA.title || 'Untitled Asset'" v-html="highlight(ruleA.title || 'Untitled Asset')"></h6>

                        <i class="fa-solid fa-right-left dup-swap-icon"></i>

                        <span class="dup-side-tag dup-side-tag--target">Target</span>
                        <h6 class="dup-title" :title="ruleB.title || 'Untitled Asset'" v-html="highlight(ruleB.title || 'Untitled Asset')"></h6>
                    </div>

                    <div class="dup-pair-card__meta">
                        <span><i class="fa-solid fa-user-edit"></i> [[ ruleA.author || 'Unknown' ]]</span>
                        <span><i class="fa-solid fa-calendar"></i> [[ formatDate(ruleA.creation_date) ]]</span>
                        <span v-if="ruleA.version"><i class="fa-solid fa-code-branch"></i> v[[ ruleA.version ]]</span>
                    </div>
                </div>

                <div class="dup-pair-card__actions">
                    <span v-if="isIdentical" class="dup-exact-badge">
                        <i class="fa-solid fa-triangle-exclamation"></i> Exact Match Detected
                    </span>
                    <div class="dup-chevron" :class="{ 'dup-chevron--open': isOpen }">
                        <i class="fa-solid fa-chevron-down"></i>
                    </div>
                </div>
            </div>
        </div>

        <div v-if="isOpen" class="dup-pair-card__detail" @click.stop>
            <div class="dup-asset-panel">
                <label class="dup-panel-label">Asset Comparison</label>

                <div class="dup-asset-card dup-asset-card--a">
                    <div class="dup-asset-card__head">
                        <span class="dup-asset-card__side">A · Base Asset</span>
                        <span class="dup-asset-card__id">ID [[ ruleA.id ]]</span>
                    </div>
                    <div class="dup-asset-card__meta">
                        <div><i class="fa-solid fa-user fa-fw"></i> [[ ruleA.author || 'N/A' ]]</div>
                        <div class="text-truncate"><i class="fa-solid fa-link fa-fw"></i> [[ ruleA.source || 'N/A' ]]</div>
                        <div><i class="fa-solid fa-calendar-plus fa-fw"></i> [[ formatDate(ruleA.created_at || ruleA.creation_date) ]]</div>
                        <div><i class="fa-solid fa-file-code fa-fw"></i> [[ (ruleA.format || 'YARA').toUpperCase() ]]</div>
                    </div>
                    <div class="dup-asset-card__actions">
                        <button class="dup-btn" title="View Details" @click.stop="viewDetails(ruleA.id)">
                            <i class="fa-solid fa-eye"></i> View
                        </button>
                        <template v-if="isAdmin">
                            <button class="dup-btn dup-btn--danger"
                                    data-bs-toggle="modal"
                                    :data-bs-target="'#del_a_' + uniqueId">
                                <i class="fa-solid fa-trash"></i>
                            </button>
                            <delete-rule-modal
                                :rule="ruleA"
                                :modal-id="'del_a_' + uniqueId"
                                @deleted="handleDeleted">
                            </delete-rule-modal>
                        </template>
                    </div>
                </div>

                <div class="dup-asset-card dup-asset-card--b">
                    <div class="dup-asset-card__head">
                        <span class="dup-asset-card__side">B · Match Found</span>
                        <span class="dup-asset-card__id">ID [[ ruleB.id ]]</span>
                    </div>
                    <div class="dup-asset-card__meta">
                        <div><i class="fa-solid fa-user fa-fw"></i> [[ ruleB.author || 'N/A' ]]</div>
                        <div class="text-truncate"><i class="fa-solid fa-link fa-fw"></i> [[ ruleB.source || 'N/A' ]]</div>
                        <div><i class="fa-solid fa-calendar-plus fa-fw"></i> [[ formatDate(ruleB.created_at || ruleB.creation_date) ]]</div>
                        <div><i class="fa-solid fa-file-code fa-fw"></i> [[ (ruleB.format || 'YARA').toUpperCase() ]]</div>
                    </div>
                    <div class="dup-asset-card__actions">
                        <button class="dup-btn" title="View Details" @click.stop="viewDetails(ruleB.id)">
                            <i class="fa-solid fa-eye"></i> View
                        </button>
                        <template v-if="isAdmin">
                            <button class="dup-btn dup-btn--danger"
                                    data-bs-toggle="modal"
                                    :data-bs-target="'#del_b_' + uniqueId">
                                <i class="fa-solid fa-trash"></i>
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

            <div class="dup-diff-panel">
                <diff-viewer
                    :initial-left="ruleA.content || ''"
                    :initial-right="ruleB.content || ''"
                    left-label="Original"
                    right-label="Modified"
                    mode="read">
                </diff-viewer>
            </div>
        </div>
    </div>
    `
};

export default SimilarRulesCard;
