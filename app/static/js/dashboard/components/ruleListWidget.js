/**
 * RuleListWidget — embeds the shared <rule-list> component in a compact,
 * filter-less "simple mode" (toolbar + pagination footer hidden via scoped
 * CSS) for three dashboard variants: most recent rules, most recently added
 * rules that carry a CVE, and top-rated rules.
 *
 * params: { variant: 'last_rules' | 'last_cves' | 'top_rated', limit, view }
 */
import WidgetFrame from '../widgetFrame.js'
import RuleList     from '/static/js/rule/ruleList.js'

const { ref, watch } = Vue

const VARIANTS = {
    last_rules: { label: 'Last Rules',  icon: 'fa-shield-halved',        hasCveOnly: false, sort: '',           dir: 'asc' },
    last_cves:  { label: 'Last CVEs',   icon: 'fa-bug',                  hasCveOnly: true,  sort: '',           dir: 'asc' },
    top_rated:  { label: 'Top Rated',   icon: 'fa-star',                 hasCveOnly: false, sort: 'vote_up',    dir: 'desc' },
}

const RuleListWidget = {
    components: {
        'widget-frame': WidgetFrame,
        'rule-list':    RuleList,
    },
    props: {
        params: { type: Object, required: true },
    },
    emits: ['update-params', 'remove'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const editForm  = ref({ ...props.params })
        const listRef   = ref(null)
        const renderKey = ref(0)

        const variant = () => VARIANTS[props.params.variant] || VARIANTS.last_rules

        function reload() {
            listRef.value && listRef.value.fetchData()
        }

        function saveSettings() {
            emit('update-params', { ...editForm.value })
            renderKey.value++ // force a clean remount — variant changes hidden props read once in setup()
        }

        watch(() => props.params, () => { editForm.value = { ...props.params } })

        return { editForm, listRef, renderKey, variant, reload, saveSettings, VARIANTS }
    },
    template: `
    <widget-frame :title="variant().label" :icon="variant().icon" :loading="false"
                   @reload="reload" @remove="$emit('remove')" @save-settings="saveSettings">
        <div class="dw-rulelist-embed">
            <rule-list
                :key="renderKey"
                ref="listRef"
                mode="read"
                :default-view="params.view || 'card'"
                :show-filters="false"
                :show-create="false"
                :show-export="false"
                :sync-url="false"
                :initial-per-page="params.limit || 5"
                :has-cve-only="variant().hasCveOnly"
                :initial-sort="variant().sort"
                :initial-dir="variant().dir">
            </rule-list>
        </div>

        <template #settings>
            <div class="mb-2">
                <label class="form-label small fw-bold text-muted text-uppercase mb-1">Variant</label>
                <select class="form-select form-select-sm" v-model="editForm.variant">
                    <option value="last_rules">Last Rules</option>
                    <option value="last_cves">Last CVEs</option>
                    <option value="top_rated">Top Rated</option>
                </select>
            </div>
            <div class="mb-2">
                <label class="form-label small fw-bold text-muted text-uppercase mb-1">View</label>
                <select class="form-select form-select-sm" v-model="editForm.view">
                    <option value="card">Card</option>
                    <option value="table">Table</option>
                </select>
            </div>
            <div>
                <label class="form-label small fw-bold text-muted text-uppercase mb-1">Items shown</label>
                <select class="form-select form-select-sm" v-model.number="editForm.limit">
                    <option :value="3">3</option>
                    <option :value="5">5</option>
                    <option :value="8">8</option>
                </select>
            </div>
        </template>
    </widget-frame>
    `,
}

export default RuleListWidget
