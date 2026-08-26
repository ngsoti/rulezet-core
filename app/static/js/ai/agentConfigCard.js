/**
 * agentConfigCard.js — "Feature status & configuration" card shared by all
 * four AI admin pages (AI_05_UI_UX_SPEC.md §6). One component, imported into
 * each page's own <script type="module">, never re-authored per page.
 *
 * Props:
 *   agentKey   String  (required) — 'chatbot' | 'rule_analysis' | 'rule_generator' | 'rule_fixer'
 *   csrfToken  String  (required)
 *
 * Emits:
 *   notify({ message, level })
 */

const { ref, reactive, onMounted } = Vue

export default {
    name: 'AgentConfigCard',
    delimiters: ['[[', ']]'],

    props: {
        agentKey:  { type: String, required: true },
        csrfToken: { type: String, required: true },
    },

    emits: ['notify'],

    template: `
        <div class="card border-0 shadow-sm rounded-4 mb-4">
            <div class="card-body p-4">
                <div class="d-flex align-items-center justify-content-between flex-wrap gap-3 mb-3">
                    <div>
                        <div class="d-flex align-items-center gap-2 mb-1">
                            <div style="width:3px;height:14px;background:#0d6efd;border-radius:2px;flex-shrink:0;"></div>
                            <span class="fw-bold" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.07em;color:var(--subtle-text-color);">
                                <i class="fa-solid fa-power-off me-1"></i>Feature status
                            </span>
                        </div>
                        <small class="text-muted">Turns this agent on or off, instance-wide.</small>
                    </div>
                    <div class="d-flex align-items-center gap-2">
                        <span class="badge rounded-pill" :class="enabled ? 'bg-success-subtle text-success-emphasis' : 'bg-secondary-subtle text-secondary-emphasis'">
                            [[ enabled ? 'Enabled' : 'Disabled' ]]
                        </span>
                        <div class="form-check form-switch mb-0">
                            <input class="form-check-input" type="checkbox" role="switch" v-model="enabled" :disabled="loading" @change="saveConfig">
                        </div>
                    </div>
                </div>

                <div v-if="!loading" class="row g-3 pt-3" style="border-top:1px solid var(--border-color);">
                    <div class="col-md-3">
                        <label class="form-label small mb-1">Default model</label>
                        <select class="form-select form-select-sm" v-model="config.default_model" @change="saveConfig">
                            <option value="">(use global default)</option>
                            <option v-for="m in enabledModels" :key="m" :value="m">[[ m ]]</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label small mb-1">Timeout (seconds)</label>
                        <input type="number" min="1" class="form-control form-control-sm" v-model.number="config.timeout_s" @change="saveConfig">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label small mb-1">Max output tokens (num_predict)</label>
                        <input type="number" min="1" class="form-control form-control-sm" v-model.number="config.num_predict" @change="saveConfig">
                    </div>
                    <div class="col-md-3" v-if="config.max_per_hour !== null">
                        <label class="form-label small mb-1">Rate limit (per user / hour)</label>
                        <input type="number" min="0" class="form-control form-control-sm" v-model.number="config.max_per_hour" @change="saveConfig">
                    </div>
                </div>
            </div>
        </div>
    `,

    setup(props, { emit }) {
        const loading = ref(true)
        const enabled = ref(true)
        const config = reactive({
            default_model: '',
            timeout_s: 120,
            num_predict: 2048,
            max_per_hour: null,
        })
        const enabledModels = ref([])

        async function fetchConfig() {
            try {
                const res = await fetch(`/ai/admin/config/${props.agentKey}`)
                if (res.ok) {
                    const data = await res.json()
                    enabled.value = data.enabled
                    config.default_model = data.default_model || ''
                    config.timeout_s = data.timeout_s
                    config.num_predict = data.num_predict
                    config.max_per_hour = data.max_per_hour
                }
            } finally {
                loading.value = false
            }
        }

        async function fetchModels() {
            try {
                const res = await fetch('/ai/admin/models/list')
                if (res.ok) {
                    const data = await res.json()
                    enabledModels.value = (data.models || []).filter(m => m.is_enabled).map(m => m.model_name)
                }
            } catch { /* dropdown just stays limited to '(use global default)' */ }
        }

        async function saveConfig() {
            try {
                const res = await fetch(`/ai/admin/config/${props.agentKey}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body: JSON.stringify({
                        enabled: enabled.value,
                        default_model: config.default_model || null,
                        timeout_s: config.timeout_s,
                        num_predict: config.num_predict,
                        max_per_hour: config.max_per_hour,
                    }),
                })
                const data = await res.json()
                if (data.success) {
                    emit('notify', { message: 'Saved.', level: 'success-subtle' })
                } else {
                    emit('notify', { message: data.error || 'Failed to save.', level: 'danger-subtle' })
                }
            } catch (e) {
                emit('notify', { message: 'Network error: ' + e, level: 'danger-subtle' })
            }
        }

        onMounted(async () => {
            await Promise.all([fetchConfig(), fetchModels()])
        })

        return { loading, enabled, config, enabledModels, saveConfig }
    },
}
