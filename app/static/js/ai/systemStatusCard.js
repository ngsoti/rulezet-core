/**
 * systemStatusCard.js — live CPU/RAM/Ollama snapshot, shared by the Models &
 * Security page (full) and the Rule Analysis trigger card (compact) — the
 * direct answer to "is now a good time to run this?" (this session found a
 * real case where a model didn't fit in available RAM and failed silently
 * per-rule instead of warning up front).
 *
 * Props:
 *   compact    Boolean (default false) — hide the loaded-models table,
 *              show just the CPU/RAM/level line.
 *   csrfToken  String (required)
 *   pollMs     Number (default 8000) — 0 disables auto-refresh.
 */

const { ref, onMounted, onUnmounted } = Vue

export default {
    name: 'SystemStatusCard',
    delimiters: ['[[', ']]'],

    props: {
        compact:   { type: Boolean, default: false },
        csrfToken: { type: String,  required: true },
        pollMs:    { type: Number,  default: 8000 },
    },

    template: `
        <div class="card border-0 shadow-sm rounded-4" :class="compact ? 'mb-3' : 'mb-4'">
            <div class="card-body" :class="compact ? 'p-3' : 'p-4'">
                <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-2">
                    <div v-if="!compact" class="d-flex align-items-center gap-2">
                        <div style="width:3px;height:14px;background:#0d6efd;border-radius:2px;flex-shrink:0;"></div>
                        <span class="fw-bold" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.07em;color:var(--subtle-text-color);">
                            <i class="fa-solid fa-gauge-high me-1"></i>System status
                        </span>
                    </div>
                    <span v-else class="fw-bold small text-muted text-uppercase" style="letter-spacing:.05em;">
                        <i class="fa-solid fa-gauge-high me-1"></i>System
                    </span>
                    <span class="badge rounded-pill"
                          :class="{
                            'bg-success-subtle text-success-emphasis': level === 'ok',
                            'bg-warning-subtle text-warning-emphasis': level === 'warning',
                            'bg-danger-subtle text-danger-emphasis':   level === 'critical',
                            'bg-secondary-subtle text-secondary-emphasis': !level,
                          }">
                        [[ levelLabel ]]
                    </span>
                </div>

                <div v-if="!ollamaReachable" class="alert alert-danger py-2 px-3 mb-2" style="font-size:.82rem;">
                    <i class="fa-solid fa-triangle-exclamation me-1"></i>Ollama isn't reachable right now.
                </div>

                <div class="row g-3">
                    <div class="col-6" :class="compact ? 'col-md-3' : 'col-md-3'">
                        <div class="small text-muted mb-1">CPU</div>
                        <div class="progress rounded-pill" style="height:6px;">
                            <div class="progress-bar" :class="barClass(cpuPercent)" :style="{ width: cpuPercent + '%' }"></div>
                        </div>
                        <div class="small mt-1">[[ cpuPercent.toFixed(0) ]]% · [[ cpuCount ]] threads</div>
                    </div>
                    <div class="col-6" :class="compact ? 'col-md-3' : 'col-md-3'">
                        <div class="small text-muted mb-1">RAM</div>
                        <div class="progress rounded-pill" style="height:6px;">
                            <div class="progress-bar" :class="barClass(memory.percent)" :style="{ width: memory.percent + '%' }"></div>
                        </div>
                        <div class="small mt-1">[[ memory.available_gb ]] GB free / [[ memory.total_gb ]] GB</div>
                    </div>
                    <div class="col-6" :class="compact ? 'col-md-3' : 'col-md-3'">
                        <div class="small text-muted mb-1">Swap</div>
                        <div class="progress rounded-pill" style="height:6px;">
                            <div class="progress-bar" :class="barClass(swap.percent)" :style="{ width: swap.percent + '%' }"></div>
                        </div>
                        <div class="small mt-1">[[ swap.used_gb ]] / [[ swap.total_gb ]] GB</div>
                    </div>
                    <div class="col-6" :class="compact ? 'col-md-3' : 'col-md-3'" v-if="loadAvg">
                        <div class="small text-muted mb-1">Load avg</div>
                        <div class="small mt-1" style="padding-top:9px;">[[ loadAvg.map(n => n.toFixed(1)).join(' / ') ]]</div>
                    </div>
                </div>

                <div v-if="level === 'warning' || level === 'critical'" class="alert py-2 px-3 mt-3 mb-0"
                     :class="level === 'critical' ? 'alert-danger' : 'alert-warning'" style="font-size:.8rem;">
                    <i class="fa-solid fa-circle-info me-1"></i>
                    <span v-if="level === 'critical'">Very little RAM free — a model load can fail outright right now (this is exactly what happened this session with a 32B model on a 30GB box). Consider unloading a model below, or waiting.</span>
                    <span v-else>Getting tight — a larger model may run slower than usual or fail to load.</span>
                </div>

                <template v-if="!compact">
                    <hr class="my-3">
                    <div class="d-flex align-items-center justify-content-between mb-2">
                        <span class="small fw-semibold text-muted text-uppercase" style="letter-spacing:.05em;">Models loaded in memory</span>
                        <button class="btn btn-sm btn-outline-secondary rounded-pill px-2 py-0" @click="fetchStatus" title="Refresh">
                            <i class="fa-solid fa-rotate" style="font-size:.7rem;"></i>
                        </button>
                    </div>
                    <div v-if="!loadedModels.length" class="text-muted small">Nothing loaded right now.</div>
                    <div v-for="m in loadedModels" :key="m.name" class="d-flex align-items-center justify-content-between py-1" style="font-size:.82rem;">
                        <span class="font-monospace">[[ m.name ]]</span>
                        <span class="text-muted">[[ m.size_gb ]] GB[[ m.gpu ? ' · GPU' : '' ]]</span>
                        <button class="btn btn-sm btn-outline-danger rounded-pill px-2 py-0" @click="unload(m.name)" title="Unload now">
                            <i class="fa-solid fa-eject" style="font-size:.7rem;"></i>
                        </button>
                    </div>
                </template>
            </div>
        </div>
    `,

    setup(props) {
        const level          = ref(null)
        const cpuPercent     = ref(0)
        const cpuCount       = ref(0)
        const loadAvg        = ref(null)
        const memory         = ref({ total_gb: 0, used_gb: 0, available_gb: 0, percent: 0 })
        const swap           = ref({ total_gb: 0, used_gb: 0, percent: 0 })
        const ollamaReachable = ref(true)
        const loadedModels   = ref([])
        let pollTimer = null

        const levelLabel = () => ({ ok: 'OK', warning: 'Tight', critical: 'Critical' }[level.value] || '…')

        function barClass(pct) {
            if (pct >= 90) return 'bg-danger'
            if (pct >= 70) return 'bg-warning'
            return 'bg-success'
        }

        async function fetchStatus() {
            try {
                const res = await fetch('/ai/admin/system_status')
                if (!res.ok) return
                const data = await res.json()
                level.value = data.level
                cpuPercent.value = data.cpu_percent
                cpuCount.value = data.cpu_count
                loadAvg.value = data.load_avg
                memory.value = data.memory
                swap.value = data.swap
                ollamaReachable.value = data.ollama_reachable
                loadedModels.value = data.loaded_models || []
            } catch { /* keep last known values, don't flicker to an error state on one hiccup */ }
        }

        async function unload(modelName) {
            await fetch('/ai/admin/system_status/unload', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                body: JSON.stringify({ model: modelName }),
            })
            fetchStatus()
        }

        onMounted(() => {
            fetchStatus()
            if (props.pollMs > 0) pollTimer = setInterval(fetchStatus, props.pollMs)
        })
        onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })

        return {
            level, levelLabel: Vue.computed(levelLabel), cpuPercent, cpuCount, loadAvg,
            memory, swap, ollamaReachable, loadedModels,
            barClass, fetchStatus, unload,
        }
    },
}
