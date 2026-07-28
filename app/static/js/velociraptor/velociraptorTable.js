/**
 * velociraptorTable.js — Velociraptor server connection management table.
 *
 * Mirrors the fetch/response conventions of connector/connectorTable.js,
 * including the per-row expandable activity history (server create/update/
 * delete, connection tests, push triggered/done) — same lazy-load-on-first-
 * expand + "2 then +5 per click" pagination as ConnectorRow's history panel.
 *
 * Props:
 *   csrfToken    String   — CSRF token for POST requests
 *
 * Emits:
 *   create       — user clicked "Add"
 *   edit         — user clicked "Edit" on a server row (passes the server object)
 *
 * Exposed:
 *   refresh()    — re-fetch servers (call via template ref)
 */

import { create_message } from '/static/js/toaster.js'

const { ref, computed, onMounted } = Vue

function statusClass(s) {
  if (!s.is_active) return 'vrp-status--inactive'
  if (s.last_error) return 'vrp-status--error'
  if (s.is_verified) return 'vrp-status--ok'
  return 'vrp-status--pending'
}
function statusLabel(s) {
  if (!s.is_active) return 'Inactive'
  if (s.last_error) return 'Error'
  if (s.is_verified) return 'Verified'
  return 'Pending'
}
function statusIcon(s) {
  if (!s.is_active) return 'fa-solid fa-pause'
  if (s.last_error) return 'fa-solid fa-circle-exclamation'
  if (s.is_verified) return 'fa-solid fa-circle-check'
  return 'fa-solid fa-circle-question'
}

// ── History timeline helpers ─────────────────────────────────────────────────
// A push_done entry can represent either a success or a failure (extra.success),
// so unlike the other action kinds it needs the whole entry, not just the action
// name, to pick the right color.
function pushFailed(e) {
  return !!(e && e.action && e.action.includes('push_done') && e.extra && e.extra.success === false)
}
function actionBadgeClass(e) {
  if (!e || !e.action) return 'bg-secondary'
  if (pushFailed(e)) return 'bg-danger'
  if (e.action.includes('push_done'))      return 'bg-success'
  if (e.action.includes('push_triggered')) return 'bg-primary'
  if (e.action.includes('test_ok'))        return 'bg-info text-dark'
  if (e.action.includes('server_create'))  return 'bg-secondary'
  if (e.action.includes('server_delete'))  return 'bg-danger'
  if (e.action.includes('server_update'))  return 'bg-warning text-dark'
  return 'bg-secondary'
}
function actionIcon(e) {
  if (!e || !e.action) return 'fa-solid fa-circle'
  if (pushFailed(e)) return 'fa-solid fa-triangle-exclamation'
  if (e.action.includes('push_done'))      return 'fa-solid fa-flag-checkered'
  if (e.action.includes('push_triggered')) return 'fa-solid fa-paper-plane'
  if (e.action.includes('test_ok'))        return 'fa-solid fa-wifi'
  if (e.action.includes('server_create'))  return 'fa-solid fa-plus'
  if (e.action.includes('server_delete'))  return 'fa-solid fa-trash'
  if (e.action.includes('server_update'))  return 'fa-solid fa-pen'
  return 'fa-solid fa-circle'
}
function dotClass(e) {
  if (!e || !e.action) return 'neutral'
  if (pushFailed(e)) return 'danger'
  if (e.action.includes('push_done'))      return 'success'
  if (e.action.includes('push_triggered')) return 'primary'
  if (e.action.includes('test_ok'))        return 'info'
  if (e.action.includes('server_delete'))  return 'danger'
  if (e.action.includes('server_update'))  return 'warning'
  return 'neutral'
}

const VelociraptorRow = {
  name: 'VelociraptorRow',
  delimiters: ['[[', ']]'],
  props: {
    s: { type: Object, required: true },
    csrfToken: { type: String, required: true },
  },
  emits: ['edit', 'refresh'],
  setup(props, { emit }) {
    const actionBusy = ref(false)

    const expanded       = ref(false)
    const historyLoaded  = ref(false)
    const historyItems   = ref([])
    const historyLoading = ref(false)
    const historyPage    = ref(2)

    const visibleHistory = computed(() => historyItems.value.slice(0, historyPage.value))
    const hasMoreHistory = computed(() => historyPage.value < historyItems.value.length)
    function loadMoreHistory() { historyPage.value += 5 }

    async function toggleHistory() {
      expanded.value = !expanded.value
      if (expanded.value && !historyLoaded.value) {
        historyLoading.value = true
        try {
          const r = await fetch(`/velociraptor/history/${props.s.uuid}`)
          historyItems.value  = await r.json()
          historyLoaded.value = true
        } catch { historyItems.value = [] }
        finally { historyLoading.value = false }
      }
    }

    async function doPost(url, body = {}) {
      return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
        body: JSON.stringify(body),
      })
    }

    async function testServer() {
      actionBusy.value = true
      try {
        const r = await doPost(`/velociraptor/test/${props.s.uuid}`)
        const data = await r.json()
        create_message(data.message || (data.success ? 'OK' : 'Failed'), data.success ? 'success' : 'danger')
        historyLoaded.value = false   // a new test just wrote a history entry — refetch on next expand
        emit('refresh')
      } finally {
        actionBusy.value = false
      }
    }

    async function toggleActive() {
      actionBusy.value = true
      try {
        const r = await doPost(`/velociraptor/toggle_active/${props.s.uuid}`)
        const data = await r.json()
        if (data.success) {
          props.s.is_active = data.is_active
        } else {
          create_message(data.error || 'Failed to update.', 'danger')
        }
      } finally {
        actionBusy.value = false
      }
    }

    async function deleteServer() {
      if (!confirm(`Delete Velociraptor server "${props.s.name}"? This cannot be undone.`)) return
      const r = await doPost(`/velociraptor/delete/${props.s.uuid}`)
      const data = await r.json()
      if (data.success) {
        create_message('Server deleted.', 'success')
        emit('refresh')
      } else {
        create_message(data.error || 'Delete failed.', 'danger')
      }
    }

    return {
      actionBusy, expanded, historyLoading, historyItems, visibleHistory, hasMoreHistory,
      statusClass, statusLabel, statusIcon,
      actionBadgeClass, actionIcon, dotClass,
      toggleHistory, loadMoreHistory, testServer, toggleActive, deleteServer,
    }
  },
  template: `
<tr class="vrp-tr">
  <td class="vrp-td">
    <div class="d-flex align-items-center gap-2">
      <div class="vrp-icon-sm" :class="s.is_verified ? 'vrp-icon-sm--ok' : (s.last_error ? 'vrp-icon-sm--err' : '')">
        <img src="/static/custom-icon/velociraptor-remove-bg.svg" alt="Velociraptor" style="height:24px;width:24px;object-fit:contain;vertical-align:-2px;" class="me-1">
      </div>
      <div>
        <div class="fw-semibold" style="font-size:.88rem;">[[ s.name ]]</div>
        <div v-if="s.description" style="font-size:.72rem;color:var(--subtle-text-color);">[[ s.description ]]</div>
      </div>
    </div>
  </td>
  <td class="vrp-td">
    <span :class="['vrp-status', statusClass(s)]">
      <i :class="statusIcon(s)"></i> [[ statusLabel(s) ]]
    </span>
    <div v-if="s.last_error" class="text-danger text-truncate" style="font-size:.7rem;max-width:220px;" :title="s.last_error">
      [[ s.last_error ]]
    </div>
  </td>
  <td class="vrp-td d-none d-md-table-cell" style="font-size:.8rem;">[[ s.api_connection_string ]]</td>
  <td class="vrp-td d-none d-lg-table-cell" style="font-size:.82rem;">[[ s.artifacts_pushed ]]</td>
  <td class="vrp-td d-none d-xl-table-cell" style="font-size:.75rem;color:var(--subtle-text-color);">[[ s.last_push_at || '—' ]]</td>
  <td class="vrp-td vrp-td--actions">
    <div class="vrp-actions">
      <button class="vrp-btn" title="History" @click="toggleHistory" :class="{ 'vrp-btn--active': expanded }">
        <i class="fa-solid fa-clock-rotate-left"></i>
      </button>
      <button class="vrp-btn" title="Test connection" @click="testServer" :disabled="actionBusy">
        <span v-if="actionBusy" class="spinner-border spinner-border-sm"></span>
        <i v-else class="fa-solid fa-wifi"></i>
      </button>
      <button class="vrp-btn" title="Edit" @click="$emit('edit', s)">
        <i class="fa-solid fa-pen-to-square"></i>
      </button>
      <button class="vrp-btn" :title="s.is_active ? 'Disable' : 'Enable'" @click="toggleActive" :disabled="actionBusy">
        <i :class="s.is_active ? 'fa-solid fa-pause' : 'fa-solid fa-play'"></i>
      </button>
      <button class="vrp-btn vrp-btn--danger" title="Delete" @click="deleteServer">
        <i class="fa-solid fa-trash"></i>
      </button>
    </div>
  </td>
</tr>
<tr v-if="expanded" class="vrp-tr-expand">
  <td colspan="6">
    <div class="vrp-history-panel">
      <div v-if="historyLoading" class="text-center py-3">
        <div class="spinner-border spinner-border-sm text-primary"></div>
      </div>
      <div v-else-if="!historyItems.length" class="text-muted text-center py-3" style="font-size:.82rem;">
        No activity recorded yet.
      </div>
      <template v-else>
        <div class="vrp-timeline">
          <div v-for="(e, idx) in visibleHistory" :key="e.timestamp+e.action+idx" class="vrp-timeline-item">
            <div class="vrp-timeline-dot" :class="'vrp-timeline-dot--'+dotClass(e)"></div>
            <div class="vrp-timeline-content">
              <div class="vrp-timeline-header">
                <span :class="['badge', 'me-1', actionBadgeClass(e)]" style="font-size:.6rem;">
                  <i :class="actionIcon(e)"></i> [[ e.action ? e.action.split('.').pop() : '?' ]]
                </span>
                <span class="vrp-timeline-ts">[[ e.timestamp ]]</span>
              </div>
              <div class="vrp-timeline-desc">
                [[ e.description ]]
                <a v-if="e.extra && e.extra.rule_uuid"
                   :href="'/rule/detail_rule/' + e.extra.rule_uuid" target="_blank"
                   class="ms-1 text-decoration-none" style="font-size:.75rem;white-space:nowrap;">
                  <i class="fa-solid fa-arrow-up-right-from-square me-1"></i>[[ e.extra.rule_title || 'View rule' ]]
                </a>
              </div>
            </div>
          </div>
        </div>
        <div v-if="hasMoreHistory" class="text-center pt-2">
          <button class="btn btn-sm btn-outline-secondary rounded-pill px-3" style="font-size:.75rem;" @click="loadMoreHistory">
            <i class="fa-solid fa-chevron-down me-1"></i>Show more
            <span class="text-muted ms-1">([[ historyItems.length - visibleHistory.length ]] hidden)</span>
          </button>
        </div>
      </template>
    </div>
  </td>
</tr>
`,
}

export default {
  name: 'VelociraptorTable',
  delimiters: ['[[', ']]'],
  components: { 'velociraptor-row': VelociraptorRow },
  props: {
    csrfToken: { type: String, required: true },
  },
  emits: ['create', 'edit'],
  expose: ['refresh'],

  setup(props, { emit }) {
    const servers = ref([])
    const loading = ref(true)
    const search = ref('')

    const filtered = computed(() => {
      const q = search.value.toLowerCase()
      if (!q) return servers.value
      return servers.value.filter(s =>
        (s.name + s.api_connection_string + (s.description || '')).toLowerCase().includes(q)
      )
    })

    async function refresh() {
      loading.value = true
      try {
        const r = await fetch('/velociraptor/get')
        servers.value = await r.json()
      } catch {
        create_message('Failed to load Velociraptor servers.', 'danger')
      } finally {
        loading.value = false
      }
    }

    onMounted(refresh)

    return {
      servers, loading, search, filtered,
      refresh,
    }
  },

  template: `
<div class="vrp-wrapper">

  <!-- Toolbar -->
  <div class="vrp-toolbar">
    <div class="vrp-toolbar-left">
      <div class="vrp-search-wrap">
        <i class="fa-solid fa-magnifying-glass vrp-search-icon"></i>
        <input class="vrp-search-input" type="text" placeholder="Search servers…" v-model="search" />
      </div>
      <span class="vrp-count">[[ filtered.length ]] server[[ filtered.length!==1?'s':'' ]]</span>
    </div>
    <div class="vrp-toolbar-right">
      <button class="btn btn-primary btn-sm rounded-pill px-3" @click="$emit('create')">
        <i class="fa-solid fa-plus me-1"></i>Add server
      </button>
    </div>
  </div>

  <!-- Loading -->
  <div v-if="loading" class="text-center py-5">
    <div class="spinner-border text-primary"></div>
  </div>

  <!-- Empty -->
  <div v-else-if="filtered.length === 0" class="vrp-empty">
    <div class="vrp-empty__icon"><i class="fa-solid fa-server"></i></div>
    <p class="mb-0">No Velociraptor servers configured yet.</p>
  </div>

  <!-- Table -->
  <div v-else class="vrp-table-wrap">
    <table class="vrp-table">
      <thead class="vrp-thead">
        <tr>
          <th class="vrp-th">Server</th>
          <th class="vrp-th">Status</th>
          <th class="vrp-th d-none d-md-table-cell">Connection</th>
          <th class="vrp-th d-none d-lg-table-cell">Artifacts pushed</th>
          <th class="vrp-th d-none d-xl-table-cell">Last push</th>
          <th class="vrp-th vrp-th--actions">Actions</th>
        </tr>
      </thead>
      <tbody>
        <velociraptor-row
          v-for="s in filtered" :key="s.uuid"
          :s="s" :csrf-token="csrfToken"
          @edit="$emit('edit', $event)"
          @refresh="refresh">
        </velociraptor-row>
      </tbody>
    </table>
  </div>

</div>
`,
}
