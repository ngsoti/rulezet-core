/**
 * mispTable.js — MISP instance connection management table.
 *
 * Mirrors app/static/js/velociraptor/velociraptorTable.js — same per-row
 * expandable activity history (server create/update/delete, connection
 * tests, push triggered/done), same "2 then +5 per click" pagination.
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
  if (!s.is_active) return 'msp-status--inactive'
  if (s.last_error) return 'msp-status--error'
  if (s.is_verified) return 'msp-status--ok'
  return 'msp-status--pending'
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

const MispRow = {
  name: 'MispRow',
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
          const r = await fetch(`/misp/history/${props.s.uuid}`)
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
        const r = await doPost(`/misp/test/${props.s.uuid}`)
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
        const r = await doPost(`/misp/toggle_active/${props.s.uuid}`)
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
      if (!confirm(`Delete MISP server "${props.s.name}"? This cannot be undone.`)) return
      const r = await doPost(`/misp/delete/${props.s.uuid}`)
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
<tr class="msp-tr">
  <td class="msp-td">
    <div class="d-flex align-items-center gap-2">
      <div class="msp-icon-sm" :class="s.is_verified ? 'msp-icon-sm--ok' : (s.last_error ? 'msp-icon-sm--err' : '')">
        <img src="/static/custom-icon/misp.svg" alt="MISP" style="height:22px;width:22px;object-fit:contain;vertical-align:-2px;">
      </div>
      <div>
        <div class="fw-semibold" style="font-size:.88rem;">[[ s.name ]]</div>
        <div v-if="s.description" style="font-size:.72rem;color:var(--subtle-text-color);">[[ s.description ]]</div>
      </div>
    </div>
  </td>
  <td class="msp-td">
    <span :class="['msp-status', statusClass(s)]">
      <i :class="statusIcon(s)"></i> [[ statusLabel(s) ]]
    </span>
    <div v-if="s.last_error" class="text-danger text-truncate" style="font-size:.7rem;max-width:220px;" :title="s.last_error">
      [[ s.last_error ]]
    </div>
  </td>
  <td class="msp-td d-none d-md-table-cell" style="font-size:.8rem;">[[ s.url ]]</td>
  <td class="msp-td d-none d-lg-table-cell" style="font-size:.82rem;">[[ s.pushes_count ]]</td>
  <td class="msp-td d-none d-xl-table-cell" style="font-size:.75rem;color:var(--subtle-text-color);">[[ s.last_push_at || '—' ]]</td>
  <td class="msp-td msp-td--actions">
    <div class="msp-actions">
      <button class="msp-btn" title="History" @click="toggleHistory" :class="{ 'msp-btn--active': expanded }">
        <i class="fa-solid fa-clock-rotate-left"></i>
      </button>
      <button class="msp-btn" title="Test connection" @click="testServer" :disabled="actionBusy">
        <span v-if="actionBusy" class="spinner-border spinner-border-sm"></span>
        <i v-else class="fa-solid fa-wifi"></i>
      </button>
      <button class="msp-btn" title="Edit" @click="$emit('edit', s)">
        <i class="fa-solid fa-pen-to-square"></i>
      </button>
      <button class="msp-btn" :title="s.is_active ? 'Disable' : 'Enable'" @click="toggleActive" :disabled="actionBusy">
        <i :class="s.is_active ? 'fa-solid fa-pause' : 'fa-solid fa-play'"></i>
      </button>
      <button class="msp-btn msp-btn--danger" title="Delete" @click="deleteServer">
        <i class="fa-solid fa-trash"></i>
      </button>
    </div>
  </td>
</tr>
<tr v-if="expanded" class="msp-tr-expand">
  <td colspan="6">
    <div class="msp-history-panel">
      <div v-if="historyLoading" class="text-center py-3">
        <div class="spinner-border spinner-border-sm text-primary"></div>
      </div>
      <div v-else-if="!historyItems.length" class="text-muted text-center py-3" style="font-size:.82rem;">
        No activity recorded yet.
      </div>
      <template v-else>
        <div class="msp-timeline">
          <div v-for="(e, idx) in visibleHistory" :key="e.timestamp+e.action+idx" class="msp-timeline-item">
            <div class="msp-timeline-dot" :class="'msp-timeline-dot--'+dotClass(e)"></div>
            <div class="msp-timeline-content">
              <div class="msp-timeline-header">
                <span :class="['badge', 'me-1', actionBadgeClass(e)]" style="font-size:.6rem;">
                  <i :class="actionIcon(e)"></i> [[ e.action ? e.action.split('.').pop() : '?' ]]
                </span>
                <span class="msp-timeline-ts">[[ e.timestamp ]]</span>
              </div>
              <div class="msp-timeline-desc">
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
  name: 'MispTable',
  delimiters: ['[[', ']]'],
  components: { 'misp-row': MispRow },
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
        (s.name + s.url + (s.description || '')).toLowerCase().includes(q)
      )
    })

    async function refresh() {
      loading.value = true
      try {
        const r = await fetch('/misp/get')
        servers.value = await r.json()
      } catch {
        create_message('Failed to load MISP servers.', 'danger')
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
<div class="msp-wrapper">

  <!-- Toolbar -->
  <div class="msp-toolbar">
    <div class="msp-toolbar-left">
      <div class="msp-search-wrap">
        <i class="fa-solid fa-magnifying-glass msp-search-icon"></i>
        <input class="msp-search-input" type="text" placeholder="Search servers…" v-model="search" />
      </div>
      <span class="msp-count">[[ filtered.length ]] server[[ filtered.length!==1?'s':'' ]]</span>
    </div>
    <div class="msp-toolbar-right">
      <button class="btn btn-primary btn-sm rounded-pill px-3" @click="$emit('create')">
        <i class="fa-solid fa-plus me-1"></i>Add instance
      </button>
    </div>
  </div>

  <!-- Loading -->
  <div v-if="loading" class="text-center py-5">
    <div class="spinner-border text-primary"></div>
  </div>

  <!-- Empty -->
  <div v-else-if="filtered.length === 0" class="msp-empty">
    <div class="msp-empty__icon"><i class="fa-solid fa-share-nodes"></i></div>
    <p class="mb-0">No MISP instances configured yet.</p>
  </div>

  <!-- Table -->
  <div v-else class="msp-table-wrap">
    <table class="msp-table">
      <thead class="msp-thead">
        <tr>
          <th class="msp-th">Instance</th>
          <th class="msp-th">Status</th>
          <th class="msp-th d-none d-md-table-cell">URL</th>
          <th class="msp-th d-none d-lg-table-cell">Pushes</th>
          <th class="msp-th d-none d-xl-table-cell">Last push</th>
          <th class="msp-th msp-th--actions">Actions</th>
        </tr>
      </thead>
      <tbody>
        <misp-row
          v-for="s in filtered" :key="s.uuid"
          :s="s" :csrf-token="csrfToken"
          @edit="$emit('edit', $event)"
          @refresh="refresh">
        </misp-row>
      </tbody>
    </table>
  </div>

</div>
`,
}
