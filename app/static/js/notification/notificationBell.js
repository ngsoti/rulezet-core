/**
 * notificationBell.js
 * Vue 3 component for the notification bell in the navbar.
 *
 * Mounts on #notif-bell-app.
 * Opens/closes the #notifOffcanvas Bootstrap offcanvas.
 *
 * Polling strategy (mirrors jobWidget):
 *   - One fetch on mount.
 *   - Active 15 s poll while the offcanvas is open OR while there are active job notifications.
 *   - Stops automatically when nothing is active.
 *
 * Bell persistence rule for jobs:
 *   A job notification stays visible in the bell until BOTH:
 *     1. The job has reached a terminal state (done / failed / cancelled)
 *     2. The user has read it (clicked on it)
 */

const { createApp, ref, computed, onMounted, onUnmounted, watch } = Vue

const POLL_INTERVAL = 15_000


function csrf() {
    return document.getElementById('csrf_token')?.value || ''
}

async function apiFetch(url, opts = {}) {
    const res = await fetch(url, {
        headers: { 'X-CSRFToken': csrf(), 'Content-Type': 'application/json' },
        ...opts,
    })
    if (!res.ok) return null
    return res.json()
}

// ── Relative time helper (uses dayjs if available) ─────────────────────────────
function relativeTime(isoStr) {
    if (!isoStr) return ''
    try {
        if (window.dayjs) {
            return dayjs.utc(isoStr).fromNow()
        }
        const diff = Math.floor((Date.now() - new Date(isoStr + 'Z').getTime()) / 1000)
        if (diff < 60)   return 'just now'
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
        if (diff < 86400)return `${Math.floor(diff / 3600)}h ago`
        return `${Math.floor(diff / 86400)}d ago`
    } catch { return '' }
}

// ── Type → bubble CSS class ────────────────────────────────────────────────────
function bubbleClass(type) {
    return `notif-icon-bubble--${type}`
}

// ── Type → icon label ─────────────────────────────────────────────────────────
const TYPE_LABEL = {
    new_rule:           'New Rule',
    rule_update_found:  'Updates Found',
    job_created:        'Job Started',
    job_finished:       'Job Finished',
    job_failed:         'Job Failed',
}

// ── Component ──────────────────────────────────────────────────────────────────
const NotificationBell = {
    delimiters: ['[[', ']]'],

    setup() {
        const items           = ref([])
        const loading         = ref(true)
        const activeTab       = ref('all')   // 'all' | 'unread' | 'jobs'
        const offcanvasEl     = ref(null)
        const bannerDismissed = ref(false)
        let bsOffcanvas   = null
        let timer         = null
        let isOpen        = false

        // Read user preference from localStorage
        const notifStyle = computed(() => localStorage.getItem('rz-notif-style') || 'discrete')

        // ── Computed ─────────────────────────────────────────────────────────
        const unreadCount = computed(() => items.value.filter(n => !n.is_read).length)

        const showBanner = computed(() =>
            notifStyle.value === 'prominent' && unreadCount.value > 0 && !bannerDismissed.value
        )

        const filteredItems = computed(() => {
            if (activeTab.value === 'unread') return items.value.filter(n => !n.is_read)
            if (activeTab.value === 'jobs')   return items.value.filter(n => n.notif_type?.startsWith('job'))
            return items.value
        })

        const hasActiveJobs = computed(() =>
            items.value.some(n => n.is_job_active || n.notif_type === 'session_running')
        )

        // ── Fetch ─────────────────────────────────────────────────────────────
        async function fetchBell() {
            try {
                const data = await apiFetch('/notifications/bell')
                if (data) {
                    items.value = data
                    // Reset banner dismiss when new unread arrive
                    if (unreadCount.value > 0) bannerDismissed.value = false
                }
            } catch {}
            loading.value = false
        }

        // ── Polling ───────────────────────────────────────────────────────────
        function startPolling() {
            if (timer) return
            timer = setInterval(fetchBell, POLL_INTERVAL)
        }

        function stopPolling() {
            if (timer) { clearInterval(timer); timer = null }
        }

        function refreshPollingState() {
            if (isOpen || hasActiveJobs.value) {
                startPolling()
            } else {
                stopPolling()
            }
        }

        watch(hasActiveJobs, refreshPollingState)

        // ── Open / close offcanvas ────────────────────────────────────────────
        function openBell() {
            if (bsOffcanvas) {
                bsOffcanvas.show()
                isOpen = true
                startPolling()
                fetchBell()
            }
        }

        // ── Actions ───────────────────────────────────────────────────────────
        async function markRead(notif) {
            if (notif.is_read) return
            await apiFetch(`/notifications/${notif.id}/read`, { method: 'POST' })
            notif.is_read = true
        }

        async function deleteNotif(notif, event) {
            event.stopPropagation()
            event.preventDefault()
            await apiFetch(`/notifications/${notif.id}`, { method: 'DELETE' })
            items.value = items.value.filter(n => n.id !== notif.id)
        }

        async function markAllRead() {
            await apiFetch('/notifications/read_all', { method: 'POST' })
            items.value.forEach(n => { n.is_read = true })
        }

        async function clickNotif(notif) {
            await markRead(notif)
            if (notif.link) window.location.href = notif.link
        }

        function dismissBanner() { bannerDismissed.value = true }

        // ── Helpers ───────────────────────────────────────────────────────────
        function progressFillClass(notif) {
            if (notif.job_status === 'done')   return 'notif-progress__fill--done'
            if (notif.job_status === 'failed') return 'notif-progress__fill--failed'
            if (!notif.job_progress)           return 'notif-progress__fill--indeterminate'
            return ''
        }

        function progressWidth(notif) {
            if (notif.job_status === 'done') return '100%'
            if (!notif.job_progress)         return null  // indeterminate — width set in CSS
            return `${notif.job_progress}%`
        }

        function typeLabel(type) { return TYPE_LABEL[type] || type }

        // ── Lifecycle ─────────────────────────────────────────────────────────
        onMounted(() => {
            offcanvasEl.value = document.getElementById('notifOffcanvas')
            if (offcanvasEl.value && window.bootstrap?.Offcanvas) {
                bsOffcanvas = new bootstrap.Offcanvas(offcanvasEl.value)
                offcanvasEl.value.addEventListener('show.bs.offcanvas',  () => { isOpen = true;  startPolling() })
                offcanvasEl.value.addEventListener('hide.bs.offcanvas',  () => { isOpen = false; refreshPollingState() })
            }
            fetchBell()
            window.addEventListener('rz:job-created', () => { fetchBell(); startPolling() })
            window.addEventListener('rz:notif-read', fetchBell)
        })

        onUnmounted(() => {
            stopPolling()
        })

        return {
            items, loading, activeTab, unreadCount, showBanner,
            filteredItems, hasActiveJobs,
            openBell, markRead, deleteNotif, markAllRead, clickNotif, dismissBanner,
            progressFillClass, progressWidth,
            bubbleClass, typeLabel, relativeTime,
        }
    },

    template: `
<div>
    <!-- ── Bell trigger ── -->
    <button class="notif-bell-btn nav-icon-btn" @click="openBell" title="Notifications">
        <i class="fa-solid fa-bell fs-5"></i>
        <span v-if="unreadCount > 0"
              :class="['notif-bell-badge', 'notif-bell-badge--pulse']">
            [[ unreadCount > 99 ? '99+' : unreadCount ]]
        </span>
    </button>

    <!-- ── Prominent banner (teleported to body) ── -->
    <teleport to="body">
        <div v-if="showBanner" class="notif-prominent-banner">
            <i class="fa-solid fa-bell me-2"></i>
            <span>You have <strong>[[ unreadCount ]]</strong> unread notification[[ unreadCount !== 1 ? 's' : '' ]]</span>
            <a href="/notifications/" class="notif-prominent-banner__link">View all</a>
            <button class="notif-prominent-banner__dismiss" @click.stop="dismissBanner" title="Dismiss">
                <i class="fa-solid fa-xmark"></i>
            </button>
        </div>
    </teleport>
</div>
    `,
}

// ── Offcanvas content app ─────────────────────────────────────────────────────
const NotificationPanel = {
    delimiters: ['[[', ']]'],
    props: ['bellApp'],   // not used, panel is standalone but shares state via window events

    setup() {
        const items       = ref([])
        const jobItems    = ref([])
        const loading     = ref(true)
        const activeTab   = ref('all')
        let timer         = null

        async function fetchBell() {
            try {
                const data = await apiFetch('/notifications/bell')
                // Jobs live exclusively in the "Jobs" tab (via fetchJobs below) —
                // keep them out of "All" so they're not shown in both places.
                if (data) items.value = data.filter(n => !n.notif_type?.startsWith('job'))
            } catch {}
            loading.value = false
        }

        // The "Jobs" tab has its own feed: get_bell_items() purges a job
        // notification as soon as it's both finished AND read, so filtering
        // `items` client-side left this tab empty most of the time. This
        // dedicated feed keeps recent jobs visible regardless of read status.
        async function fetchJobs() {
            try {
                const data = await apiFetch('/notifications/bell/jobs')
                if (data) jobItems.value = data
            } catch {}
        }

        const unreadCount    = computed(() => items.value.filter(n => !n.is_read).length)
        const unreadJobCount = computed(() => jobItems.value.filter(n => !n.is_read).length)
        const filteredItems = computed(() => {
            if (activeTab.value === 'jobs') return jobItems.value
            return items.value
        })
        const hasActiveJobs = computed(() =>
            items.value.some(n => n.notif_type === 'session_running') ||
            jobItems.value.some(n => n.is_job_active)
        )

        function fetchAll() { fetchBell(); fetchJobs() }

        function startPolling() {
            if (timer) return
            timer = setInterval(fetchAll, POLL_INTERVAL)
        }
        function stopPolling() {
            if (timer) { clearInterval(timer); timer = null }
        }
        watch(hasActiveJobs, v => { v ? startPolling() : stopPolling() })

        async function markRead(notif) {
            if (notif.is_read) return
            await apiFetch(`/notifications/${notif.id}/read`, { method: 'POST' })
            notif.is_read = true
            // Read notifications drop out of the bell immediately, so the
            // panel visibly empties out as things get handled.
            items.value = items.value.filter(n => n.id !== notif.id)
            jobItems.value = jobItems.value.filter(n => n.id !== notif.id)
            window.dispatchEvent(new Event('rz:notif-read'))
        }
        async function deleteNotif(notif, event) {
            event.stopPropagation(); event.preventDefault()
            await apiFetch(`/notifications/${notif.id}`, { method: 'DELETE' })
            items.value = items.value.filter(n => n.id !== notif.id)
            jobItems.value = jobItems.value.filter(n => n.id !== notif.id)
            window.dispatchEvent(new Event('rz:notif-read'))
        }
        async function markAllRead() {
            await apiFetch('/notifications/read_all', { method: 'POST' })
            items.value = []
            jobItems.value = []
            window.dispatchEvent(new Event('rz:notif-read'))
        }
        async function clickNotif(notif) {
            await markRead(notif)
            if (notif.link) window.location.href = notif.link
        }

        function progressFillClass(notif) {
            if (notif.job_status === 'done')   return 'notif-progress__fill--done'
            if (notif.job_status === 'failed') return 'notif-progress__fill--failed'
            if (!notif.job_progress)           return 'notif-progress__fill--indeterminate'
            return ''
        }
        function progressWidth(notif) {
            if (notif.job_status === 'done') return '100%'
            if (!notif.job_progress)         return null
            return `${notif.job_progress}%`
        }

        onMounted(() => {
            const el = document.getElementById('notifOffcanvas')
            if (el) {
                el.addEventListener('show.bs.offcanvas', () => { fetchAll(); startPolling() })
                el.addEventListener('hide.bs.offcanvas', () => { if (!hasActiveJobs.value) stopPolling() })
            }
            fetchAll()
            window.addEventListener('rz:job-created', () => { fetchAll(); startPolling() })
        })
        onUnmounted(stopPolling)

        return {
            items, jobItems, loading, activeTab, unreadCount, unreadJobCount, filteredItems, hasActiveJobs,
            markRead, deleteNotif, markAllRead, clickNotif,
            progressFillClass, progressWidth,
            bubbleClass, typeLabel: t => TYPE_LABEL[t] || t, relativeTime,
        }
    },

    template: `
<div class="d-flex flex-column h-100">

    <!-- Header -->
    <div class="notif-offcanvas-header">
        <div class="notif-offcanvas-header__left">
            <div class="notif-offcanvas-header__icon">
                <i class="fa-solid fa-bell"></i>
            </div>
            <div>
                <div class="notif-offcanvas-header__title">Notifications</div>
                <div class="notif-offcanvas-header__sub" v-if="unreadCount > 0">
                    <span class="notif-offcanvas-header__badge">[[ unreadCount ]]</span>
                    unread
                </div>
                <div class="notif-offcanvas-header__sub" v-else>All caught up</div>
            </div>
        </div>
        <div class="d-flex align-items-center gap-2">
            <a href="/notifications/" class="notif-offcanvas-header__action" title="Notification settings">
                <i class="fa-solid fa-sliders"></i>
            </a>
            <button type="button" class="notif-offcanvas-header__close" data-bs-dismiss="offcanvas" title="Close">
                <i class="fa-solid fa-xmark"></i>
            </button>
        </div>
    </div>

    <!-- Tabs -->
    <div class="notif-tabs">
        <button class="notif-tab" :class="{active: activeTab==='all'}"    @click="activeTab='all'">
            <i class="fa-solid fa-list me-1" style="font-size:.7rem;"></i>All
            <span v-if="unreadCount > 0" class="notif-tab-badge">[[ unreadCount ]]</span>
        </button>
        <button class="notif-tab" :class="{active: activeTab==='jobs'}"   @click="activeTab='jobs'">
            <i class="fa-solid fa-gears me-1" style="font-size:.7rem;"></i>Jobs
            <span v-if="unreadJobCount > 0" class="notif-tab-badge">[[ unreadJobCount ]]</span>
        </button>
    </div>

    <!-- Toolbar -->
    <div class="notif-toolbar" v-if="filteredItems.length > 0 || unreadCount > 0">
        <span class="notif-toolbar-count">
            [[ filteredItems.length ]] notification[[ filteredItems.length !== 1 ? 's' : '' ]]
        </span>
        <div class="notif-toolbar-actions">
            <button class="notif-toolbar-btn" @click="markAllRead" v-if="unreadCount > 0">
                <i class="fa-solid fa-check-double me-1"></i>Mark all read
            </button>
        </div>
    </div>

    <!-- List -->
    <div class="notif-list-wrap">

        <!-- Loading skeleton -->
        <template v-if="loading">
            <div v-for="i in 4" :key="i" class="notif-skeleton">
                <div class="notif-skeleton__bubble"></div>
                <div class="notif-skeleton__lines">
                    <div class="notif-skeleton__line"></div>
                    <div class="notif-skeleton__line"></div>
                </div>
            </div>
        </template>

        <!-- Empty state -->
        <template v-else-if="filteredItems.length === 0">
            <div class="notif-empty">
                <div class="notif-empty__icon"><i class="fa-solid fa-bell-slash"></i></div>
                <div class="notif-empty__title">All caught up!</div>
                <div class="notif-empty__sub">No notifications to show.</div>
            </div>
        </template>

        <!-- Items -->
        <template v-else>
            <div v-for="notif in filteredItems" :key="notif.id"
                 :class="['notif-item', !notif.is_read ? 'unread' : '']"
                 @click="clickNotif(notif)">

                <!-- Icon bubble -->
                <div :class="['notif-icon-bubble', bubbleClass(notif.notif_type)]">
                    <i :class="notif.icon || 'fa-solid fa-bell'"></i>
                </div>

                <!-- Content -->
                <div class="notif-content">
                    <div class="notif-title">[[ notif.title ]]</div>
                    <div class="notif-body" v-if="notif.body">[[ notif.body ]]</div>

                    <!-- Job progress -->
                    <template v-if="notif.notif_type?.startsWith('job')">
                        <div class="notif-progress mt-2">
                            <div :class="['notif-progress__fill', progressFillClass(notif)]"
                                 :style="progressWidth(notif) ? \`width:\${progressWidth(notif)}\` : ''">
                            </div>
                        </div>
                        <div style="font-size:.68rem;color:var(--subtle-text-color);margin-top:3px;">
                            <span v-if="notif.job_status === 'done'" class="text-success fw-semibold">
                                <i class="fa-solid fa-circle-check me-1"></i>Completed — 100%
                            </span>
                            <span v-else-if="notif.job_status === 'failed'" class="text-danger fw-semibold">
                                <i class="fa-solid fa-circle-xmark me-1"></i>Failed
                            </span>
                            <span v-else-if="notif.job_status === 'cancelled'" class="text-muted">
                                <i class="fa-solid fa-ban me-1"></i>Cancelled
                            </span>
                            <span v-else class="text-primary">
                                <i class="fa-solid fa-circle-notch fa-spin me-1"></i>
                                [[ notif.job_progress ? notif.job_progress + '%' : 'Running…' ]]
                            </span>
                        </div>
                    </template>

                    <div class="notif-time">[[ relativeTime(notif.created_at) ]]</div>
                </div>

                <!-- Actions -->
                <div class="notif-actions">
                    <button class="notif-action-btn notif-action-btn--read"
                            title="Mark as read"
                            v-if="!notif.is_read"
                            @click.stop="markRead(notif)">
                        <i class="fa-solid fa-check"></i>
                    </button>
                    <button class="notif-action-btn notif-action-btn--delete"
                            title="Delete"
                            @click="deleteNotif(notif, $event)">
                        <i class="fa-solid fa-xmark"></i>
                    </button>
                </div>
            </div>
        </template>
    </div>

    <!-- Footer -->
    <div class="notif-footer">
        <a href="/notifications/" class="notif-footer__all">
            <i class="fa-solid fa-arrow-right me-1"></i>See all notifications
        </a>
        <a href="/settings" class="notif-footer__settings" title="Notification settings">
            <i class="fa-solid fa-gear"></i>
        </a>
    </div>

</div>
    `,
}


// ── Mount ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const bellEl  = document.getElementById('notif-bell-app')
    const panelEl = document.getElementById('notif-panel-app')

    if (bellEl) {
        createApp(NotificationBell).mount('#notif-bell-app')
    }
    if (panelEl) {
        createApp(NotificationPanel).mount('#notif-panel-app')
    }
})
