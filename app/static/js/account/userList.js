/**
 * userList.js — Admin user list component (card + table views).
 *
 * Props:
 *   fetchUrl        String   default: '/account/users_data_table'
 *   currentUserId   Number
 *   defaultView     String   'card'|'table'   default: 'card'
 *   initialPerPage  Number   default: 20
 *   syncUrl         Boolean  default: true
 *
 * Events:
 *   toggle-admin(user)
 *   delete-user(user)
 *
 * Expose:
 *   fetchData()
 */

import PaginationComponent from '/static/js/rule/paginationComponent.js'
import UserChip            from '/static/js/components/UserChip.js'
import { apiFetch }        from '/static/js/constants.js'
import { create_message }  from '/static/js/toaster.js'

const { ref, reactive, computed, watch, onMounted, onUnmounted } = Vue

export default {
    name: 'UserList',
    components: { PaginationComponent, UserChip },

    props: {
        fetchUrl:       { type: String,           default: '/account/users_data_table' },
        currentUserId:  { type: [Number, String], default: null },
        defaultView:    { type: String,           default: 'table' },
        initialPerPage: { type: Number,           default: 20 },
        syncUrl:        { type: Boolean,          default: true },
    },

    emits: ['toggle-admin', 'delete-user'],
    expose: ['fetchData'],

    template: `
    <div class="ul-wrapper">

        <!-- ── Toolbar ── -->
        <div class="ul-toolbar">
            <div class="ul-toolbar-left">
                <div class="dt-search">
                    <i class="fas fa-search dt-search-icon"></i>
                    <input class="dt-search-input" type="text" v-model="search"
                           placeholder="Search users…" @input="onSearchInput" />
                    <button v-if="search" class="dt-search-clear" @click="clearSearch">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>
                <span v-if="!loading" class="text-muted small ms-2 text-nowrap">
                    <strong>{{ total }}</strong> user<span v-if="total !== 1">s</span>
                </span>
            </div>

            <div class="ul-toolbar-right">
                <!-- Sort (card) -->
                <select v-if="viewMode === 'card'" v-model="cardSort" @change="onCardSortChange"
                        class="rl-sort-select">
                    <option value="newest">Newest</option>
                    <option value="oldest">Oldest</option>
                    <option value="name_asc">A → Z</option>
                    <option value="last_seen">Last active</option>
                </select>

                <!-- View toggle -->
                <div class="dt-view-toggle">
                    <button class="dt-view-btn" :class="{ 'dt-view-btn--active': viewMode === 'card' }"
                            @click="viewMode = 'card'">
                        <i class="fas fa-id-card"></i>
                    </button>
                    <button class="dt-view-btn" :class="{ 'dt-view-btn--active': viewMode === 'table' }"
                            @click="viewMode = 'table'">
                        <i class="fas fa-table-cells-large"></i>
                    </button>
                </div>

                <!-- Blur toggle -->
                <button class="dt-toolbar-btn" :class="{ 'dt-toolbar-btn--active': !blurEnabled }"
                        @click="blurEnabled = !blurEnabled; revealedIds.clear()"
                        title="Toggle sensitive data blur">
                    <i :class="blurEnabled ? 'fas fa-eye-slash' : 'fas fa-eye'"></i>
                    <span>{{ blurEnabled ? 'Blurred' : 'Visible' }}</span>
                </button>

                <!-- Per-page (table) -->
                <div v-if="viewMode === 'table'" class="rl-per-page">
                    <span>Rows</span>
                    <select v-model="perPageModel">
                        <option v-for="n in [10,20,50,100]" :key="n" :value="n">{{ n }}</option>
                    </select>
                </div>

                <!-- Filters open -->
                <button class="dt-toolbar-btn" :class="{ 'dt-toolbar-btn--active': filtersOpen }"
                        @click="filtersOpen = !filtersOpen">
                    <i class="fas fa-sliders"></i>
                    <span>Filters</span>
                    <span v-if="activeFilterCount > 0" class="rl-filter-badge ms-1">{{ activeFilterCount }}</span>
                </button>
            </div>
        </div>

        <!-- ── Filter panel ── -->
        <div v-show="filtersOpen" class="rl-filter-panel">
            <div class="rl-fp-row">

                <!-- Admin status -->
                <div class="ul-filter-group">
                    <span class="rl-fp-multi-label"><i class="fas fa-user-shield text-warning me-1"></i>Role</span>
                    <div class="ul-toggle-group">
                        <button :class="['ul-toggle-btn', adminFilter === '' ? 'ul-toggle-btn--active' : '']"
                                @click="adminFilter = ''; onFilterChange()">All</button>
                        <button :class="['ul-toggle-btn', adminFilter === 'true' ? 'ul-toggle-btn--active' : '']"
                                @click="adminFilter = 'true'; onFilterChange()">
                            <i class="fas fa-shield-halved me-1"></i>Admin
                        </button>
                        <button :class="['ul-toggle-btn', adminFilter === 'false' ? 'ul-toggle-btn--active' : '']"
                                @click="adminFilter = 'false'; onFilterChange()">
                            <i class="fas fa-user me-1"></i>User
                        </button>
                    </div>
                </div>

                <!-- Connection status -->
                <div class="ul-filter-group">
                    <span class="rl-fp-multi-label"><i class="fas fa-circle text-success me-1" style="font-size:.55rem;"></i>Status</span>
                    <div class="ul-toggle-group">
                        <button :class="['ul-toggle-btn', connFilter === '' ? 'ul-toggle-btn--active' : '']"
                                @click="connFilter = ''; onFilterChange()">All</button>
                        <button :class="['ul-toggle-btn', connFilter === 'true' ? 'ul-toggle-btn--active' : '']"
                                @click="connFilter = 'true'; onFilterChange()">
                            <i class="fas fa-circle me-1 text-success" style="font-size:.55rem;"></i>Online
                        </button>
                        <button :class="['ul-toggle-btn', connFilter === 'false' ? 'ul-toggle-btn--active' : '']"
                                @click="connFilter = 'false'; onFilterChange()">
                            <i class="fas fa-circle me-1 text-secondary" style="font-size:.55rem;"></i>Offline
                        </button>
                    </div>
                </div>

                <!-- Verified -->
                <div class="ul-filter-group">
                    <span class="rl-fp-multi-label"><i class="fas fa-circle-check text-primary me-1"></i>Verified</span>
                    <div class="ul-toggle-group">
                        <button :class="['ul-toggle-btn', verifFilter === '' ? 'ul-toggle-btn--active' : '']"
                                @click="verifFilter = ''; onFilterChange()">All</button>
                        <button :class="['ul-toggle-btn', verifFilter === 'true' ? 'ul-toggle-btn--active' : '']"
                                @click="verifFilter = 'true'; onFilterChange()">
                            <i class="fas fa-check me-1"></i>Verified
                        </button>
                        <button :class="['ul-toggle-btn', verifFilter === 'false' ? 'ul-toggle-btn--active' : '']"
                                @click="verifFilter = 'false'; onFilterChange()">
                            <i class="fas fa-xmark me-1"></i>Unverified
                        </button>
                    </div>
                </div>

                <button v-if="activeFilterCount > 0" class="rl-fp-reset" @click="resetFilters">
                    <i class="fas fa-rotate-left me-1"></i>Reset
                </button>
            </div>
        </div>

        <!-- ── Loading ── -->
        <div v-if="loading" class="rl-loading">
            <div class="spinner-border text-primary"></div>
        </div>

        <!-- ── Empty ── -->
        <div v-else-if="items.length === 0" class="rl-empty">
            <div class="rl-empty-icon"><i class="fas fa-users-slash"></i></div>
            <p class="mb-0">No users matching your search.</p>
        </div>

        <!-- ═══════════════════════════════════
             CARD VIEW
             ═══════════════════════════════════ -->
        <div v-else-if="viewMode === 'card'" class="ul-cards">
            <div v-for="user in items" :key="user.id"
                 class="ul-user-card"
                 :class="{ 'ul-user-card--self': isSelf(user), 'ul-user-card--admin': user.admin }">

                <div class="ul-card-accent"></div>

                <!-- Avatar -->
                <div class="ul-card-top">
                    <div class="ul-avatar-wrap">
                        <div class="ul-avatar" :style="user.profile_picture ? 'background-image:url(' + user.profile_picture + ')' : ''">
                            <span v-if="!user.profile_picture" class="ul-avatar-initials">
                                {{ initials(user) }}
                            </span>
                        </div>
                        <span class="ul-status-dot" :class="user.is_connected ? 'ul-status-dot--on' : 'ul-status-dot--off'"
                              :title="user.is_connected ? 'Online' : 'Offline'"></span>
                    </div>

                    <div class="ul-card-badges">
                        <span v-if="user.admin" class="badge bg-warning text-dark">
                            <i class="fas fa-shield-halved me-1"></i>Admin
                        </span>
                        <span v-if="isSelf(user)" class="badge bg-info text-dark">
                            <i class="fas fa-user-check me-1"></i>You
                        </span>
                        <span v-if="user.is_verified" class="badge bg-success">
                            <i class="fas fa-circle-check me-1"></i>Verified
                        </span>
                        <span v-else class="badge bg-secondary" style="opacity:.55;">
                            <i class="fas fa-circle-xmark me-1"></i>Unverified
                        </span>
                    </div>
                </div>

                <!-- Role picker (non-admins only — admins bypass permissions entirely) -->
                <div v-if="!user.admin" class="ul-role-picker ul-role-picker--card">
                    <button class="ul-role-picker-btn" @click="toggleRoleMenu(user.id, $event)">
                        <span v-if="user.roles && user.roles.length" class="d-flex flex-wrap gap-1">
                            <span v-for="r in user.roles" :key="r.id" class="badge bg-primary-subtle text-primary" style="font-size:.65rem;">{{ r.name }}</span>
                        </span>
                        <span v-else class="text-muted small">No role</span>
                        <i class="fas fa-caret-down ms-1"></i>
                    </button>
                    <div v-if="openRoleMenuUserId === user.id" class="ul-role-menu" @click.stop>
                        <div v-if="allRoles.length === 0" class="ul-role-menu-empty">No roles defined yet.</div>
                        <label v-for="r in allRoles" :key="r.id" class="ul-role-menu-item">
                            <input type="checkbox" :checked="hasRole(user, r.id)" @change="toggleUserRole(user, r)">
                            <span>{{ r.name }}</span>
                        </label>
                    </div>
                </div>

                <!-- Identity -->
                <div class="ul-card-identity">
                    <a :href="'/account/detail_user/' + user.id" class="ul-card-name">
                        {{ user.first_name }} {{ user.last_name || '' }}
                    </a>
                    <span class="ul-card-username text-muted">@{{ user.username || user.first_name }}</span>
                    <div class="ul-card-email"
                         :class="{ 'ul-blurred': blurEnabled && !revealedIds.has(user.id) }"
                         @click="toggleReveal(user.id)" :title="blurEnabled && !revealedIds.has(user.id) ? 'Click to reveal' : ''">
                        <i class="fas fa-envelope me-1 opacity-50" style="font-size:.72rem;"></i>{{ user.email }}
                    </div>
                </div>

                <!-- Bio -->
                <p v-if="user.bio" class="ul-card-bio">{{ user.bio }}</p>

                <!-- Meta -->
                <div class="ul-card-meta">
                    <span v-if="user.location" class="ul-meta-item">
                        <i class="fas fa-location-dot"></i>{{ user.location }}
                    </span>
                    <span class="ul-meta-item">
                        <i class="fas fa-file-code"></i>{{ user.rule_count }} rule{{ user.rule_count !== 1 ? 's' : '' }}
                    </span>
                    <span class="ul-meta-item">
                        <i class="fas fa-layer-group"></i>{{ user.bundle_count }} bundle{{ user.bundle_count !== 1 ? 's' : '' }}
                    </span>
                    <span v-if="user.created_at" class="ul-meta-item">
                        <i class="fas fa-calendar-plus"></i>{{ user.created_at }}
                    </span>
                    <span class="ul-meta-item" :class="{ 'ul-blurred': blurEnabled && !revealedIds.has(user.id) }"
                          @click="toggleReveal(user.id)">
                        <i class="fas fa-clock"></i>{{ user.last_seen ? 'Active ' + fromNow(user.last_seen) : 'Never seen' }}
                    </span>
                </div>

                <!-- Links -->
                <div v-if="user.github_url || user.twitter_url || user.website_url" class="ul-card-links">
                    <a v-if="user.github_url"  :href="user.github_url"  class="ul-link-btn" target="_blank" rel="noopener">
                        <i class="fab fa-github"></i>
                    </a>
                    <a v-if="user.twitter_url" :href="user.twitter_url" class="ul-link-btn" target="_blank" rel="noopener">
                        <i class="fab fa-twitter"></i>
                    </a>
                    <a v-if="user.website_url" :href="user.website_url" class="ul-link-btn" target="_blank" rel="noopener">
                        <i class="fas fa-globe"></i>
                    </a>
                </div>

                <!-- Actions -->
                <div class="ul-card-actions">
                    <a :href="'/account/detail_user/' + user.id" class="ul-action-primary">
                        <i class="fas fa-eye me-1"></i>Profile
                    </a>
                    <button v-if="!isSelf(user)"
                            class="ul-action-secondary"
                            :class="{ 'ul-action-secondary--warn': user.admin }"
                            @click="$emit('toggle-admin', user)"
                            :title="user.admin ? 'Remove admin' : 'Promote to admin'">
                        <i :class="user.admin ? 'fas fa-user-minus' : 'fas fa-user-shield'"></i>
                    </button>
                    <button class="ul-action-secondary ul-action-secondary--danger"
                            @click="$emit('delete-user', user)"
                            title="Delete user">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════
             TABLE VIEW
             ═══════════════════════════════════ -->
        <div v-else class="dt-table-wrap">
            <table class="dt-table">
                <thead class="dt-thead">
                    <tr>
                        <th class="dt-th" style="min-width:220px;">
                            <div class="dt-th-inner dt-th--sortable"
                                 :class="{ 'dt-th--sorted': sortKey === 'first_name' }"
                                 @click="setSort('first_name')">
                                User <i class="fas dt-sort-icon" :class="sortIcon('first_name')"></i>
                            </div>
                        </th>
                        <th class="dt-th">
                            <div class="d-flex align-items-center gap-2">
                                Email
                                <button class="ul-blur-toggle" @click="blurEnabled = !blurEnabled; revealedIds.clear()"
                                        :title="blurEnabled ? 'Show emails' : 'Blur emails'">
                                    <i :class="blurEnabled ? 'fas fa-eye' : 'fas fa-eye-slash'"></i>
                                </button>
                            </div>
                        </th>
                        <th class="dt-th" style="width:100px;">Role</th>
                        <th class="dt-th" style="width:90px;">Status</th>
                        <th class="dt-th" style="width:100px;">Verified</th>
                        <th class="dt-th" style="width:80px;">Rules</th>
                        <th class="dt-th dt-th--sortable" style="width:120px;"
                            :class="{ 'dt-th--sorted': sortKey === 'created_at' }"
                            @click="setSort('created_at')">
                            <div class="dt-th-inner">
                                Joined <i class="fas dt-sort-icon" :class="sortIcon('created_at')"></i>
                            </div>
                        </th>
                        <th class="dt-th dt-th--sortable" style="width:130px;"
                            :class="{ 'dt-th--sorted': sortKey === 'last_seen' }"
                            @click="setSort('last_seen')">
                            <div class="dt-th-inner">
                                Last seen <i class="fas dt-sort-icon" :class="sortIcon('last_seen')"></i>
                            </div>
                        </th>
                        <th class="dt-th dt-th--actions" style="width:110px;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <tr v-for="user in items" :key="user.id" class="dt-row"
                        :class="{ 'ul-row--self': isSelf(user), 'ul-row--admin': user.admin }">

                        <!-- User -->
                        <td class="dt-td">
                            <div class="ul-table-user">
                                <div class="ul-table-avatar"
                                     :style="user.profile_picture ? 'background-image:url(' + user.profile_picture + ')' : ''">
                                    <span v-if="!user.profile_picture" class="ul-avatar-initials ul-avatar-initials--sm">
                                        {{ initials(user) }}
                                    </span>
                                    <span class="ul-status-dot ul-status-dot--table"
                                          :class="user.is_connected ? 'ul-status-dot--on' : 'ul-status-dot--off'"></span>
                                </div>
                                <div class="ul-table-identity">
                                    <a :href="'/account/detail_user/' + user.id" class="ul-table-name">
                                        {{ user.first_name }} {{ user.last_name || '' }}
                                    </a>
                                    <span class="ul-table-username">@{{ user.username || user.first_name }}</span>
                                </div>
                                <span v-if="isSelf(user)" class="badge bg-info text-dark ms-1" style="font-size:.6rem;">YOU</span>
                            </div>
                        </td>

                        <!-- Email -->
                        <td class="dt-td">
                            <span :class="{ 'ul-blurred': blurEnabled && !revealedIds.has(user.id) }"
                                  @click="toggleReveal(user.id)"
                                  :title="blurEnabled && !revealedIds.has(user.id) ? 'Click to reveal' : ''"
                                  style="font-size:.8rem;cursor:pointer;">
                                {{ user.email }}
                            </span>
                        </td>

                        <!-- Role -->
                        <td class="dt-td">
                            <span v-if="user.admin" class="badge bg-warning text-dark">
                                <i class="fas fa-shield-halved me-1"></i>Admin
                            </span>
                            <div v-else class="ul-role-picker">
                                <button class="ul-role-picker-btn" @click="toggleRoleMenu(user.id, $event)">
                                    <span v-if="user.roles && user.roles.length" class="d-flex flex-wrap gap-1">
                                        <span v-for="r in user.roles" :key="r.id" class="badge bg-primary-subtle text-primary" style="font-size:.65rem;">{{ r.name }}</span>
                                    </span>
                                    <span v-else class="text-muted small">No role</span>
                                    <i class="fas fa-caret-down ms-1"></i>
                                </button>
                                <div v-if="openRoleMenuUserId === user.id" class="ul-role-menu" @click.stop>
                                    <div v-if="allRoles.length === 0" class="ul-role-menu-empty">No roles defined yet.</div>
                                    <label v-for="r in allRoles" :key="r.id" class="ul-role-menu-item">
                                        <input type="checkbox" :checked="hasRole(user, r.id)" @change="toggleUserRole(user, r)">
                                        <span>{{ r.name }}</span>
                                    </label>
                                </div>
                            </div>
                        </td>

                        <!-- Status -->
                        <td class="dt-td">
                            <span class="ul-status-label"
                                  :class="user.is_connected ? 'ul-status-label--on' : 'ul-status-label--off'">
                                <i class="fas fa-circle" style="font-size:.5rem;"></i>
                                {{ user.is_connected ? 'Online' : 'Offline' }}
                            </span>
                        </td>

                        <!-- Verified -->
                        <td class="dt-td">
                            <span v-if="user.is_verified" class="badge bg-success">
                                <i class="fas fa-check"></i>
                            </span>
                            <span v-else class="text-muted small opacity-50">—</span>
                        </td>

                        <!-- Rules -->
                        <td class="dt-td" style="font-size:.82rem;font-weight:600;color:var(--text-color);">
                            {{ user.rule_count }}
                        </td>

                        <!-- Joined -->
                        <td class="dt-td" style="font-size:.78rem;white-space:nowrap;">
                            {{ user.created_at || '—' }}
                        </td>

                        <!-- Last seen -->
                        <td class="dt-td">
                            <span :class="{ 'ul-blurred': blurEnabled && !revealedIds.has(user.id) }"
                                  @click="toggleReveal(user.id)"
                                  style="font-size:.78rem;cursor:pointer;"
                                  :title="blurEnabled && !revealedIds.has(user.id) ? 'Click to reveal' : ''">
                                {{ user.last_seen ? fromNow(user.last_seen) : '—' }}
                            </span>
                        </td>

                        <!-- Actions -->
                        <td class="dt-td dt-td--actions">
                            <div class="dt-actions">
                                <a :href="'/account/detail_user/' + user.id"
                                   class="dt-action-btn" title="View profile">
                                    <i class="fas fa-eye"></i>
                                </a>
                                <button v-if="!isSelf(user)"
                                        class="dt-action-btn"
                                        :class="user.admin ? 'dt-action-btn--warn' : ''"
                                        :title="user.admin ? 'Remove admin' : 'Promote to admin'"
                                        @click="$emit('toggle-admin', user)">
                                    <i :class="user.admin ? 'fas fa-user-minus' : 'fas fa-user-shield'"></i>
                                </button>
                                <button class="dt-action-btn dt-action-btn--danger"
                                        title="Delete user"
                                        @click="$emit('delete-user', user)">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- ── Footer ── -->
        <div v-if="!loading && items.length > 0" class="rl-footer">
            <div v-if="viewMode === 'card'" class="rl-per-page">
                <span>Per page</span>
                <select v-model="perPageModel">
                    <option v-for="n in [8,16,32,64]" :key="n" :value="n">{{ n }}</option>
                </select>
            </div>
            <div v-else style="width:1px;"></div>
            <div style="flex-grow:1;display:flex;justify-content:center;">
                <pagination-component :current-page="page" :total-pages="totalPages"
                                      @change-page="goToPage"></pagination-component>
            </div>
            <div class="rl-footer-info">{{ footerInfo }}</div>
        </div>
    </div>
    `,

    setup(props, { emit }) {
        // ── URL helpers ───────────────────────────────────────────────────
        const _url = new URLSearchParams(window.location.search)
        const _p   = (k, fb = '') => _url.get(k) ?? fb

        // ── State ─────────────────────────────────────────────────────────
        const items      = ref([])
        const total      = ref(0)
        const totalPages = ref(1)
        const loading    = ref(false)

        const viewMode  = ref(_p('view', props.defaultView))
        const page      = ref(Number(_p('page', '1')) || 1)
        const sortKey   = ref(_p('sort', ''))
        const sortDir   = ref(_p('dir', 'desc'))
        const cardSort  = ref('newest')

        const _urlPP      = Number(_p('per_page', '')) || 0
        const cardPP      = ref(viewMode.value !== 'table' && _urlPP ? _urlPP : props.initialPerPage)
        const tablePP     = ref(viewMode.value === 'table'  && _urlPP ? _urlPP : 25)

        const perPage = computed(() => viewMode.value === 'table' ? tablePP.value : cardPP.value)
        const perPageModel = computed({
            get: () => perPage.value,
            set: val => {
                if (viewMode.value === 'table') tablePP.value = Number(val)
                else                            cardPP.value  = Number(val)
                page.value = 1
                fetchData()
            },
        })

        // ── Filters ───────────────────────────────────────────────────────
        const search      = ref(_p('search', ''))
        const adminFilter = ref(_p('admin', ''))
        const connFilter  = ref(_p('connected', ''))
        const verifFilter = ref(_p('verified', ''))
        const filtersOpen = ref(['admin','connected','verified'].some(k => _url.has(k) && _url.get(k)))

        const activeFilterCount = computed(() =>
            (adminFilter.value ? 1 : 0) + (connFilter.value ? 1 : 0) + (verifFilter.value ? 1 : 0)
        )

        // ── Blur ──────────────────────────────────────────────────────────
        const blurEnabled = ref(true)
        const revealedIds = reactive(new Set())

        // ── Role picker (non-admin users only) ───────────────────────────
        const allRoles          = ref([])
        const openRoleMenuUserId = ref(null)

        async function fetchAllRoles() {
            try {
                const res = await fetch('/admin/roles/all')
                if (!res.ok) return
                const data = await res.json()
                if (data.success) allRoles.value = data.roles
            } catch { /* role picker just stays empty if this fails */ }
        }

        function toggleRoleMenu(userId, evt) {
            evt.stopPropagation()
            openRoleMenuUserId.value = openRoleMenuUserId.value === userId ? null : userId
        }
        function closeRoleMenu() { openRoleMenuUserId.value = null }

        function hasRole(user, roleId) {
            return (user.roles || []).some(r => r.id === roleId)
        }

        async function toggleUserRole(user, role) {
            const has = hasRole(user, role.id)
            const res = await apiFetch(`/admin/roles/${role.id}/users/${has ? 'remove' : 'add'}`, 'POST', { user_id: user.id })
            const data = await res.json()
            if (data.success) {
                user.roles = has
                    ? (user.roles || []).filter(r => r.id !== role.id)
                    : [...(user.roles || []), { id: role.id, name: role.name }]
                create_message(
                    has ? `Removed "${role.name}" from ${user.first_name}` : `Assigned "${role.name}" to ${user.first_name}`,
                    'success-subtle'
                )
            } else {
                create_message(data.message || 'Failed to update role.', 'danger-subtle')
            }
        }

        function toggleReveal(id) {
            if (!blurEnabled.value) return
            if (revealedIds.has(id)) revealedIds.delete(id)
            else                     revealedIds.add(id)
        }

        // ── Computed ──────────────────────────────────────────────────────
        const numericCurrentUserId = computed(() =>
            props.currentUserId !== null && props.currentUserId !== ''
                ? Number(props.currentUserId) : null
        )
        function isSelf(user) { return numericCurrentUserId.value === user.id }

        const footerInfo = computed(() => {
            if (total.value === 0) return 'No results'
            const s = (page.value - 1) * perPage.value + 1
            const e = Math.min(page.value * perPage.value, total.value)
            return `${s}–${e} of ${total.value}`
        })

        // ── URL sync ──────────────────────────────────────────────────────
        function syncToUrl() {
            if (!props.syncUrl) return
            const p = new URLSearchParams()
            if (search.value)                        p.set('search',    search.value)
            if (page.value > 1)                      p.set('page',      page.value)
            if (sortKey.value)                     { p.set('sort',      sortKey.value); p.set('dir', sortDir.value) }
            if (viewMode.value !== props.defaultView) p.set('view',     viewMode.value)
            const defPP = viewMode.value === 'table' ? 25 : props.initialPerPage
            if (perPage.value !== defPP)             p.set('per_page',  perPage.value)
            if (adminFilter.value)                   p.set('admin',     adminFilter.value)
            if (connFilter.value)                    p.set('connected', connFilter.value)
            if (verifFilter.value)                   p.set('verified',  verifFilter.value)
            const qs = p.toString()
            history.replaceState(null, '', qs ? `?${qs}` : window.location.pathname)
        }

        // ── Fetch ─────────────────────────────────────────────────────────
        async function fetchData() {
            loading.value = true
            try {
                const p = new URLSearchParams()
                p.set('page',     page.value)
                p.set('per_page', perPage.value)
                if (search.value)      p.set('search',    search.value)
                if (sortKey.value)   { p.set('sort',      sortKey.value); p.set('dir', sortDir.value) }
                if (adminFilter.value) p.set('admin',     adminFilter.value)
                if (connFilter.value)  p.set('connected', connFilter.value)
                if (verifFilter.value) p.set('verified',  verifFilter.value)

                const sep = props.fetchUrl.includes('?') ? '&' : '?'
                const res = await fetch(`${props.fetchUrl}${sep}${p}`)
                if (!res.ok) return
                const data = await res.json()
                items.value      = data.items      ?? []
                total.value      = data.total      ?? 0
                totalPages.value = data.total_pages ?? 1
                if (page.value > totalPages.value && totalPages.value > 0)
                    page.value = totalPages.value
                syncToUrl()
            } finally {
                loading.value = false
            }
        }

        // ── Filters / sort ────────────────────────────────────────────────
        let _searchTimer = null
        function onSearchInput() {
            clearTimeout(_searchTimer)
            _searchTimer = setTimeout(() => { page.value = 1; fetchData() }, 360)
        }
        function clearSearch() { search.value = ''; page.value = 1; fetchData() }

        function onFilterChange() { page.value = 1; fetchData() }

        function resetFilters() {
            adminFilter.value = ''; connFilter.value = ''; verifFilter.value = ''
            onFilterChange()
        }

        function setSort(key) {
            if (sortKey.value === key) sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
            else { sortKey.value = key; sortDir.value = 'desc' }
            page.value = 1; fetchData()
        }
        function sortIcon(key) {
            if (sortKey.value !== key) return 'fa-sort'
            return sortDir.value === 'asc' ? 'fa-sort-up' : 'fa-sort-down'
        }
        function onCardSortChange() {
            const m = { newest: ['created_at','desc'], oldest: ['created_at','asc'],
                        name_asc: ['first_name','asc'], last_seen: ['last_seen','desc'] }
            const s = m[cardSort.value]
            if (s) { sortKey.value = s[0]; sortDir.value = s[1] }
            page.value = 1; fetchData()
        }

        function goToPage(p) { page.value = p; fetchData() }

        // ── Helpers ───────────────────────────────────────────────────────
        function initials(user) {
            const n = ((user.first_name || '') + ' ' + (user.last_name || '')).trim()
            return n ? n.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2) : '?'
        }

        function fromNow(dateStr) {
            if (!dateStr) return ''
            try {
                if (window.dayjs) return window.dayjs.utc(dateStr).fromNow()
                return new Date(dateStr).toLocaleDateString()
            } catch { return dateStr }
        }

        // ── Lifecycle ─────────────────────────────────────────────────────
        onMounted(() => {
            fetchData()
            fetchAllRoles()
            document.addEventListener('click', closeRoleMenu)
        })
        watch(viewMode, () => { page.value = 1; fetchData() })
        onUnmounted(() => {
            clearTimeout(_searchTimer)
            document.removeEventListener('click', closeRoleMenu)
        })

        return {
            items, total, totalPages, loading,
            viewMode, page, perPage, perPageModel, sortKey, sortDir, cardSort,
            search, adminFilter, connFilter, verifFilter,
            filtersOpen, activeFilterCount,
            blurEnabled, revealedIds,
            allRoles, openRoleMenuUserId,
            footerInfo,
            isSelf, initials, fromNow,
            onSearchInput, clearSearch, onFilterChange, resetFilters,
            setSort, sortIcon, onCardSortChange, goToPage, toggleReveal, fetchData,
            toggleRoleMenu, hasRole, toggleUserRole,
        }
    },
}
