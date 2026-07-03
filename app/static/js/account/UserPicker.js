/**
 * UserPicker.js — Searchable user directory with UserChip rows, single-select.
 * Used by admin bulk-actions that need to target one arbitrary user (e.g.
 * granting rule ownership in the Manual Ownership admin page).
 *
 * Props:
 *   modelValue   Object|null   the selected user (raw User.to_json() shape), or null
 * Emits:
 *   update:modelValue(user|null)
 *
 * Data source: GET /account/get_all_users?page=&search=  (admin-only)
 */
import UserChip from '/static/js/components/UserChip.js'

const { ref, watch, onMounted } = Vue

const UserPicker = {
    name: 'UserPicker',
    delimiters: ['[[', ']]'],
    components: { 'user-chip': UserChip },
    props: {
        modelValue: { type: Object, default: null },
    },
    emits: ['update:modelValue'],
    setup(props, { emit }) {
        const search     = ref('')
        const users      = ref([])
        const page       = ref(1)
        const totalPages = ref(1)
        const loading    = ref(false)

        let debounceTimer = null

        async function fetchUsers(p = 1) {
            loading.value = true
            try {
                const params = new URLSearchParams({ page: p })
                if (search.value.trim()) params.set('search', search.value.trim())
                const res  = await fetch(`/account/get_all_users?${params}`)
                const data = await res.json()
                if (res.ok) {
                    users.value      = data.user || []
                    totalPages.value = data.total_pages || 1
                    page.value       = p
                }
            } catch { /* leave list as-is on network error */ }
            finally { loading.value = false }
        }

        watch(search, () => {
            clearTimeout(debounceTimer)
            debounceTimer = setTimeout(() => fetchUsers(1), 300)
        })

        function selectUser(u) { emit('update:modelValue', u) }
        function clearSelection() { emit('update:modelValue', null) }

        onMounted(() => fetchUsers(1))

        return { search, users, page, totalPages, loading, fetchUsers, selectUser, clearSelection }
    },
    template: `
<div class="user-picker">

    <!-- Selected state -->
    <div v-if="modelValue" class="user-picker__selected">
        <user-chip :user-id="modelValue.id" :username="modelValue.username"
                   :avatar="modelValue.profile_picture" size="md"></user-chip>
        <button type="button" class="user-picker__clear" @click="clearSelection" title="Change user">
            <i class="fa-solid fa-xmark me-1"></i>Change
        </button>
    </div>

    <!-- Search + list -->
    <template v-else>
        <div class="user-picker__search">
            <i class="fa-solid fa-magnifying-glass"></i>
            <input type="text" v-model="search" placeholder="Search by name, username, email…">
        </div>

        <div class="user-picker__list">
            <div v-if="loading" class="user-picker__empty">
                <div class="spinner-border spinner-border-sm text-primary"></div>
            </div>
            <div v-else-if="!users.length" class="user-picker__empty">
                <i class="fa-solid fa-user-slash mb-1"></i>
                <div>No users found.</div>
            </div>
            <button v-else v-for="u in users" :key="u.id" type="button"
                    class="user-picker__row" @click="selectUser(u)">
                <user-chip :user-id="u.id" :username="u.username" :avatar="u.profile_picture" size="sm"></user-chip>
                <span v-if="u.is_admin" class="badge rounded-pill user-picker__admin-badge">
                    <i class="fa-solid fa-crown me-1"></i>Admin
                </span>
            </button>
        </div>

        <div v-if="totalPages > 1" class="user-picker__pager">
            <button type="button" class="btn btn-sm btn-outline-secondary" :disabled="page<=1 || loading"
                    @click="fetchUsers(page-1)">
                <i class="fa-solid fa-chevron-left"></i>
            </button>
            <span class="small text-muted">Page [[ page ]] / [[ totalPages ]]</span>
            <button type="button" class="btn btn-sm btn-outline-secondary" :disabled="page>=totalPages || loading"
                    @click="fetchUsers(page+1)">
                <i class="fa-solid fa-chevron-right"></i>
            </button>
        </div>
    </template>

</div>
`,
}

export default UserPicker
