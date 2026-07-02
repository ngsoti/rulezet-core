/**
 * multiPersonFilter.js — Searchable multi-select filter for rule authors and editors.
 *
 * Has an internal toggle between two modes:
 *   'author'  → filters by the rule's metadata author field
 *   'editor'  → filters by the Rulezet user who uploaded the rule
 *
 * Emits:
 *   change({ mode, values })  whenever the mode or selection changes
 */

const MultiPersonFilter = {
    props: {
        modelValue: { type: Object, default: () => ({ mode: 'author', values: [] }) },
        authorEndpoint: { type: String, default: '/rule/get_rules_authors_usage' },
        editorEndpoint: { type: String, default: '/rule/get_rules_editors_usage' },
        userId: { type: Number, default: null },
        sourceRules: { type: String, default: '' },
        // Query string of every OTHER currently active RuleList filter — keeps
        // these counts scoped to what's actually visible.
        filterContext: { type: String, default: '' },
    },
    emits: ['update:modelValue', 'change'],
    delimiters: ['[[', ']]'],

    setup(props, { emit }) {
        const mode      = Vue.ref(props.modelValue?.mode || 'author')
        const selected  = Vue.ref([...(props.modelValue?.values || [])])
        const list      = Vue.ref([])
        const search    = Vue.ref('')
        const isLoading = Vue.ref(false)

        Vue.watch(() => props.modelValue, (v) => {
            if (!v) return
            mode.value     = v.mode     || 'author'
            selected.value = [...(v.values || [])]
        }, { deep: true })

        const fetchList = async () => {
            isLoading.value = true
            list.value = []
            try {
                const endpoint = mode.value === 'editor' ? props.editorEndpoint : props.authorEndpoint
                const params = new URLSearchParams(props.filterContext)
                if (props.userId) params.append('user_id', props.userId)
                if (props.sourceRules && !params.has('sources')) params.append('sources', props.sourceRules)
                const url = endpoint + (params.toString() ? '?' + params.toString() : '')
                const res = await fetch(url)
                if (res.ok) list.value = await res.json()
            } catch (e) {
                console.error('MultiPersonFilter fetch error', e)
            } finally {
                isLoading.value = false
            }
        }

        Vue.watch(mode, () => {
            selected.value = []
            emit('update:modelValue', { mode: mode.value, values: [] })
            emit('change', { mode: mode.value, values: [] })
            fetchList()
        })

        Vue.watch(() => props.sourceRules, fetchList)
        Vue.watch(() => props.filterContext, fetchList)

        const filteredList = Vue.computed(() => {
            const q = search.value.toLowerCase()
            return q ? list.value.filter(item => item.name.toLowerCase().includes(q)) : list.value
        })

        const toggle = (name) => {
            const idx = selected.value.indexOf(name)
            if (idx > -1) selected.value.splice(idx, 1)
            else selected.value.push(name)
            const payload = { mode: mode.value, values: [...selected.value] }
            emit('update:modelValue', payload)
            emit('change', payload)
        }

        const switchMode = (m) => { mode.value = m }

        const clearAll = () => {
            selected.value = []
            const payload = { mode: mode.value, values: [] }
            emit('update:modelValue', payload)
            emit('change', payload)
        }

        Vue.onMounted(fetchList)

        return { mode, selected, list, search, isLoading, filteredList, toggle, switchMode, clearAll }
    },

    template: `
    <div class="dropdown multi-person-filter w-100">

        <!-- ── Trigger ── -->
        <div class="form-control d-flex flex-wrap gap-2 align-items-center p-2 shadow-sm border-secondary-subtle"
             data-bs-toggle="dropdown" data-bs-auto-close="outside"
             style="cursor:pointer;min-height:48px;border-radius:12px;">

            <i class="fa-solid fa-person-circle-check text-warning opacity-75 ms-1 me-1"></i>
            <span v-if="selected.length === 0" class="text-muted small fw-bold">
                Filter by [[ mode === 'editor' ? 'editor' : 'author' ]]…
            </span>

            <span v-for="name in selected" :key="name"
                  class="d-flex align-items-center rounded-2 shadow-sm bg-warning text-dark"
                  style="font-size:0.75rem;overflow:hidden;">
                <div class="px-2 py-1 bg-black bg-opacity-10 border-end border-dark border-opacity-10">
                    <i class="fa-solid fa-user"></i>
                </div>
                <div class="px-2 py-1 d-flex align-items-center">
                    <span class="fw-bold me-2">[[ name ]]</span>
                    <i class="fa-solid fa-circle-xmark opacity-75 ms-1" @click.stop="toggle(name)" style="cursor:pointer;"></i>
                </div>
            </span>
            <i class="fa-solid fa-chevron-down ms-auto me-1 text-muted small"></i>
        </div>

        <!-- ── Dropdown panel ── -->
        <div class="dropdown-menu shadow-lg border-0 w-100 p-3 mt-2"
             style="max-height:520px;border-radius:15px;z-index:1060;min-width:320px;">

            <!-- Mode toggle -->
            <div class="d-flex gap-1 mb-3 p-1 rounded-3" style="background:var(--light-bg-color);">
                <button @click.stop="switchMode('author')"
                        :class="['btn btn-sm flex-fill fw-bold', mode === 'author' ? 'btn-warning' : 'btn-link text-muted']"
                        style="border-radius:8px;font-size:.8rem;">
                    <i class="fa-solid fa-feather-pointed me-1"></i>Author
                </button>
                <button @click.stop="switchMode('editor')"
                        :class="['btn btn-sm flex-fill fw-bold', mode === 'editor' ? 'btn-warning' : 'btn-link text-muted']"
                        style="border-radius:8px;font-size:.8rem;">
                    <i class="fa-solid fa-user-pen me-1"></i>Editor
                </button>
            </div>

            <!-- Search -->
            <div class="input-group input-group-sm mb-3">
                <span class="input-group-text bg-light border-0"><i class="fa-solid fa-magnifying-glass"></i></span>
                <input type="text" v-model="search" class="form-control bg-light border-0 shadow-none"
                       :placeholder="'Search ' + (mode === 'editor' ? 'editors' : 'authors') + '…'"
                       @click.stop />
            </div>

            <!-- List -->
            <div class="custom-tag-scroll pe-2" style="max-height:340px;overflow-y:auto;">

                <div v-if="isLoading" class="text-center py-4">
                    <div class="spinner-border spinner-border-sm text-warning"></div>
                </div>

                <div v-else-if="filteredList.length === 0" class="text-center py-4" style="color:var(--text-color)">
                    <i class="fa-solid fa-user-slash fa-2x text-muted opacity-25 d-block mb-2"></i>
                    <small class="text-muted">No [[ mode === 'editor' ? 'editors' : 'authors' ]] found</small>
                </div>

                <div v-else class="d-flex flex-column gap-1">
                    <div v-for="item in filteredList" :key="item.name"
                         @click="toggle(item.name)"
                         class="p-2 rounded border d-flex align-items-center justify-content-between tag-item-hover"
                         :class="selected.includes(item.name) ? 'border-warning bg-warning bg-opacity-10 shadow-sm' : ''"
                         style="cursor:pointer;">
                        <div class="d-flex align-items-center gap-2">
                            <i class="fa-solid fa-user text-warning opacity-75" style="font-size:.8rem;"></i>
                            <span class="small fw-bold" style="color:var(--text-color)">[[ item.name ]]</span>
                        </div>
                        <div class="d-flex align-items-center gap-2">
                            <span class="badge rounded-pill bg-light border" style="font-size:.65rem;color:var(--text-color);">[[ item.count ]]</span>
                            <i v-if="selected.includes(item.name)" class="fa-solid fa-check-circle text-warning"></i>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Clear button -->
            <div v-if="selected.length > 0" class="mt-2 pt-2 border-top text-end">
                <button @click.stop="clearAll" class="btn btn-sm btn-link text-muted text-decoration-none">
                    <i class="fa-solid fa-rotate-left me-1"></i>Clear
                </button>
            </div>
        </div>
    </div>
    `,
}

export default MultiPersonFilter
