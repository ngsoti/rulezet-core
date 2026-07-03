/**
 * VoterPopover.js — Hover popover listing who voted/reacted (rule votes, bundle
 * votes, comment likes/dislikes). Wrap any trigger element (a vote button) with
 * this component; it fetches the voter list lazily on first hover and caches it.
 *
 * Mirrors the tag-tooltip pattern: teleport to body + position:fixed, so the
 * popover escapes any overflow:hidden ancestor (cards, tables…).
 *
 * Usage:
 *   <voter-popover fetch-url="/rule/voters/42?type=up" label="Liked by">
 *     <button @click="vote('up', 42)">...</button>
 *   </voter-popover>
 */
import UserChip from '/static/js/components/UserChip.js'

const { ref, reactive } = Vue

const POPOVER_WIDTH = 260
const GAP = 10

export default {
    name: 'VoterPopover',
    components: { UserChip },
    props: {
        fetchUrl: { type: String, required: true },
        label:    { type: String, default: 'Reacted by' },
    },

    template: `
    <span class="vp-wrapper" ref="wrapperEl" @mouseenter="onEnter" @mouseleave="onLeave">
        <slot></slot>

        <teleport to="body">
            <div v-if="show" class="vp-popover" :style="style"
                 @mouseenter="onPopEnter" @mouseleave="onPopLeave">
                <div class="vp-popover-title">
                    <i class="fas fa-users me-1"></i>{{ label }}
                </div>

                <div v-if="loading" class="vp-popover-loading">
                    <div class="spinner-border spinner-border-sm text-primary"></div>
                </div>

                <div v-else-if="error" class="vp-popover-empty text-danger">
                    Couldn't load
                </div>

                <div v-else-if="users.length === 0" class="vp-popover-empty">
                    No one yet
                </div>

                <div v-else class="vp-popover-list">
                    <user-chip v-for="u in users" :key="u.id"
                               :user-id="u.id" :username="u.username" :avatar="u.avatar"
                               size="xs" :show-name="true">
                    </user-chip>
                    <div v-if="total > users.length" class="vp-popover-more">
                        +{{ total - users.length }} more
                    </div>
                </div>
            </div>
        </teleport>
    </span>
    `,

    setup(props) {
        const wrapperEl = ref(null)
        const show      = ref(false)
        const loading   = ref(false)
        const error     = ref(false)
        const users     = ref([])
        const total     = ref(0)
        const style     = reactive({})

        let fetched   = false
        let hideTimer = null

        function computePos() {
            if (!wrapperEl.value) return
            const rect = wrapperEl.value.getBoundingClientRect()
            let left = rect.left + rect.width / 2 - POPOVER_WIDTH / 2
            left = Math.max(8, Math.min(left, window.innerWidth - POPOVER_WIDTH - 8))
            Object.assign(style, {
                position:   'fixed',
                top:        (rect.top - GAP) + 'px',
                left:       left + 'px',
                transform:  'translateY(-100%)',
                width:      POPOVER_WIDTH + 'px',
                zIndex:     9999,
            })
        }

        async function ensureFetched() {
            if (fetched) return
            fetched = true
            loading.value = true
            try {
                const res  = await fetch(props.fetchUrl)
                const data = await res.json()
                users.value = data.users || []
                total.value = data.total ?? users.value.length
            } catch (e) {
                error.value = true
            } finally {
                loading.value = false
            }
        }

        function onEnter() {
            clearTimeout(hideTimer)
            computePos()
            show.value = true
            ensureFetched()
        }
        function onLeave()    { hideTimer = setTimeout(() => { show.value = false }, 150) }
        function onPopEnter() { clearTimeout(hideTimer) }
        function onPopLeave() { hideTimer = setTimeout(() => { show.value = false }, 150) }

        return {
            wrapperEl, show, loading, error, users, total, style,
            onEnter, onLeave, onPopEnter, onPopLeave,
        }
    },
}
