/**
 * ActivityFeedWidget — same public activity feed as the homepage's
 * "Community Activity" panel (same /activity_feed endpoint, same action
 * labels/colors, same target-link resolution, same relative-time via
 * dayjs) — just embedded compactly as a dashboard widget instead of
 * hand-rolling a different look.
 *
 * params: { limit }
 */
import WidgetFrame from '../widgetFrame.js'
import UserChip     from '/static/js/components/UserChip.js'

const { ref, watch, onMounted } = Vue

const ENDPOINT = '/activity_feed'

// Mirrors app/templates/home.html's ACTION_LABELS / ACTION_COLORS exactly —
// keep both in sync if the home feed's vocabulary changes.
const ACTION_LABELS = {
    'rule.create': 'created a rule', 'rule.edit': 'edited a rule',
    'rule.vote_up': 'upvoted a rule', 'rule.vote_down': 'downvoted a rule',
    'rule.favorite': 'favorited a rule', 'bundle.create': 'created a bundle',
    'bundle.edit': 'updated a bundle', 'comment.add': 'commented',
    'user.register': 'joined Rulezet', 'tag.create': 'created a tag',
    'github.import_started': 'started a GitHub import',
}
const ACTION_COLORS = {
    'rule':    { bg: 'rgba(13,110,253,.12)',  color: '#0d6efd' },
    'bundle':  { bg: 'rgba(255,193,7,.15)',   color: '#ca8a04' },
    'comment': { bg: 'rgba(25,135,84,.12)',   color: '#198754' },
    'user':    { bg: 'rgba(108,117,125,.12)', color: '#6c757d' },
    'tag':     { bg: 'rgba(111,66,193,.12)',  color: '#6f42c1' },
}

function feedBubbleStyle(action) {
    const c = ACTION_COLORS[action.split('.')[0]] || { bg: 'rgba(108,117,125,.1)', color: '#6c757d' }
    return `background:${c.bg};color:${c.color};`
}
function friendlyAction(action) {
    return ACTION_LABELS[action] || action.replace('.', ' ').replace(/_/g, ' ')
}
function feedUrl(item) {
    if (item.target_type === 'rule') {
        if (item.target_uuid) return `/rule/detail_rule/${item.target_uuid}`
        if (item.target_id)   return `/rule/detail_rule/${item.target_id}`
    }
    if (item.target_type === 'bundle') {
        if (item.target_uuid) return `/bundle/detail/${item.target_uuid}`
        if (item.target_id)   return `/bundle/detail/${item.target_id}`
    }
    if (item.target_type === 'user' && item.target_id)
        return `/account/detail_user/${item.target_id}`
    if (item.action === 'github.import_started' && item.extra?.url)
        return `/rule/github_detail?url=${encodeURIComponent(item.extra.url)}`
    if (item.target_type === 'comment' && item.target_id) {
        const base = item.extra?.rule_uuid  ? `/rule/detail_rule/${item.extra.rule_uuid}`
                   : item.extra?.rule_id    ? `/rule/detail_rule/${item.extra.rule_id}` : null
        if (base) return `${base}?comment=${item.target_id}`
    }
    if (item.target_type === 'bundle_comment' && item.target_id) {
        const base = item.extra?.bundle_uuid ? `/bundle/detail/${item.extra.bundle_uuid}`
                   : item.extra?.bundle_id   ? `/bundle/detail/${item.extra.bundle_id}` : null
        if (base) return `${base}?comment=${item.target_id}`
    }
    if (item.target_type === 'blog_post') {
        if (item.target_uuid) return `/blog/post/${item.target_uuid}`
        if (item.target_id)   return `/blog/post/${item.target_id}`
    }
    return null
}
function formatTime(ts) {
    if (!ts) return ''
    return dayjs.utc(ts).fromNow()
}

const ActivityFeedWidget = {
    components: { 'widget-frame': WidgetFrame, 'user-chip': UserChip },
    props: {
        params: { type: Object, required: true },
    },
    emits: ['update-params', 'remove'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const feed     = ref([])
        const loading  = ref(false)
        const editForm = ref({ ...props.params })

        async function load() {
            loading.value = true
            try {
                const limit = props.params.limit || 8
                const res   = await fetch(`${ENDPOINT}?page=1&per_page=${limit}`)
                const data  = await res.json()
                feed.value  = data.logs || []
            } catch {
                feed.value = []
            } finally {
                loading.value = false
            }
        }

        function openFeedItem(item) {
            const url = feedUrl(item)
            if (url) window.open(url, '_blank')
        }

        function saveSettings() {
            emit('update-params', { ...editForm.value })
        }

        watch(() => props.params, () => { editForm.value = { ...props.params }; load() })
        onMounted(load)

        return {
            feed, loading, editForm, load, saveSettings,
            feedBubbleStyle, friendlyAction, feedUrl, formatTime, openFeedItem,
        }
    },
    template: `
    <widget-frame title="Community Activity" icon="fa-clock-rotate-left" :loading="loading"
                   @reload="load" @remove="$emit('remove')" @save-settings="saveSettings">
        <div v-if="!loading && feed.length === 0" class="text-center text-muted small py-4">
            <i class="fa-solid fa-satellite-dish opacity-25 d-block mb-2" style="font-size:1.5rem;"></i>
            No activity yet.
        </div>
        <div class="dw-feed">
            <div v-for="item in feed" :key="item.id"
                 :class="['dw-feed-row', feedUrl(item) ? '' : 'dw-feed-row--no-link']"
                 @click="feedUrl(item) && openFeedItem(item)">
                <div class="dw-feed-bubble" :style="feedBubbleStyle(item.action)">
                    <i :class="item.icon || 'fa-solid fa-circle-dot'"></i>
                </div>
                <div class="flex-grow-1 min-width-0">
                    <div class="d-flex align-items-baseline gap-1 flex-wrap">
                        <user-chip v-if="item.user_id" :user-id="item.user_id" :username="item.username" size="xs" @click.stop></user-chip>
                        <span v-else class="dw-feed-uname">Someone</span>
                        <span class="dw-feed-action">[[ friendlyAction(item.action) ]]</span>
                    </div>
                    <div v-if="item.description" class="dw-feed-desc" :title="item.description">[[ item.description ]]</div>
                    <div class="dw-feed-time"><i class="fa-regular fa-clock me-1 opacity-40"></i>[[ formatTime(item.created_at) ]]</div>
                </div>
            </div>
        </div>

        <template #settings>
            <div>
                <label class="form-label small fw-bold text-muted text-uppercase mb-1">Items shown</label>
                <select class="form-select form-select-sm" v-model.number="editForm.limit">
                    <option :value="5">5</option>
                    <option :value="8">8</option>
                    <option :value="15">15</option>
                    <option :value="20">20</option>
                </select>
            </div>
        </template>
    </widget-frame>
    `,
}

export default ActivityFeedWidget
