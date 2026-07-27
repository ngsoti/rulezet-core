/**
 * timeline.js — Vertical tree timeline with collapse/expand per item.
 *
 * Props:
 *   items        Array   Required. Each item: { uuid, title, description, level,
 *                        category, action, created_at, actor_name, meta }
 *   loading      Boolean Show skeleton rows
 *   group-by-day Boolean Group items under sticky day headers (default: true)
 *   max-desc     Number  Max chars shown in description before truncation (default: 180)
 *
 * Events:
 *   select(item)  — item clicked
 */

const { computed, ref } = Vue

import MetaChangeList from './meta-change-list.js'

// ── Helpers ───────────────────────────────────────────────────────────────────

const LEVEL_CONFIG = {
    info:    { color: 'tl-dot--info',    icon: 'fa-circle-info'  },
    success: { color: 'tl-dot--success', icon: 'fa-circle-check' },
    warning: { color: 'tl-dot--warning', icon: 'fa-triangle-exclamation' },
    error:   { color: 'tl-dot--error',   icon: 'fa-circle-xmark' },
}

const CATEGORY_ICONS = {
    user:     'fa-user',
    system:   'fa-gear',
    security: 'fa-shield-halved',
    admin:    'fa-crown',
    api:      'fa-code',
    database: 'fa-database',
    rule:     'fa-file-shield',
    connectors: 'fa-plug',
}

function levelConfig(level) {
    return LEVEL_CONFIG[level] || LEVEL_CONFIG.info
}

function categoryIcon(cat) {
    return CATEGORY_ICONS[cat] || 'fa-circle'
}

function initials(name) {
    if (!name) return '?'
    const parts = name.trim().split(/\s+/)
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase()
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase()
}

function formatRelative(iso) {
    if (!iso) return '—'
    const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
    if (diff < 5)    return 'just now'
    if (diff < 60)   return `${diff}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
    return new Date(iso).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

function formatFull(iso) {
    if (!iso) return ''
    return new Date(iso).toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
}

function dayKey(iso) {
    if (!iso) return 'Unknown'
    const d = new Date(iso)
    const today     = new Date(); today.setHours(0,0,0,0)
    const yesterday = new Date(today); yesterday.setDate(yesterday.getDate() - 1)
    const itemDay   = new Date(d); itemDay.setHours(0,0,0,0)

    if (itemDay.getTime() === today.getTime()) return 'Today'
    if (itemDay.getTime() === yesterday.getTime()) return 'Yesterday'
    return d.toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric', year: 'numeric' })
}

function truncate(str, max) {
    if (!str || str.length <= max) return str
    return str.slice(0, max) + '…'
}

// ── Component ─────────────────────────────────────────────────────────────────

export default {
    name: 'Timeline',

    components: { 'meta-change-list': MetaChangeList },

    props: {
        items:          { type: Array,   default: () => [] },
        loading:        { type: Boolean, default: false },
        groupByDay:     { type: Boolean, default: true },
        maxDesc:        { type: Number,  default: 180 },
        canDelete:      { type: Boolean, default: false },
        startCollapsed: { type: Boolean, default: false },
    },

    emits: ['select', 'delete', 'view-content'],

    setup(props, { emit }) {
        const collapsed = ref(new Set())

        function toggle(uuid) {
            const s = new Set(collapsed.value)
            if (s.has(uuid)) s.delete(uuid)
            else s.add(uuid)
            collapsed.value = s
        }

        function isCollapsed(uuid) { return collapsed.value.has(uuid) }

        const _seeded = ref(false)
        function seedCollapsed(items) {
            if (_seeded.value || !items.length) return
            if (props.startCollapsed) {
                collapsed.value = new Set(items.map(i => i.uuid))
            }
            _seeded.value = true
        }

        const grouped = computed(() => {
            seedCollapsed(props.items)
            if (!props.groupByDay) {
                return [{ day: null, items: props.items }]
            }
            const map = new Map()
            for (const item of props.items) {
                const key = dayKey(item.created_at)
                if (!map.has(key)) map.set(key, [])
                map.get(key).push(item)
            }
            return Array.from(map.entries()).map(([day, items]) => ({ day, items }))
        })

        function expandAll()   { collapsed.value = new Set() }
        function collapseAll() { collapsed.value = new Set(props.items.map(i => i.uuid)) }

        return {
            grouped, collapsed, toggle, isCollapsed,
            expandAll, collapseAll,
            levelConfig, categoryIcon, initials,
            formatRelative, formatFull, truncate,
        }
    },

    expose: ['expandAll', 'collapseAll'],

    template: `
<div class="tl">

    <!-- Global controls -->
    <div v-if="!loading && items.length" class="tl-controls">
        <button class="tl-ctrl-btn" @click="expandAll">
            <i class="fas fa-chevron-down"></i> Expand all
        </button>
        <button class="tl-ctrl-btn" @click="collapseAll">
            <i class="fas fa-chevron-right"></i> Collapse all
        </button>
    </div>

    <!-- Skeleton -->
    <template v-if="loading">
        <div class="tl-skeleton" v-for="i in 5" :key="i">
            <div class="tl-skeleton-dot"></div>
            <div class="tl-skeleton-body">
                <div class="tl-skeleton-title"></div>
                <div class="tl-skeleton-meta"></div>
            </div>
        </div>
    </template>

    <!-- Empty -->
    <div v-else-if="!items.length" class="tl-empty">
        <i class="fas fa-scroll"></i>
        <span>No events</span>
    </div>

    <!-- Groups -->
    <template v-else>
        <div v-for="group in grouped" :key="group.day" class="tl-group">
            <div v-if="group.day" class="tl-day-header">
                <span>{{ group.day }}</span>
            </div>

            <!-- Tree trunk wraps all items in the group -->
            <div class="tl-trunk">
                <div
                    v-for="(item, idx) in group.items"
                    :key="item.uuid"
                    :class="['tl-item', idx === group.items.length - 1 ? 'tl-item--last' : '']">

                    <!-- Branch connector + dot -->
                    <div class="tl-branch">
                        <div :class="['tl-dot', levelConfig(item.level).color]">
                            <i :class="item.icon || ('fas ' + levelConfig(item.level).icon)"></i>
                        </div>
                    </div>

                    <!-- Content card -->
                    <div class="tl-content">
                        <!-- Header row: title + badges + chevron + delete -->
                        <div class="tl-header" @click.stop="toggle(item.uuid); $emit('select', item)">
                            <span class="tl-title">{{ item.title }}</span>
                            <div class="tl-badges">
                                <span class="tl-cat-badge">
                                    <i :class="'fas ' + categoryIcon(item.category)"></i>
                                    {{ item.category }}
                                </span>
                                <span :class="['tl-level-badge', 'tl-level-badge--' + item.level]">
                                    {{ item.level }}
                                </span>
                            </div>
                            <button v-if="canDelete"
                                    class="tl-delete-btn"
                                    @click.stop="$emit('delete', item)"
                                    title="Delete this entry">
                                <i class="fas fa-trash"></i>
                            </button>
                            <button class="tl-chevron" :class="{ 'tl-chevron--open': !isCollapsed(item.uuid) }">
                                <i class="fas fa-chevron-right"></i>
                            </button>
                        </div>

                        <!-- Collapsible body -->
                        <div v-show="!isCollapsed(item.uuid)" class="tl-body">
                            <div class="tl-meta">
                                <span v-if="item.actor_name" class="tl-actor">
                                    <span class="tl-actor-avatar">{{ initials(item.actor_name) }}</span>
                                    {{ item.actor_name }}
                                </span>
                                <span v-else class="tl-actor tl-actor--system">
                                    <i class="fas fa-gear"></i> System
                                </span>
                                <span class="tl-sep">·</span>
                                <span class="tl-time" :title="formatFull(item.created_at)">
                                    {{ formatRelative(item.created_at) }}
                                </span>
                                <span v-if="item.action" class="tl-sep">·</span>
                                <span v-if="item.action" class="tl-action">{{ item.action }}</span>
                            </div>

                            <div v-if="item.description" class="tl-desc">
                                {{ item.description }}
                            </div>

                            <!-- Human-readable metadata diff (e.g. "Owner: X -> Y") — never raw JSON -->
                            <meta-change-list v-if="item.metadata_changes && item.metadata_changes.length"
                                               :changes="item.metadata_changes" compact>
                            </meta-change-list>

                            <!-- View proposal button -->
                            <div v-if="item.proposal_id" class="tl-diff-hint" style="cursor:default;">
                                <a :href="'/rule/proposal_content_discuss?id=' + item.proposal_id"
                                   class="tl-action-btn"
                                   @click.stop>
                                    <i class="fas fa-arrow-up-right-from-square me-1"></i>View proposal
                                </a>
                            </div>

                            <!-- Content / diff hints for version events -->
                            <div v-if="item.type === 'update' && (item.old_content || item.new_content)" class="d-flex gap-2 flex-wrap">
                                <div class="tl-diff-hint" style="cursor:pointer;" @click.stop="$emit('view-content', item)">
                                    <i class="fas fa-file-code me-1"></i>
                                    Click to see the rule
                                </div>
                                <div class="tl-diff-hint" style="cursor:pointer;" @click.stop="$emit('select', item)">
                                    <i class="fas fa-code-compare me-1"></i>
                                    Click to see diff
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </template>

</div>
    `,
}
