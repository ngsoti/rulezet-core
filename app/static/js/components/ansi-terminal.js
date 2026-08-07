/**
 * ansi-terminal.js — Terminal output panel with ANSI color rendering.
 *
 * Accepts structured log entries OR raw text lines.
 *
 * Props:
 *   entries     Array   [{ts?, msg, level?}] — structured (job logs)
 *   lines       Array   Raw strings, may contain ANSI escape sequences
 *   loading     Boolean Show skeleton
 *   live        Boolean Auto-scroll to bottom on new content (default: true)
 *   title       String  Header label (default: 'Terminal')
 *   max-lines   Number  Keep only last N lines (default: 5000)
 *   mode        String  'view' (read-only) | 'edit' (input line at bottom, emits @submit)
 *   placeholder String  Placeholder in edit mode (default: 'Enter command…')
 *
 * Exposes (via ref):
 *   scroll_bottom()  — programmatically scroll to bottom
 *   focus_input()    — focus the edit-mode input (no-op in view mode)
 *
 * Events:
 *   clear          — user clicked the clear button
 *   submit(text)   — user submitted a command (edit mode only)
 */

const { ref, computed, watch, onMounted, onUnmounted, nextTick } = Vue

const THEME_KEY = 'rz-terminal-theme'
function load_default_theme() {
    const t = localStorage.getItem(THEME_KEY)
    return ['dark', 'light', 'hacker'].includes(t) ? t : 'dark'
}

// ── ANSI parser ────────────────────────────────────────────────────────────────

const _ANSI_FG = {
    '30':'#4a4a4a','31':'#ef4444','32':'#22c55e','33':'#f59e0b',
    '34':'#3b82f6','35':'#a855f7','36':'#06b6d4','37':'#9ca3af',
    '90':'#6b7280','91':'#f87171','92':'#4ade80','93':'#fbbf24',
    '94':'#60a5fa','95':'#c084fc','96':'#22d3ee','97':'#f3f4f6',
}

function parse_ansi(text) {
    if (!text) return [{ text: '', color: null, bold: false }]
    const parts = []
    let color = null, bold = false
    const chunks = text.split(/\x1b\[([0-9;]*)m/)
    for (let i = 0; i < chunks.length; i++) {
        if (i % 2 === 0) {
            if (chunks[i]) parts.push({ text: chunks[i], color, bold })
        } else {
            const codes = chunks[i] ? chunks[i].split(';') : ['0']
            for (const raw of codes) {
                const c = parseInt(raw, 10) || 0
                if (c === 0) { color = null; bold = false }
                else if (c === 1) { bold = true }
                else if (c === 22) { bold = false }
                else if ((c >= 30 && c <= 37) || (c >= 90 && c <= 97)) {
                    color = _ANSI_FG[String(c)] || null
                }
                else if (c === 39) { color = null }
            }
        }
    }
    if (!parts.length) parts.push({ text: text, color: null, bold: false })
    return parts
}

// ── Level → class ──────────────────────────────────────────────────────────────

const LEVEL_CLASS = {
    info:    'at-line--info',
    success: 'at-line--success',
    warning: 'at-line--warning',
    error:   'at-line--error',
    debug:   'at-line--debug',
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmt_ts(ts) {
    if (!ts) return ''
    try {
        return new Date(ts).toLocaleTimeString(undefined, { hour12: false })
    } catch { return '' }
}

// ── Component ──────────────────────────────────────────────────────────────────

export default {
    name: 'AnsiTerminal',

    props: {
        entries:     { type: Array,   default: () => [] },
        lines:       { type: Array,   default: () => [] },
        loading:     { type: Boolean, default: false },
        live:        { type: Boolean, default: true },
        title:       { type: String,  default: 'Terminal' },
        maxLines:    { type: Number,  default: 5000 },
        mode:        { type: String,  default: 'view' },  // 'view' | 'edit'
        placeholder: { type: String,  default: 'Enter command…' },
    },

    emits: ['clear', 'submit', 'scroll'],

    setup(props, { emit, expose }) {
        const body_ref    = ref(null)
        const input_ref   = ref(null)
        const auto_scroll = ref(true)
        const line_count  = ref(0)
        const input_text  = ref('')
        const theme       = ref(load_default_theme())  // 'dark' | 'light' | 'hacker'
        const collapsed   = ref(false)
        const highlight_index = ref(null)
        const _THEMES = ['dark', 'light', 'hacker']
        let highlight_timer = null

        function toggle_collapse() {
            collapsed.value = !collapsed.value
            if (!collapsed.value && props.live && auto_scroll.value) scroll_bottom()
        }

        function toggle_theme() {
            const idx = _THEMES.indexOf(theme.value)
            theme.value = _THEMES[(idx + 1) % _THEMES.length]
            // Toggling here also updates the app-wide default (see /settings)
            localStorage.setItem(THEME_KEY, theme.value)
        }

        // Live-updates if the default is changed from /settings in another tab/page
        function on_theme_setting_changed() {
            theme.value = load_default_theme()
        }

        const theme_icon = computed(() => {
            if (theme.value === 'dark')   return { icon: 'fas fa-sun',      title: 'Switch to light'  }
            if (theme.value === 'light')  return { icon: 'fas fa-terminal', title: 'Switch to hacker' }
            return                               { icon: 'fas fa-moon',     title: 'Switch to dark'   }
        })

        const parsed = computed(() => {
            let source
            if (props.entries.length) {
                source = props.entries
            } else {
                source = props.lines.map(l => ({ msg: String(l) }))
            }
            if (source.length > props.maxLines) {
                source = source.slice(-props.maxLines)
            }
            line_count.value = source.length
            return source.map(e => ({
                ts:       e.ts || null,
                level:    e.level || 'info',
                cls:      LEVEL_CLASS[e.level] || 'at-line--info',
                segments: parse_ansi(e.msg || ''),
            }))
        })

        function scroll_bottom() {
            auto_scroll.value = true
            nextTick(() => {
                if (body_ref.value) body_ref.value.scrollTop = body_ref.value.scrollHeight
            })
        }

        // Jump to and briefly highlight a specific line — used by pages that
        // link a summary/tooltip entry back to its exact spot in the log.
        function scroll_to(index) {
            if (collapsed.value) collapsed.value = false
            nextTick(() => {
                const el = body_ref.value?.querySelector(`[data-line-index="${index}"]`)
                if (!el) return
                el.scrollIntoView({ block: 'center', behavior: 'smooth' })
                highlight_index.value = index
                clearTimeout(highlight_timer)
                highlight_timer = setTimeout(() => { highlight_index.value = null }, 2000)
            })
        }

        function focus_input() {
            nextTick(() => input_ref.value?.focus())
        }

        const scroll_pct = ref(100)

        function on_scroll() {
            if (!body_ref.value) return
            const { scrollTop, scrollHeight, clientHeight } = body_ref.value
            auto_scroll.value = scrollHeight - scrollTop - clientHeight < 40
            const scrollable = scrollHeight - clientHeight
            scroll_pct.value = scrollable > 0 ? Math.round((scrollTop / scrollable) * 100) : 100
            emit('scroll', { pct: scroll_pct.value })
        }

        const clear_armed = ref(false)
        let clear_arm_timer = null

        function handle_clear() {
            if (!clear_armed.value) {
                clear_armed.value = true
                clearTimeout(clear_arm_timer)
                clear_arm_timer = setTimeout(() => { clear_armed.value = false }, 3000)
                return
            }
            clearTimeout(clear_arm_timer)
            clear_armed.value = false
            emit('clear')
        }

        const copied = ref(false)
        let copied_timer = null

        function copy_all() {
            const text = parsed.value.map(e => {
                const ts  = e.ts ? fmt_ts(e.ts) + ' ' : ''
                const msg = e.segments.map(s => s.text).join('')
                return ts + msg
            }).join('\n')
            navigator.clipboard?.writeText(text).then(() => {
                copied.value = true
                clearTimeout(copied_timer)
                copied_timer = setTimeout(() => { copied.value = false }, 1400)
            })
        }

        function submit() {
            const text = input_text.value.trim()
            if (!text) return
            emit('submit', text)
            input_text.value = ''
        }

        watch(
            () => [props.entries.length, props.lines.length],
            () => { if (props.live && auto_scroll.value) scroll_bottom() }
        )

        onMounted(() => {
            if (props.live) scroll_bottom()
            window.addEventListener('rz:terminal-theme-changed', on_theme_setting_changed)
        })

        onUnmounted(() => {
            window.removeEventListener('rz:terminal-theme-changed', on_theme_setting_changed)
            clearTimeout(copied_timer)
            clearTimeout(clear_arm_timer)
        })

        expose({ scroll_bottom, focus_input, scroll_to })

        return {
            body_ref, input_ref, auto_scroll, line_count, input_text,
            theme, toggle_theme, theme_icon, copied,
            collapsed, toggle_collapse, clear_armed,
            highlight_index, scroll_pct,
            parsed, fmt_ts, on_scroll, scroll_bottom,
            handle_clear, copy_all, submit,
        }
    },

    template: `
<div class="at" :class="[ 'at--' + theme, { 'at--collapsed': collapsed } ]">
    <!-- Header -->
    <div class="at-header" :class="{ 'at-header--collapsed': collapsed }" @dblclick="toggle_collapse">
        <div class="at-header-left">
            <span class="at-dot at-dot--red"></span>
            <span class="at-dot at-dot--yellow"></span>
            <span class="at-dot at-dot--green"></span>
            <span class="at-title">{{ title }}</span>
            <span v-if="mode === 'edit'" class="at-mode-badge">interactive</span>
        </div>
        <div class="at-header-right">
            <span class="at-count">{{ line_count }} lines</span>
            <button v-if="!collapsed" class="at-btn" :title="theme_icon.title" @click="toggle_theme">
                <i :class="theme_icon.icon"></i>
            </button>
            <button v-if="!collapsed" class="at-btn" :class="{ 'at-btn--copied': copied }" :title="copied ? 'Copied!' : 'Copy all'" @click="copy_all">
                <i :class="copied ? 'fas fa-check' : 'fas fa-copy'"></i>
            </button>
            <button v-if="!collapsed" class="at-btn" title="Scroll to bottom" @click="scroll_bottom">
                <i class="fas fa-arrow-down"></i>
            </button>
            <button v-if="!collapsed" class="at-btn at-btn--danger" :class="{ 'at-btn--armed': clear_armed }"
                    :title="clear_armed ? 'Click again to confirm' : 'Clear'" @click="handle_clear">
                <i class="fas" :class="clear_armed ? 'fa-triangle-exclamation' : 'fa-trash'"></i>
            </button>
            <button class="at-btn" :title="collapsed ? 'Expand' : 'Collapse'" @click="toggle_collapse">
                <i class="fas" :class="collapsed ? 'fa-chevron-down' : 'fa-chevron-up'"></i>
            </button>
        </div>
    </div>

    <template v-if="!collapsed">
        <!-- Skeleton -->
        <div v-if="loading" class="at-body">
            <div class="at-skeleton" v-for="i in 4" :key="i"></div>
        </div>

        <!-- Empty -->
        <div v-else-if="!parsed.length" class="at-body at-empty">
            <i class="fas fa-terminal"></i>
            <span>No output yet</span>
        </div>

        <!-- Lines -->
        <div v-else class="at-body" ref="body_ref" @scroll="on_scroll">
            <div
                v-for="(line, i) in parsed"
                :key="i"
                :data-line-index="i"
                :class="['at-line', line.cls, { 'at-line--highlight': highlight_index === i }]">
                <span v-if="line.ts" class="at-ts">{{ fmt_ts(line.ts) }}</span>
                <span class="at-msg">
                    <span
                        v-for="(seg, j) in line.segments"
                        :key="j"
                        :style="{ color: seg.color || undefined, fontWeight: seg.bold ? '700' : undefined }">{{ seg.text }}</span>
                </span>
            </div>
        </div>

        <!-- Scroll position — where you are relative to the full log -->
        <div v-if="parsed.length > 0" class="at-scrollpos">
            <div class="at-scrollpos-fill" :style="{ width: scroll_pct + '%' }"></div>
        </div>

        <!-- Footer: live indicator (view) or input row (edit) -->
        <div v-if="mode === 'edit'" class="at-input-row">
            <span class="at-prompt">❯</span>
            <input
                v-model="input_text"
                ref="input_ref"
                class="at-input"
                type="text"
                :placeholder="placeholder"
                spellcheck="false"
                autocomplete="off"
                @keydown.enter.prevent="submit">
            <button class="at-btn at-send-btn" @click="submit" title="Send (Enter)">
                <i class="fas fa-arrow-right"></i>
            </button>
        </div>
        <div v-else-if="live" class="at-footer">
            <span v-if="auto_scroll" class="at-live-dot"></span>
            <span class="at-live-label">{{ auto_scroll ? 'live' : 'paused — scroll down to resume' }}</span>
        </div>
    </template>
</div>
    `,
}
