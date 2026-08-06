/**
 * smart-editor.js — Intelligent text/markdown/code editor form field
 *
 * Props:
 *   modelValue   String   content (v-model)
 *   mode         String   'text' | 'markdown' | 'code'  (default: 'text')
 *   language     String   initial code language          (default: 'javascript')
 *   placeholder  String
 *   name         String   HTML name for form submission (renders hidden input)
 *   minHeight    String   CSS value e.g. '220px'
 *   maxHeight    String   CSS value e.g. '600px'
 *   readonly     Boolean
 *
 * Emits:
 *   update:modelValue  (v-model compatible)
 *
 * Usage:
 *   import SmartEditor from '/static/js/components/smart-editor.js'
 *
 *   <!-- v-model -->
 *   <smart-editor v-model="body" mode="markdown"></smart-editor>
 *
 *   <!-- plain form field -->
 *   <smart-editor name="content" mode="code" language="python"></smart-editor>
 *   <button type="submit">Save</button>
 */

// ── Module-level singletons ────────────────────────────────────────────────────

const PAIRS   = { '{': '}', '[': ']', '(': ')', '"': '"', "'": "'", '`': '`' }
const CLOSERS = new Set([')', ']', '}', '"', "'", '`'])

const _KNOWN_HLJS = new Set([
    'bash','c','cpp','css','diff','go','html','http','java','javascript','json',
    'kotlin','lua','markdown','nginx','php','plaintext','python','ruby','rust',
    'shell','sql','swift','typescript','xml','yaml','text',
])
const _LANG_ALIASES = { nse:'lua', sigma:'yaml', wazuh:'xml', yara:'text', suricata:'text', zeek:'text', crs:'text', nova:'text', kql:'sql' }
function _resolve_lang(lang) {
    const mapped = _LANG_ALIASES[lang] || lang
    return _KNOWN_HLJS.has(mapped) ? mapped : 'text'
}

let _hljs_p   = null
let _marked_p = null
let _purify_p = null

function load_hljs() {
    if (window.hljs)  return Promise.resolve(window.hljs)
    if (_hljs_p) return _hljs_p
    _hljs_p = new Promise((res, rej) => {
        const s = document.createElement('script')
        s.src   = '/static/js/hljs.min.js'
        s.onload  = () => res(window.hljs)
        s.onerror = rej
        document.head.appendChild(s)
    })
    return _hljs_p
}

function load_marked() {
    if (window.marked) return Promise.resolve(window.marked)
    if (_marked_p) return _marked_p
    _marked_p = new Promise((res, rej) => {
        const s = document.createElement('script')
        s.src   = '/static/js/marked.min.js'
        s.onload  = () => res(window.marked)
        s.onerror = rej
        document.head.appendChild(s)
    })
    return _marked_p
}

function load_purify() {
    if (window.DOMPurify) return Promise.resolve(window.DOMPurify)
    if (_purify_p) return _purify_p
    _purify_p = new Promise((res, rej) => {
        const s = document.createElement('script')
        s.src   = '/static/js/purify.min.js'
        s.onload  = () => res(window.DOMPurify)
        s.onerror = rej
        document.head.appendChild(s)
    })
    return _purify_p
}

// ── Component ──────────────────────────────────────────────────────────────────

const { ref, computed, watch, nextTick, onMounted, onBeforeUnmount } = Vue

const LINE_H = 21   // px — must match CSS line-height on .se-overlay / .se-ta--code
const PAD_Y  = 24   // px — top + bottom padding inside code area

const MD_ACTIONS = [
    { id: 'bold',    icon: 'fa-bold',        title: 'Bold'          },
    { id: 'italic',  icon: 'fa-italic',      title: 'Italic'        },
    { id: 'h2',      icon: 'fa-heading',     title: 'Heading'       },
    { id: 'code',    icon: 'fa-terminal',    title: 'Inline code'   },
    { id: 'link',    icon: 'fa-link',        title: 'Link'          },
    { id: 'ul',      icon: 'fa-list-ul',     title: 'Bullet list'   },
    { id: 'ol',      icon: 'fa-list-ol',     title: 'Numbered list' },
    { id: 'quote',   icon: 'fa-quote-right', title: 'Blockquote'    },
    { id: 'hr',      icon: 'fa-minus',       title: 'Horizontal rule' },
]

export default {
    name: 'SmartEditor',

    props: {
        modelValue:  { type: String,  default: '' },
        mode:        { type: String,  default: 'text' },
        language:    { type: String,  default: 'javascript' },
        placeholder: { type: String,  default: 'Type here…' },
        name:        { type: String,  default: null },
        minHeight:   { type: String,  default: '220px' },
        maxHeight:   { type: String,  default: '600px' },
        readonly:    { type: Boolean, default: false },
    },

    emits: ['update:modelValue'],

    template: `
<div class="se-root" :class="'se-mode--' + mode">

    <!-- hidden input for native form submission -->
    <input v-if="name" type="hidden" :name="name" :value="inner_value">

    <!-- ── Toolbar ──────────────────────────────────────────────────── -->
    <div class="se-toolbar">

        <!-- Mode badge (display only) -->
        <span class="se-mode-badge">
            <i :class="mode_icon"></i> {{ mode_label }}
        </span>

        <div class="se-toolbar-sep"></div>

        <!-- Markdown: formatting shortcuts + preview toggle -->
        <template v-if="mode === 'markdown'">
            <template v-if="!show_preview">
                <button
                    v-for="a in MD_ACTIONS" :key="a.id"
                    class="se-tb-btn"
                    type="button"
                    :title="a.title"
                    @click="md_action(a.id)">
                    <i :class="'fas ' + a.icon"></i>
                </button>
                <div class="se-toolbar-sep"></div>
            </template>
            <button
                class="se-preview-toggle"
                :class="{ 'is-active': show_preview }"
                type="button"
                @click="toggle_preview">
                <i :class="show_preview ? 'fas fa-pen' : 'fas fa-eye'"></i>
                {{ show_preview ? 'Edit' : 'Preview' }}
            </button>
            <div class="se-toolbar-sep"></div>
        </template>

        <!-- Code: language badge (display only) -->
        <span v-if="mode === 'code'" class="se-lang-badge">{{ language }}</span>

        <div class="se-toolbar-spacer"></div>

        <!-- Undo / Redo buttons -->
        <button class="se-tb-btn" type="button" title="Undo (Ctrl+Z)"
            :disabled="undo_count === 0" @click="btn_undo">
            <i class="fas fa-rotate-left"></i>
        </button>
        <button class="se-tb-btn" type="button" title="Redo (Ctrl+Y)"
            :disabled="redo_count === 0" @click="btn_redo">
            <i class="fas fa-rotate-right"></i>
        </button>
        <div class="se-toolbar-sep"></div>

        <span class="se-char-count">{{ stat_label }}</span>
    </div>

    <!-- ── Body ─────────────────────────────────────────────────────── -->
    <div class="se-body" :style="body_style">

        <!-- TEXT ───────────────────────────────────── -->
        <template v-if="mode === 'text'">
            <textarea
                ref="ta_ref"
                class="se-ta"
                :value="inner_value"
                @input="on_input"
                :placeholder="placeholder"
                :readonly="readonly"
                spellcheck="true"
                @keydown="on_keydown">
            </textarea>
        </template>

        <!-- MARKDOWN ───────────────────────────────── -->
        <template v-else-if="mode === 'markdown'">
            <textarea
                v-show="!show_preview"
                ref="ta_ref"
                class="se-ta se-ta--md"
                :value="inner_value"
                @input="on_input"
                :placeholder="placeholder"
                :readonly="readonly"
                spellcheck="false"
                @keydown="on_keydown">
            </textarea>
            <div v-show="show_preview" class="se-md-preview" v-html="rendered_md"></div>
        </template>

        <!-- CODE ───────────────────────────────────── -->
        <template v-else>
            <div class="se-code-wrap" :style="code_wrap_style">
                <div class="se-gutter" ref="gutter_ref">
                    <span v-for="n in line_count" :key="n" class="se-lnum">{{ n }}</span>
                </div>
                <div class="se-code-area">
                    <pre
                        class="se-overlay"
                        ref="overlay_ref"
                        aria-hidden="true"
                        v-html="highlighted || escaped_code">
                    </pre>
                    <textarea
                        ref="ta_ref"
                        class="se-ta se-ta--code"
                        :value="inner_value"
                        @input="on_input"
                        :placeholder="placeholder"
                        :readonly="readonly"
                        spellcheck="false"
                        autocorrect="off"
                        autocapitalize="off"
                        @keydown="on_keydown"
                        @scroll="sync_scroll">
                    </textarea>
                </div>
            </div>
            <div v-if="!hljs_ready" class="se-code-loading">
                <i class="fas fa-spinner fa-spin"></i> Loading syntax engine…
            </div>
        </template>

    </div><!-- /.se-body -->
</div><!-- /.se-root -->
    `,

    setup(props, { emit }) {

        // ── Reactive state ──────────────────────────────────────────────
        const inner_value  = ref(props.modelValue)
        const hljs_ready   = ref(false)
        const highlighted  = ref('')
        const show_preview = ref(false)
        const rendered_md  = ref('')
        const ta_ref       = ref(null)
        const overlay_ref  = ref(null)
        const gutter_ref   = ref(null)

        // ── Undo / redo history ─────────────────────────────────────────
        const _undo = []   // stack of past string values
        const _redo = []
        let _undo_t    = null   // debounce timer handle
        let _prev_snap = null   // value captured at start of current typing burst
        const undo_count = ref(0)
        const redo_count = ref(0)

        // Sync with parent v-model
        watch(() => props.modelValue, v => { if (v !== inner_value.value) inner_value.value = v })
        watch(inner_value, v => emit('update:modelValue', v))

        // ── Computed ────────────────────────────────────────────────────
        const MODE_META = {
            text:     { label: 'Text',     icon: 'fas fa-align-left' },
            markdown: { label: 'Markdown', icon: 'fas fa-brands fa-markdown' },
            code:     { label: 'Code',     icon: 'fas fa-code' },
        }
        const mode_label = computed(() => MODE_META[props.mode]?.label ?? props.mode)
        const mode_icon  = computed(() => MODE_META[props.mode]?.icon  ?? 'fas fa-file')

        const line_count = computed(() =>
            (inner_value.value.match(/\n/g) || []).length + 1
        )

        const stat_label = computed(() => {
            const c = inner_value.value.length
            if (props.mode === 'text') {
                const w = inner_value.value.trim() ? inner_value.value.trim().split(/\s+/).length : 0
                return `${w}w · ${c}c`
            }
            if (props.mode === 'code') return `${line_count.value}L · ${c}c`
            return `${c}c`
        })

        const min_h = computed(() => parseInt(props.minHeight) || 220)
        const max_h = computed(() => parseInt(props.maxHeight) || 600)

        const body_style = computed(() =>
            props.mode === 'code' ? {} : { minHeight: props.minHeight }
        )

        const code_wrap_style = computed(() => {
            const h = Math.min(max_h.value, Math.max(min_h.value, line_count.value * LINE_H + PAD_Y))
            return { minHeight: h + 'px' }
        })

        const escaped_code = computed(() =>
            inner_value.value
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
        )

        // ── highlight.js ────────────────────────────────────────────────
        function refresh_highlight() {
            if (!hljs_ready.value || !window.hljs) return
            const code = inner_value.value
            if (!code) { highlighted.value = ''; return }
            try {
                const lang = _resolve_lang(props.language)
                if (lang === 'text' || lang === 'plaintext') {
                    highlighted.value = escaped_code.value
                } else {
                    highlighted.value = window.hljs.highlight(code, { language: lang }).value
                }
            } catch {
                highlighted.value = window.hljs.highlightAuto(code).value
            }
        }

        // ── marked ──────────────────────────────────────────────────────
        function _sanitize_html(html) {
            if (window.DOMPurify) return window.DOMPurify.sanitize(html)
            // DOMPurify failed to load — fall back to a minimal strip as last resort
            const tmp = document.createElement('div')
            tmp.innerHTML = html
            tmp.querySelectorAll('script, iframe, object, embed, form').forEach(el => el.remove())
            tmp.querySelectorAll('*').forEach(el => {
                for (const attr of [...el.attributes]) {
                    const n = attr.name.toLowerCase()
                    const v = attr.value
                    if (n.startsWith('on') ||
                        ((n === 'href' || n === 'src' || n === 'action') && /^javascript:/i.test(v.trim()))) {
                        el.removeAttribute(attr.name)
                    }
                }
            })
            return tmp.innerHTML
        }

        function render_md() {
            if (!window.marked) return
            try { rendered_md.value = _sanitize_html(window.marked.parse(inner_value.value)) }
            catch { rendered_md.value = '<p><em>Render error</em></p>' }
        }

        async function toggle_preview() {
            show_preview.value = !show_preview.value
            if (show_preview.value) {
                if (!window.marked) await load_marked()
                if (!window.DOMPurify) await load_purify()
                render_md()
            }
        }

        // ── Debounced content watcher ───────────────────────────────────
        let _hl_t = null, _md_t = null

        watch(inner_value, () => {
            if (props.mode === 'code' && hljs_ready.value) {
                clearTimeout(_hl_t)
                _hl_t = setTimeout(refresh_highlight, 80)
            }
            if (props.mode === 'markdown' && show_preview.value && window.marked) {
                clearTimeout(_md_t)
                _md_t = setTimeout(render_md, 100)
            }
        })

        // ── Auto-close / smart keydown ──────────────────────────────────
        function on_keydown(e) {
            if (e.isComposing) return
            const ta  = e.target
            const s   = ta.selectionStart
            const sel = ta.selectionEnd
            const val = inner_value.value
            const key = e.key

            // ── Undo / Redo ──────────────────────────────────────────
            if ((e.ctrlKey || e.metaKey) && !e.shiftKey && key === 'z') {
                e.preventDefault(); do_undo(ta); return
            }
            if ((e.ctrlKey || e.metaKey) && (key === 'y' || (e.shiftKey && key === 'z'))) {
                e.preventDefault(); do_redo(ta); return
            }

            // ── Auto-close pairs ─────────────────────────────────────
            if (PAIRS[key] && !e.ctrlKey && !e.metaKey) {
                e.preventDefault()
                _save_now()
                const selected = val.slice(s, sel)
                const close = PAIRS[key]
                const nv = val.slice(0, s) + key + selected + close + val.slice(sel)
                set_value(ta, nv, s + 1 + selected.length)
                return
            }

            // ── Skip over auto-inserted closing char ─────────────────
            if (CLOSERS.has(key) && val[s] === key && s === sel) {
                e.preventDefault()
                ta.selectionStart = ta.selectionEnd = s + 1
                return
            }

            // ── Backspace: delete both chars of an empty pair ────────
            if (key === 'Backspace' && s === sel && s > 0) {
                const prev = val[s - 1], next = val[s]
                if (PAIRS[prev] === next) {
                    e.preventDefault()
                    _save_now()
                    set_value(ta, val.slice(0, s - 1) + val.slice(s + 1), s - 1)
                    return
                }
            }

            // ── Tab: indent / dedent ─────────────────────────────────
            if (key === 'Tab') {
                e.preventDefault()
                _save_now()
                if (s === sel) {
                    // No selection: insert 2 spaces at cursor
                    set_value(ta, val.slice(0, s) + '  ' + val.slice(sel), s + 2)
                } else {
                    const before   = val.slice(0, s)
                    const selected = val.slice(s, sel)
                    const after    = val.slice(sel)
                    if (e.shiftKey) {
                        const dedented = selected.replace(/^  /gm, '')
                        set_value(ta, before + dedented + after, s, s + dedented.length)
                    } else {
                        const indented = selected.replace(/^/gm, '  ')
                        set_value(ta, before + indented + after, s, s + indented.length)
                    }
                }
                return
            }

            // ── Enter: preserve indent + open-bracket extra indent ───
            if (key === 'Enter' && !e.shiftKey) {
                const line_start = val.lastIndexOf('\n', s - 1) + 1
                const indent     = val.slice(line_start, s).match(/^(\s+)/)?.[1] ?? ''
                const prev_ch    = val[s - 1]
                const next_ch    = val[s]
                const is_open    = PAIRS[prev_ch] === next_ch

                if (indent || is_open) {
                    e.preventDefault()
                    _save_now()
                    const extra      = is_open ? '  ' : ''
                    const close_line = is_open ? '\n' + indent : ''
                    const nv = val.slice(0, s) + '\n' + indent + extra + close_line + val.slice(sel)
                    set_value(ta, nv, s + 1 + indent.length + extra.length)
                }
            }
        }

        function set_value(ta, new_val, cursor_start, cursor_end = null) {
            inner_value.value = new_val
            nextTick(() => {
                ta.selectionStart = cursor_start
                ta.selectionEnd   = cursor_end ?? cursor_start
            })
        }

        // ── Undo/redo functions ─────────────────────────────────────────

        // Called on every regular @input — captures the pre-burst state debounced.
        function on_input(e) {
            if (_prev_snap === null) _prev_snap = inner_value.value
            inner_value.value = e.target.value
            clearTimeout(_undo_t)
            _undo_t = setTimeout(() => {
                const v = _prev_snap
                _prev_snap = null
                if (_undo[_undo.length - 1] !== v) {
                    _undo.push(v)
                    if (_undo.length > 200) _undo.shift()
                    _redo.length = 0
                }
                undo_count.value = _undo.length
                redo_count.value = _redo.length
            }, 600)
        }

        // Push current value immediately (called before each smart edit).
        function _save_now() {
            clearTimeout(_undo_t); _prev_snap = null
            const v = inner_value.value
            if (_undo[_undo.length - 1] !== v) {
                _undo.push(v)
                if (_undo.length > 200) _undo.shift()
                _redo.length = 0
            }
            undo_count.value = _undo.length
            redo_count.value = _redo.length
        }

        function do_undo(ta) {
            clearTimeout(_undo_t); _prev_snap = null
            if (!_undo.length) return
            _redo.push(inner_value.value)
            inner_value.value = _undo.pop()
            undo_count.value = _undo.length
            redo_count.value = _redo.length
            nextTick(() => { if (ta) { ta.selectionStart = ta.selectionEnd = inner_value.value.length } })
        }

        function do_redo(ta) {
            if (!_redo.length) return
            _undo.push(inner_value.value)
            inner_value.value = _redo.pop()
            undo_count.value = _undo.length
            redo_count.value = _redo.length
            nextTick(() => { if (ta) { ta.selectionStart = ta.selectionEnd = inner_value.value.length } })
        }

        function btn_undo() { do_undo(ta_ref.value) }
        function btn_redo() { do_redo(ta_ref.value) }

        // ── Code overlay scroll sync ────────────────────────────────────
        function sync_scroll(e) {
            if (overlay_ref.value) {
                overlay_ref.value.scrollTop  = e.target.scrollTop
                overlay_ref.value.scrollLeft = e.target.scrollLeft
            }
            if (gutter_ref.value) {
                gutter_ref.value.scrollTop = e.target.scrollTop
            }
        }

        // ── Markdown toolbar actions ────────────────────────────────────
        function md_action(id) {
            const ta = ta_ref.value
            if (!ta) return
            const { selectionStart: s, selectionEnd: e } = ta
            const val = inner_value.value
            const sel = val.slice(s, e)

            const WRAP = {
                bold:   ['**', '**'],
                italic: ['*',  '*'],
                code:   ['`',  '`'],
            }
            const LINE_PREFIX = {
                h2:    '## ',
                ul:    '- ',
                ol:    '1. ',
                quote: '> ',
            }

            if (WRAP[id]) {
                const [o, c] = WRAP[id]
                const text = sel || 'text'
                const nv   = val.slice(0, s) + o + text + c + val.slice(e)
                set_value(ta, nv, s + o.length, s + o.length + text.length)
            } else if (LINE_PREFIX[id]) {
                const pfx   = LINE_PREFIX[id]
                const ls    = val.lastIndexOf('\n', s - 1) + 1
                const nv    = val.slice(0, ls) + pfx + val.slice(ls)
                set_value(ta, nv, s + pfx.length)
            } else if (id === 'link') {
                const text   = sel || 'link text'
                const snippet = '[' + text + '](url)'
                const nv     = val.slice(0, s) + snippet + val.slice(e)
                set_value(ta, nv, s + 1, s + 1 + text.length)
            } else if (id === 'hr') {
                const nv = val.slice(0, s) + '\n\n---\n\n' + val.slice(e)
                set_value(ta, nv, s + 7)
            }

            ta.focus()
        }

        // ── Lifecycle ───────────────────────────────────────────────────
        onMounted(async () => {
            if (props.mode === 'code') {
                await load_hljs()
                hljs_ready.value = true
                refresh_highlight()
            }
        })

        onBeforeUnmount(() => { clearTimeout(_hl_t); clearTimeout(_md_t) })

        return {
            inner_value, hljs_ready, highlighted, escaped_code,
            show_preview, rendered_md,
            ta_ref, overlay_ref, gutter_ref,
            MD_ACTIONS,
            mode_label, mode_icon,
            line_count, stat_label, body_style, code_wrap_style,
            undo_count, redo_count, btn_undo, btn_redo,
            on_input, on_keydown, sync_scroll, md_action, toggle_preview,
        }
    }
}
