/**
 * regex-tester.js — Live regular expression tester with match highlighting.
 *
 * Fully self-contained interactive component.
 *
 * Props:
 *   default-pattern String  Pre-fill the pattern input
 *   default-flags   String  Pre-fill the flags (e.g. 'gi')
 *   default-text    String  Pre-fill the test text
 *
 * Events:
 *   none
 */

const { ref, computed, watch } = Vue

const ALL_FLAGS = [
    { key: 'g', label: 'g', title: 'Global — find all matches' },
    { key: 'i', label: 'i', title: 'Insensitive — case-insensitive' },
    { key: 'm', label: 'm', title: 'Multiline — ^ and $ match line boundaries' },
    { key: 's', label: 's', title: 'Dotall — . matches newline characters' },
]

const MATCH_COLORS = [
    '#3b82f6', '#a855f7', '#22c55e', '#f59e0b', '#06b6d4', '#f97316',
]

export default {
    name: 'RegexTester',

    props: {
        defaultPattern: { type: String, default: '' },
        defaultFlags:   { type: String, default: 'g' },
        defaultText:    { type: String, default: '' },
    },

    setup(props) {
        const pattern     = ref(props.defaultPattern)
        const active_flags = ref(new Set(props.defaultFlags.split('').filter(Boolean)))
        const test_text   = ref(props.defaultText)
        const regex_error = ref('')

        const flags_str = computed(() => [...active_flags.value].join(''))

        function toggle_flag(f) {
            if (active_flags.value.has(f)) {
                active_flags.value.delete(f)
            } else {
                active_flags.value.add(f)
            }
            active_flags.value = new Set(active_flags.value)
        }

        const result = computed(() => {
            regex_error.value = ''
            const p = pattern.value
            if (!p) return { matches: [], segments: [{ text: test_text.value, match_idx: null }] }

            let re
            const f = flags_str.value.includes('g') ? flags_str.value : flags_str.value + 'g'
            try {
                re = new RegExp(p, f)
            } catch (e) {
                regex_error.value = e.message
                return { matches: [], segments: [{ text: test_text.value, match_idx: null }] }
            }

            const text    = test_text.value
            const matches = []
            let m
            re.lastIndex  = 0

            while ((m = re.exec(text)) !== null) {
                matches.push({
                    index:  m.index,
                    end:    m.index + m[0].length,
                    text:   m[0],
                    groups: m.slice(1),
                })
                if (m[0].length === 0) re.lastIndex++ // avoid infinite loop on zero-width match
                if (matches.length >= 500) break
            }

            // Build segments for highlighted rendering
            const segments = []
            let pos = 0
            for (const [mi, match] of matches.entries()) {
                if (match.index > pos) {
                    segments.push({ text: text.slice(pos, match.index), match_idx: null })
                }
                segments.push({ text: match.text, match_idx: mi % MATCH_COLORS.length })
                pos = match.end
            }
            if (pos < text.length) {
                segments.push({ text: text.slice(pos), match_idx: null })
            }
            if (!segments.length) {
                segments.push({ text, match_idx: null })
            }

            return { matches, segments }
        })

        const match_count = computed(() => result.value.matches.length)

        return {
            pattern, active_flags, test_text, flags_str, regex_error,
            result, match_count,
            toggle_flag, ALL_FLAGS, MATCH_COLORS,
        }
    },

    template: `
<div class="rt">

    <!-- Pattern input -->
    <div class="rt-pattern-row">
        <span class="rt-delimiter">/</span>
        <input
            v-model="pattern"
            class="rt-pattern-input"
            placeholder="pattern"
            type="text"
            spellcheck="false"
            :class="{ 'rt-pattern-input--error': regex_error }">
        <span class="rt-delimiter">/</span>
        <span class="rt-flags-display">{{ flags_str || '&nbsp;' }}</span>
        <div class="rt-flags">
            <button
                v-for="f in ALL_FLAGS"
                :key="f.key"
                :class="['rt-flag-btn', { 'is-active': active_flags.has(f.key) }]"
                :title="f.title"
                @click="toggle_flag(f.key)">
                {{ f.label }}
            </button>
        </div>
    </div>

    <!-- Regex error -->
    <div v-if="regex_error" class="rt-error">
        <i class="fas fa-circle-xmark me-1"></i>{{ regex_error }}
    </div>

    <!-- Test area + highlighted overlay -->
    <div class="rt-test-wrap">
        <div class="rt-highlighted" aria-hidden="true">
            <span
                v-for="(seg, i) in result.segments"
                :key="i"
                :class="seg.match_idx !== null ? 'rt-match' : ''"
                :style="seg.match_idx !== null ? { background: MATCH_COLORS[seg.match_idx] + '33', borderBottom: '2px solid ' + MATCH_COLORS[seg.match_idx] } : {}">{{ seg.text }}</span><span v-if="!test_text" class="rt-placeholder">Test string…</span>
        </div>
        <textarea
            v-model="test_text"
            class="rt-textarea"
            placeholder="Test string…"
            spellcheck="false"
            rows="5">
        </textarea>
    </div>

    <!-- Match summary -->
    <div class="rt-summary">
        <span v-if="!pattern" class="rt-summary-hint">Enter a pattern to see matches</span>
        <template v-else-if="regex_error">
            <span class="rt-summary-error">Invalid pattern</span>
        </template>
        <template v-else>
            <span :class="['rt-match-count', match_count > 0 ? 'rt-match-count--hit' : 'rt-match-count--miss']">
                <i :class="['fas', match_count > 0 ? 'fa-check' : 'fa-xmark']"></i>
                {{ match_count }} match{{ match_count !== 1 ? 'es' : '' }}
            </span>
        </template>
    </div>

    <!-- Match list -->
    <div v-if="result.matches.length > 0" class="rt-match-list">
        <div
            v-for="(m, i) in result.matches"
            :key="i"
            class="rt-match-row"
            :style="{ borderLeftColor: MATCH_COLORS[i % MATCH_COLORS.length] }">
            <span class="rt-match-idx">#{{ i + 1 }}</span>
            <code class="rt-match-text">{{ m.text }}</code>
            <span class="rt-match-pos">@{{ m.index }}–{{ m.end }}</span>
            <template v-if="m.groups.length">
                <span class="rt-match-groups">
                    Groups: <code v-for="(g, gi) in m.groups" :key="gi" class="rt-group">{{ g ?? 'undefined' }}</code>
                </span>
            </template>
        </div>
    </div>

</div>
    `,
}
