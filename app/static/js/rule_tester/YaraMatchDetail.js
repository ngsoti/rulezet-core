/**
 * YaraMatchDetail.js — Per-string hit list of a YARA match (identifier /
 * offset / length / hex), with an optional side-by-side compare against the
 * original test input. Used on the test detail page (bulk results table)
 * and TestResultDisplay.js (single test). Falls back to nothing meaningful
 * if `details` isn't a YARA `full_execution` / `batch_execution` payload.
 */
import CodeViewer from '/static/js/components/code-viewer.js';
import PaginationComponent from '/static/js/rule/paginationComponent.js';

// Cap how many raw bytes get spelled out per matched string — a single match
// can span thousands of bytes, and spacing/ascii-decoding all of them makes
// one unreadable, page-widening wall of text for no benefit (s.length already
// shows the true size).
const MAX_PREVIEW_BYTES = 64;
const STRINGS_PER_PAGE = 100;

const YaraMatchDetail = {
    name: 'YaraMatchDetail',
    delimiters: ['[[', ']]'],
    components: { CodeViewer, PaginationComponent },
    props: {
        details:      { type: Object, default: () => ({}) },
        qualityHints: { type: Array,  default: () => [] },
        // The payload the rule was tested against — { type: 'hex'|'string'|..., value }.
        // Optional: when absent, the per-string "compare" button is hidden.
        testInput:    { type: Object, default: null },
    },
    data() {
        return { openIndex: null, currentPage: 1 };
    },
    watch: {
        details() { this.currentPage = 1; this.openIndex = null; },
    },
    computed: {
        // strings_matched used to be a bare count (older results) — only ever
        // treat it as the array it's supposed to be.
        strings() {
            const sm = this.details.strings_matched;
            return Array.isArray(sm) ? sm : [];
        },
        totalPages() {
            return Math.max(1, Math.ceil(this.strings.length / STRINGS_PER_PAGE));
        },
        pagedStrings() {
            const start = (this.currentPage - 1) * STRINGS_PER_PAGE;
            return this.strings.slice(start, start + STRINGS_PER_PAGE);
        },
        hasStructuredDetail() {
            return this.strings.length > 0;
        },
        // Catch-all: we know a real test ran (mode/rule_name present) but there's
        // neither a strings array nor a quality hint to show — either an older
        // sparse result (strings_matched was a bare count) or a rule with no
        // strings defined that matched on its condition alone. Either way, don't
        // leave the user with a dead-end "nothing available" message.
        isLegacyResult() {
            if (this.strings.length > 0) return false;
            if (this.qualityHints && this.qualityHints.length) return false;
            return !!this.details.rule_name || this.details.mode === 'batch_execution' || this.details.mode === 'full_execution';
        },
        hasTestInput() {
            return !!(this.testInput && this.testInput.value);
        },
        // Total size of the input the rule was tested against, in bytes.
        inputTotalLength() {
            if (!this.hasTestInput) return 0;
            const { type, value } = this.testInput;
            if (type === 'hex') return value.replace(/\s+/g, '').length / 2;
            if (type === 'file_b64') {
                try { return atob(value).length; } catch (e) { return Math.floor(value.length * 0.75); }
            }
            return value.length;
        },
        // The input, formatted the same way as the matched-string definitions
        // above, so the two are visually comparable.
        formattedInput() {
            if (!this.hasTestInput) return '';
            const { type, value } = this.testInput;
            if (type === 'hex') return this.spacedHex(value.replace(/\s+/g, ''));
            if (type === 'file_b64') return `[binary file — ${this.inputTotalLength} bytes]`;
            return value;
        },
    },
    methods: {
        // Reconstruct the YARA-style definition for this match, e.g.
        // "$s0 = { 31 F7 40 88 7C 04 4C 48 FF C0 }" — the bytes that were
        // actually found at this offset, formatted like the rule source.
        spacedHex(hex) {
            if (!hex) return '';
            return (hex.match(/.{1,2}/g) || []).join(' ').toUpperCase();
        },
        asciiPreview(hex) {
            if (!hex) return '';
            try {
                const bytes = hex.match(/.{1,2}/g) || [];
                return bytes.map(b => {
                    const n = parseInt(b, 16);
                    return n >= 32 && n <= 126 ? String.fromCharCode(n) : '.';
                }).join('');
            } catch (e) { return ''; }
        },
        // Capped variants for the list row — a match can span thousands of
        // bytes, and spelling all of them out per row is what pushes the
        // layout wide when many rows render at once. The full compare view
        // (toggleCompare) still uses the uncapped spacedHex/asciiPreview.
        isTruncated(hex) {
            return !!hex && hex.length / 2 > MAX_PREVIEW_BYTES;
        },
        spacedHexPreview(hex) {
            if (!hex) return '';
            const capped = hex.slice(0, MAX_PREVIEW_BYTES * 2);
            return this.spacedHex(capped) + (this.isTruncated(hex) ? ' …' : '');
        },
        asciiPreviewCapped(hex) {
            if (!hex) return '';
            const capped = hex.slice(0, MAX_PREVIEW_BYTES * 2);
            return this.asciiPreview(capped) + (this.isTruncated(hex) ? '…' : '');
        },
        stringByteLength(s) {
            return s.length != null ? s.length : (s.value_hex ? s.value_hex.length / 2 : 0);
        },
        // What % of the whole input this one matched string accounts for.
        matchPct(s) {
            const total = this.inputTotalLength;
            if (!total) return null;
            return Math.round((this.stringByteLength(s) / total) * 1000) / 10;
        },
        toggleCompare(i) {
            this.openIndex = this.openIndex === i ? null : i;
        },
        stringDef(s) {
            return `${s.identifier} = { ${this.spacedHex(s.value_hex)} }`;
        },
        goToPage(p) {
            this.currentPage = p;
            this.openIndex = null;
        },
    },
    template: `
<div class="rtr-yara-detail">

  <!-- Matched strings — shown as the YARA definition that was found -->
  <div v-if="strings.length" class="mb-1">
    <div style="font-size:.78rem;font-weight:800;text-transform:uppercase;letter-spacing:.05em;color:#0d6efd;margin-bottom:.5rem;">
      <i class="fa-solid fa-magnifying-glass me-1"></i>Matched strings ([[ strings.length ]])
    </div>
    <div class="d-flex flex-column gap-2">
      <div v-for="(s, i) in pagedStrings" :key="i" class="rtr-yara-string">
        <div class="d-flex align-items-start gap-2">
          <code class="rtr-yara-string__def flex-grow-1">[[ s.identifier ]] = { [[ spacedHexPreview(s.value_hex) ]] }</code>
          <button v-if="hasTestInput" type="button" class="rtr-yara-compare-btn"
                  :class="{ 'rtr-yara-compare-btn--active': openIndex === i }"
                  title="Compare with your input" @click="toggleCompare(i)">
            <i class="fa-solid fa-code-compare"></i>
          </button>
        </div>
        <div class="rtr-yara-string__meta">
          <span><i class="fa-solid fa-location-dot me-1"></i>offset [[ s.offset ]]</span>
          <span v-if="s.length != null">[[ s.length ]] byte[[ s.length===1?'':'s' ]]</span>
          <span v-if="asciiPreviewCapped(s.value_hex)" class="rtr-yara-string__ascii">"[[ asciiPreviewCapped(s.value_hex) ]]"</span>
        </div>

        <!-- Side-by-side compare: your input (with this string highlighted in place) vs. the matched pattern -->
        <div v-if="openIndex === i && hasTestInput" class="rtr-yara-compare">
          <div class="rtr-yara-compare__row">
            <div class="rtr-yara-compare__col">
              <div class="rtr-yara-compare__label">Your input — [[ s.identifier ]] highlighted in place</div>
              <code-viewer :code="formattedInput" language="text" :show-lines="false" :word-wrap="true"
                           :extra-highlights="[spacedHex(s.value_hex)]" max-height="180px">
              </code-viewer>
            </div>
            <div class="rtr-yara-compare__col">
              <div class="rtr-yara-compare__label">Matched string</div>
              <code-viewer :code="stringDef(s)" language="text" :show-lines="false" :word-wrap="true" max-height="180px">
              </code-viewer>
            </div>
          </div>
          <div v-if="matchPct(s) !== null" class="rtr-yara-compare__pct">
            <i class="fa-solid fa-chart-pie me-1"></i>
            This string is <strong>[[ matchPct(s) ]]%</strong> of your total input
            ([[ stringByteLength(s) ]] / [[ inputTotalLength ]] bytes)
          </div>
        </div>
      </div>
    </div>
    <pagination-component v-if="totalPages > 1" class="mt-2"
                           :current-page="currentPage" :total-pages="totalPages"
                           @change-page="goToPage">
    </pagination-component>
  </div>

  <!-- Quality hints -->
  <div v-if="qualityHints && qualityHints.length" class="rtr-hints px-0">
    <div v-for="hint in qualityHints" :key="hint" class="rtr-hint-item">
      <i class="fa-solid fa-lightbulb rtr-hint-icon"></i>[[ hint ]]
    </div>
  </div>

  <!-- Legacy / sparse result: matched, but no per-string breakdown to show -->
  <p v-if="isLegacyResult" class="text-muted mb-0" style="font-size:.8rem;">
    <i class="fa-solid fa-circle-info me-1"></i>
    This rule matched, but no per-string breakdown is available — either it defines no strings
    (matched on its condition alone), or this result predates detailed tracking. Re-run the test to check.
  </p>

  <!-- Fallback: nothing at all to show (not even a rule_name/mode) -->
  <p v-else-if="!hasStructuredDetail && (!qualityHints || !qualityHints.length)" class="text-muted mb-0" style="font-size:.8rem;">
    No structured detail available for this result.
  </p>
</div>
`,
};

export default YaraMatchDetail;
