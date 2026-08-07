/**
 * connectorPullFilter.js — Pull modal filter panel
 *
 * Emits `filter` on every change with shape:
 * {
 *   date_from, date_to,
 *   formats: string[],
 *   tags:     { names: string[], mode: "AND"|"OR", exclude: bool }[],
 *   authors:  string[],
 *   licenses: { names: string[], mode: "AND"|"OR", exclude: bool }[],
 *   cves:     { names: string[], mode: "AND"|"OR", exclude: bool }[],
 * }
 */

import { getTextColor, mapIcon } from '/static/js/tags/utils/galaxie.js'

const { ref, computed, onMounted } = Vue

// ── Icon / colour map for known formats (display only) ───────────────────────
const FORMAT_META = {
    yara:     { icon: 'fa-solid fa-shield-halved', color: '#0d6efd' },
    sigma:    { icon: 'fa-solid fa-chart-simple',  color: '#6f42c1' },
    suricata: { icon: 'fa-solid fa-fish',          color: '#fd7e14' },
    zeek:     { icon: 'fa-solid fa-eye',           color: '#20c997' },
    crs:      { icon: 'fa-solid fa-shield',        color: '#dc3545' },
    nova:     { icon: 'fa-solid fa-star',          color: '#ffc107' },
    nse:      { icon: 'fa-solid fa-terminal',      color: '#0dcaf0' },
    wazuh:    { icon: 'fa-solid fa-lock',          color: '#198754' },
    elastic:  { icon: 'fa-solid fa-database',      color: '#e83e8c' },
}
function fmtIcon(name)  { return FORMAT_META[name?.toLowerCase()]?.icon  || 'fa-solid fa-file-code' }
function fmtColor(name) { return FORMAT_META[name?.toLowerCase()]?.color || '#6c757d' }

// ── Tag helpers ───────────────────────────────────────────────────────────────
function namespaceOf(name) {
    if (!name || !name.includes(':')) return ''
    if (name.startsWith('misp-galaxy:') && name.includes('=')) return name.split(':')[1].split('=')[0]
    return name.split(':')[0]
}
function valueOf(name) {
    if (!name) return ''
    const m = name.match(/="(.+)"$/)
    if (m) return m[1]
    if (name.includes(':')) return name.split(':').slice(1).join(':')
    return name
}
// Full detail: parses the RAW name directly (not via namespaceOf(), which
// collapses "misp-galaxy:tool=..." to just "tool" for grouping purposes) so
// every segment — including the predicate ("malware-type") and the
// "misp-galaxy:" prefix — is shown, not silently dropped.
function tagLabel(name) {
    if (!name) return ''
    const colonIdx = name.indexOf(':')
    if (colonIdx === -1) return name
    const rawNs = name.slice(0, colonIdx)
    const rest  = name.slice(colonIdx + 1)
    const eqIdx = rest.indexOf('=')
    if (eqIdx === -1) return `${rawNs}:${rest}`
    const pred = rest.slice(0, eqIdx)
    return `${rawNs}:${pred}=${valueOf(name)}`
}

// ── Generic "add manually" input component ────────────────────────────────────
const ManualInput = {
    name: 'ManualInput',
    delimiters: ['[[', ']]'],
    props: {
        placeholder: { type: String, default: 'Type and press Enter…' },
    },
    emits: ['add'],
    setup(props, { emit }) {
        const val = ref('')
        function submit() {
            const v = val.value.trim()
            if (v) { emit('add', v); val.value = '' }
        }
        return { val, submit }
    },
    template: `
<div class="cpf-manual-wrap">
  <i class="fa-solid fa-keyboard cpf-search-icon" style="color:var(--subtle-text-color);"></i>
  <input type="text" class="cpf-search-input"
         :placeholder="placeholder"
         v-model="val"
         @keyup.enter="submit"
         @keyup.188="submit">
  <button v-if="val.trim()" class="cpf-add-btn" @click="submit" title="Add">
    <i class="fa-solid fa-plus"></i>
  </button>
</div>
`
}

// ─────────────────────────────────────────────────────────────────────────────

export default {
    name: 'ConnectorPullFilter',
    delimiters: ['[[', ']]'],
    components: { ManualInput },
    emits: ['filter'],

    setup(props, { emit }) {

        // ── Formats (dynamic from API) ───────────────────────────────────────
        const allFormats      = ref([])
        const formatsLoading  = ref(false)
        const selectedFormats = ref([])

        async function fetchFormats() {
            formatsLoading.value = true
            try {
                const r = await fetch('/rule/get_rules_formats')
                if (r.ok) allFormats.value = (await r.json()).formats || []
            } catch {}
            finally { formatsLoading.value = false }
        }

        function toggleFormat(name) {
            const i = selectedFormats.value.indexOf(name)
            if (i > -1) selectedFormats.value.splice(i, 1)
            else selectedFormats.value.push(name)
            emitFilter()
        }
        function selectAllFormats() { selectedFormats.value = allFormats.value.map(f => f.name); emitFilter() }
        function clearFormats()     { selectedFormats.value = []; emitFilter() }

        // ── Date ────────────────────────────────────────────────────────────
        const dateFrom = ref('')
        const dateTo   = ref('')

        // ── Tags ────────────────────────────────────────────────────────────
        const allTags      = ref([])
        const tagsLoading  = ref(false)
        const tagSearch    = ref('')
        const selectedTags = ref([])
        const tagMode      = ref('OR')
        const tagExclude   = ref(false)
        const activeTagNs  = ref(null)
        const tagSource    = ref('all')
        const tagManual    = ref('')

        const TAG_SOURCES = [
            { value: 'all',      label: 'All',      icon: 'fa-layer-group', color: '#6c757d' },
            { value: 'Taxonomy', label: 'Taxonomy',  icon: 'fa-list',        color: '#0d6efd' },
            { value: 'Galaxy',   label: 'Galaxy',    icon: 'fa-atom',        color: '#8b5cf6' },
            { value: 'Manual',   label: 'Manual',    icon: 'fa-tag',         color: '#198754' },
        ]

        async function fetchTags() {
            tagsLoading.value = true
            try {
                const r = await fetch('/rule/get_all_tags_usage')
                if (r.ok) allTags.value = (await r.json()).tags || []
            } catch {}
            finally { tagsLoading.value = false }
        }

        const sourcedTags = computed(() => {
            const base = tagSource.value === 'all'
                ? allTags.value
                : allTags.value.filter(t => t.source === tagSource.value)
            if (!tagSearch.value) return base
            const q = tagSearch.value.toLowerCase()
            return base.filter(t => t.name.toLowerCase().includes(q))
        })

        const groupedTags = computed(() => {
            const groups = {}
            sourcedTags.value.forEach(t => {
                const ns = (namespaceOf(t.name) || 'OTHER').toUpperCase()
                if (!groups[ns]) groups[ns] = []
                groups[ns].push(t)
            })
            return groups
        })

        function isTagSelected(name) {
            return selectedTags.value.some(n => n.toLowerCase() === name.toLowerCase())
        }

        function toggleTag(name) {
            const i = selectedTags.value.findIndex(n => n.toLowerCase() === name.toLowerCase())
            if (i > -1) selectedTags.value.splice(i, 1)
            else selectedTags.value.push(name)
            emitFilter()
        }

        function addTagManually(v) {
            if (v && !isTagSelected(v)) { selectedTags.value.push(v); emitFilter() }
        }

        // ── CVEs ────────────────────────────────────────────────────────────
        const allCves      = ref([])
        const cvesLoading  = ref(false)
        const cveSearch    = ref('')
        const selectedCves = ref([])
        const cveMode      = ref('OR')
        const cveExclude   = ref(false)

        async function fetchCves() {
            cvesLoading.value = true
            try {
                const r = await fetch('/rule/get_all_rules_vulnerabilities_usage')
                if (r.ok) allCves.value = (await r.json()).vulnerabilities || []
            } catch {}
            finally { cvesLoading.value = false }
        }

        const filteredCves = computed(() => {
            if (!cveSearch.value) return allCves.value
            const q = cveSearch.value.toLowerCase()
            return allCves.value.filter(v => v.name.toLowerCase().includes(q))
        })

        function toggleCve(name) {
            const i = selectedCves.value.indexOf(name)
            if (i > -1) selectedCves.value.splice(i, 1)
            else selectedCves.value.push(name)
            emitFilter()
        }

        function addCveManually(v) {
            if (v && !selectedCves.value.includes(v)) { selectedCves.value.push(v); emitFilter() }
        }

        // ── ATT&CK techniques ───────────────────────────────────────────────
        const allAttacks      = ref([])
        const attacksLoading  = ref(false)
        const attackSearch    = ref('')
        const selectedAttacks = ref([])

        async function fetchAttacks() {
            attacksLoading.value = true
            try {
                const r = await fetch('/attack/techniques/usage')
                if (r.ok) allAttacks.value = (await r.json()).techniques || []
            } catch {}
            finally { attacksLoading.value = false }
        }

        const filteredAttacks = computed(() => {
            if (!attackSearch.value) return allAttacks.value
            const q = attackSearch.value.toLowerCase()
            return allAttacks.value.filter(t =>
                t.technique_id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
            )
        })

        function toggleAttack(tid) {
            const i = selectedAttacks.value.indexOf(tid)
            if (i > -1) selectedAttacks.value.splice(i, 1)
            else selectedAttacks.value.push(tid)
            emitFilter()
        }

        function addAttackManually(v) {
            const tid = (v || '').trim().toUpperCase()
            if (tid && !selectedAttacks.value.includes(tid)) { selectedAttacks.value.push(tid); emitFilter() }
        }

        // ── Licenses ────────────────────────────────────────────────────────
        const allLicenses      = ref([])
        const licensesLoading  = ref(false)
        const licenseSearch    = ref('')
        const selectedLicenses = ref([])
        const licenseMode      = ref('OR')
        const licenseExclude   = ref(false)

        async function fetchLicenses() {
            licensesLoading.value = true
            try {
                const r = await fetch('/rule/get_rules_licenses_usage')
                if (r.ok) {
                    const d = await r.json()
                    allLicenses.value = Array.isArray(d) ? d : (d.licenses || [])
                }
            } catch {}
            finally { licensesLoading.value = false }
        }

        const filteredLicenses = computed(() => {
            if (!licenseSearch.value) return allLicenses.value
            const q = licenseSearch.value.toLowerCase()
            return allLicenses.value.filter(l => l.name.toLowerCase().includes(q))
        })

        function toggleLicense(name) {
            const i = selectedLicenses.value.indexOf(name)
            if (i > -1) selectedLicenses.value.splice(i, 1)
            else selectedLicenses.value.push(name)
            emitFilter()
        }

        function addLicenseManually(v) {
            if (v && !selectedLicenses.value.includes(v)) { selectedLicenses.value.push(v); emitFilter() }
        }

        // ── Authors ─────────────────────────────────────────────────────────
        const authorList = ref([])

        function addAuthor(v) {
            if (v && !authorList.value.includes(v)) { authorList.value.push(v); emitFilter() }
        }
        function removeAuthor(a) { authorList.value = authorList.value.filter(x => x !== a); emitFilter() }

        // ── Active count ─────────────────────────────────────────────────────
        const activeCount = computed(() => {
            let n = 0
            if (dateFrom.value || dateTo.value)  n++
            if (selectedFormats.value.length)     n++
            if (selectedTags.value.length)        n++
            if (selectedLicenses.value.length)    n++
            if (selectedCves.value.length)        n++
            if (selectedAttacks.value.length)     n++
            if (authorList.value.length)          n++
            return n
        })

        function clearAll() {
            dateFrom.value = ''; dateTo.value = ''
            selectedFormats.value = []; selectedTags.value = []
            selectedLicenses.value = []; selectedCves.value = []
            selectedAttacks.value = []
            authorList.value = []
            tagSearch.value = ''; cveSearch.value = ''; licenseSearch.value = ''; attackSearch.value = ''
            emitFilter()
        }

        // ── Emit ─────────────────────────────────────────────────────────────
        function emitFilter() {
            emit('filter', getFilter())
        }

        function getFilter() {
            return {
                date_from: dateFrom.value || null,
                date_to:   dateTo.value   || null,
                formats:   [...selectedFormats.value],
                tags:      selectedTags.value.length
                    ? [{ names: [...selectedTags.value], mode: tagMode.value, exclude: tagExclude.value }] : [],
                authors:   [...authorList.value],
                licenses:  selectedLicenses.value.length
                    ? [{ names: [...selectedLicenses.value], mode: licenseMode.value, exclude: licenseExclude.value }] : [],
                cves:      selectedCves.value.length
                    ? [{ names: [...selectedCves.value], mode: cveMode.value, exclude: cveExclude.value }] : [],
                attacks:   [...selectedAttacks.value],
            }
        }

        onMounted(() => {
            fetchFormats()
            fetchTags()
            fetchLicenses()
            fetchCves()
            fetchAttacks()
        })

        return {
            // formats
            allFormats, formatsLoading, selectedFormats,
            toggleFormat, selectAllFormats, clearFormats, fmtIcon, fmtColor,
            // date
            dateFrom, dateTo,
            // tags
            allTags, tagsLoading, tagSearch, selectedTags, tagMode, tagExclude,
            activeTagNs, tagSource, TAG_SOURCES, sourcedTags, groupedTags,
            isTagSelected, toggleTag, addTagManually, tagLabel,
            getTextColor, mapIcon,
            // cves
            allCves, cvesLoading, cveSearch, selectedCves, cveMode, cveExclude,
            filteredCves, toggleCve, addCveManually,
            // attacks
            allAttacks, attacksLoading, attackSearch, selectedAttacks,
            filteredAttacks, toggleAttack, addAttackManually,
            // licenses
            allLicenses, licensesLoading, licenseSearch, selectedLicenses,
            licenseMode, licenseExclude, filteredLicenses, toggleLicense, addLicenseManually,
            // authors
            authorList, addAuthor, removeAuthor,
            // meta
            activeCount, clearAll, emitFilter, getFilter,
        }
    },

    template: `
<div class="cpf-root">

  <!-- ── Header ────────────────────────────────────────── -->
  <div class="cpf-header">
    <div class="d-flex align-items-center gap-2">
      <i class="fa-solid fa-sliders text-primary"></i>
      <span class="fw-semibold" style="font-size:.88rem;">Filters</span>
      <span v-if="activeCount > 0" class="badge bg-primary rounded-pill" style="font-size:.65rem;">[[ activeCount ]] active</span>
      <span v-else class="text-muted" style="font-size:.72rem;">— all rules will be synced if empty</span>
    </div>
    <button v-if="activeCount > 0" class="cpf-clear-all" @click="clearAll">
      <i class="fa-solid fa-xmark me-1"></i>Clear all
    </button>
  </div>

  <!-- ── Date range ────────────────────────────────────── -->
  <div class="cpf-section">
    <div class="cpf-section-label">
      <i class="fa-solid fa-calendar-days text-primary"></i> Date range
      <span class="cpf-section-hint">modified on the remote after / before</span>
    </div>
    <div class="d-flex align-items-center gap-2 flex-wrap">
      <div class="cpf-date-field">
        <label class="cpf-date-label">From</label>
        <input type="date" class="cpf-date-input" v-model="dateFrom" @change="emitFilter">
      </div>
      <i class="fa-solid fa-arrow-right" style="font-size:.65rem;color:var(--subtle-text-color);"></i>
      <div class="cpf-date-field">
        <label class="cpf-date-label">Until</label>
        <input type="date" class="cpf-date-input" v-model="dateTo" @change="emitFilter">
      </div>
      <button v-if="dateFrom || dateTo" class="cpf-mini-clear" @click="dateFrom=''; dateTo=''; emitFilter()">
        <i class="fa-solid fa-xmark"></i>
      </button>
    </div>
  </div>

  <!-- ── Format ────────────────────────────────────────── -->
  <div class="cpf-section">
    <div class="cpf-section-label d-flex align-items-center justify-content-between">
      <span><i class="fa-solid fa-file-code text-primary"></i> Format</span>
      <div class="d-flex gap-1">
        <button class="cpf-mini-action" @click="selectAllFormats">All</button>
        <button class="cpf-mini-action" @click="clearFormats">None</button>
      </div>
    </div>
    <div v-if="formatsLoading" class="d-flex align-items-center gap-2 py-1">
      <div class="spinner-border spinner-border-sm text-primary" style="width:14px;height:14px;"></div>
      <span class="text-muted" style="font-size:.78rem;">Loading formats…</span>
    </div>
    <div v-else class="cpf-format-grid">
      <button v-for="f in allFormats" :key="f.name"
              :class="['cpf-format-btn', selectedFormats.includes(f.name) && 'cpf-format-btn--active']"
              @click="toggleFormat(f.name)">
        [[ f.name.toUpperCase() ]]
      </button>
    </div>
  </div>

  <!-- ── Tags ──────────────────────────────────────────── -->
  <div class="cpf-section">
    <div class="cpf-section-label">
      <i class="fa-solid fa-tags text-primary"></i> Tags
    </div>

    <!-- Logic + Include/Exclude -->
    <div class="d-flex align-items-center gap-2 mb-2 flex-wrap">
      <div class="cpf-logic-toggle">
        <button :class="['cpf-logic-btn', tagMode==='OR'  && 'cpf-logic-btn--active']" @click="tagMode='OR';  emitFilter()">OR</button>
        <button :class="['cpf-logic-btn', tagMode==='AND' && 'cpf-logic-btn--active']" @click="tagMode='AND'; emitFilter()">AND</button>
      </div>
      <button :class="['cpf-excl-btn', tagExclude && 'cpf-excl-btn--active']" @click="tagExclude=!tagExclude; emitFilter()">
        <i :class="tagExclude ? 'fa-solid fa-ban' : 'fa-solid fa-check'"></i>
        [[ tagExclude ? 'Exclude' : 'Include' ]]
      </button>
    </div>

    <!-- Selected chips -->
    <div v-if="selectedTags.length" class="cpf-chips mb-2">
      <span v-for="name in selectedTags" :key="name"
            class="cpf-chip" :class="tagExclude && 'cpf-chip--exclude'"
            @click="toggleTag(name)">
        <i class="fa-solid fa-xmark me-1" style="font-size:.6rem;"></i>[[ tagLabel(name) ]]
      </span>
      <span class="cpf-logic-badge">[[ tagMode ]]</span>
    </div>

    <!-- Source chips -->
    <div class="d-flex gap-1 flex-wrap mb-2">
      <button v-for="src in TAG_SOURCES" :key="src.value"
              class="cpf-source-chip"
              :class="tagSource===src.value && 'cpf-source-chip--active'"
              :style="tagSource===src.value ? { background:src.color, borderColor:src.color, color:'#fff' } : {}"
              @click="tagSource=src.value; activeTagNs=null; tagSearch=''">
        <i :class="'fa-solid '+src.icon+' me-1'"></i>[[ src.label ]]
      </button>
    </div>

    <!-- Browser dropdown -->
    <div class="dropdown mb-2">
      <div class="cpf-search-box" data-bs-toggle="dropdown" data-bs-auto-close="outside">
        <i class="fa-solid fa-magnifying-glass cpf-search-icon"></i>
        <input type="text" class="cpf-search-input" placeholder="Browse tags…" v-model="tagSearch" @click.stop>
        <div v-if="tagsLoading" class="spinner-border spinner-border-sm text-primary" style="width:14px;height:14px;flex-shrink:0;"></div>
      </div>
      <div class="dropdown-menu shadow-lg border-0 cpf-dropdown"
           style="min-width:340px;max-height:360px;overflow-y:auto;border-radius:14px;z-index:2000;padding:.75rem;">

        <!-- Search results -->
        <template v-if="tagSearch">
          <div v-for="tag in sourcedTags" :key="tag.name"
               class="cpf-dropdown-item"
               :class="isTagSelected(tag.name) && 'cpf-dropdown-item--selected'"
               @click.stop="toggleTag(tag.name)">
            <span class="tag-split shadow-sm flex-shrink-0">
              <span class="tag-left" v-html="mapIcon(tag.icon)"></span>
              <span class="tag-right" :style="{ backgroundColor: tag.color||'#6c757d' }">
                <span :style="{ color: getTextColor(tag.color||'#6c757d') }" style="font-size:.72rem;">[[ tagLabel(tag.name) ]]</span>
              </span>
            </span>
            <span style="font-size:.68rem;color:var(--subtle-text-color);">[[ tag.usage_count ]]</span>
            <i v-if="isTagSelected(tag.name)" class="fa-solid fa-check text-primary ms-auto" style="font-size:.75rem;"></i>
          </div>
          <!-- "Add manually" option when nothing matches -->
          <div v-if="sourcedTags.length===0"
               class="cpf-dropdown-item cpf-dropdown-item--manual"
               @click.stop="addTagManually(tagSearch); tagSearch=''">
            <i class="fa-solid fa-plus text-primary" style="font-size:.75rem;"></i>
            <span>Add <strong>[[ tagSearch ]]</strong> manually</span>
          </div>
        </template>

        <!-- Namespace browser -->
        <template v-else-if="!activeTagNs">
          <div class="mb-2" style="font-size:.7rem;color:var(--subtle-text-color);text-transform:uppercase;letter-spacing:.05em;">Namespaces</div>
          <div v-for="(tags, ns) in groupedTags" :key="ns" class="cpf-ns-row" @click.stop="activeTagNs=ns">
            <div class="d-flex align-items-center gap-2">
              <i class="fa-solid fa-folder text-primary opacity-75"></i>
              <span class="fw-semibold" style="font-size:.82rem;color:var(--text-color);">[[ ns ]]</span>
              <span v-if="tags.filter(t=>isTagSelected(t.name)).length > 0"
                    class="badge bg-primary rounded-pill" style="font-size:.58rem;">
                [[ tags.filter(t=>isTagSelected(t.name)).length ]]
              </span>
            </div>
            <div class="d-flex align-items-center gap-2">
              <span style="font-size:.72rem;color:var(--subtle-text-color);">[[ tags.length ]]</span>
              <i class="fa-solid fa-chevron-right opacity-40" style="font-size:.65rem;"></i>
            </div>
          </div>
        </template>

        <!-- Tags inside namespace -->
        <template v-else>
          <div class="d-flex align-items-center gap-2 mb-2">
            <button class="btn btn-sm btn-outline-secondary rounded-circle p-0 d-flex align-items-center justify-content-center"
                    style="width:26px;height:26px;" @click.stop="activeTagNs=null">
              <i class="fa-solid fa-arrow-left" style="font-size:.7rem;"></i>
            </button>
            <span class="fw-bold text-primary text-uppercase" style="font-size:.78rem;">[[ activeTagNs ]]</span>
          </div>
          <div v-for="tag in groupedTags[activeTagNs]" :key="tag.name"
               class="cpf-dropdown-item"
               :class="isTagSelected(tag.name) && 'cpf-dropdown-item--selected'"
               @click.stop="toggleTag(tag.name)">
            <span class="tag-split shadow-sm flex-shrink-0">
              <span class="tag-left" v-html="mapIcon(tag.icon)"></span>
              <span class="tag-right" :style="{ backgroundColor: tag.color||'#6c757d' }">
                <span :style="{ color: getTextColor(tag.color||'#6c757d') }" style="font-size:.72rem;">[[ tagLabel(tag.name) ]]</span>
              </span>
            </span>
            <span style="font-size:.68rem;color:var(--subtle-text-color);">[[ tag.usage_count ]]</span>
            <i v-if="isTagSelected(tag.name)" class="fa-solid fa-check text-primary ms-auto" style="font-size:.75rem;"></i>
          </div>
        </template>
      </div>
    </div>

    <!-- Manual input -->
    <manual-input placeholder="Or type a tag name and press Enter… (e.g. tlp:clear)" @add="addTagManually"></manual-input>
  </div>

  <!-- ── CVE / Vulnerabilities ──────────────────────────── -->
  <div class="cpf-section">
    <div class="cpf-section-label">
      <i class="fa-solid fa-shield-virus text-danger"></i> CVE / Vulnerabilities
    </div>
    <div class="d-flex align-items-center gap-2 mb-2 flex-wrap">
      <div class="cpf-logic-toggle">
        <button :class="['cpf-logic-btn', cveMode==='OR'  && 'cpf-logic-btn--active']" @click="cveMode='OR';  emitFilter()">OR</button>
        <button :class="['cpf-logic-btn', cveMode==='AND' && 'cpf-logic-btn--active']" @click="cveMode='AND'; emitFilter()">AND</button>
      </div>
      <button :class="['cpf-excl-btn', cveExclude && 'cpf-excl-btn--active']" @click="cveExclude=!cveExclude; emitFilter()">
        <i :class="cveExclude ? 'fa-solid fa-ban' : 'fa-solid fa-check'"></i>
        [[ cveExclude ? 'Exclude' : 'Include' ]]
      </button>
    </div>
    <div v-if="selectedCves.length" class="cpf-chips mb-2">
      <span v-for="name in selectedCves" :key="name"
            class="cpf-chip cpf-chip--cve" :class="cveExclude && 'cpf-chip--exclude'"
            @click="toggleCve(name)">
        <i class="fa-solid fa-xmark me-1" style="font-size:.6rem;"></i>[[ name ]]
      </span>
      <span class="cpf-logic-badge">[[ cveMode ]]</span>
    </div>
    <!-- Browser dropdown -->
    <div class="dropdown mb-2">
      <div class="cpf-search-box" data-bs-toggle="dropdown" data-bs-auto-close="outside">
        <i class="fa-solid fa-magnifying-glass cpf-search-icon"></i>
        <input type="text" class="cpf-search-input" placeholder="Browse CVEs…" v-model="cveSearch" @click.stop>
        <div v-if="cvesLoading" class="spinner-border spinner-border-sm text-danger" style="width:14px;height:14px;flex-shrink:0;"></div>
      </div>
      <div class="dropdown-menu shadow-lg border-0 cpf-dropdown"
           style="min-width:320px;max-height:280px;overflow-y:auto;border-radius:12px;z-index:2000;padding:.5rem;">
        <div v-if="filteredCves.length===0 && !cvesLoading" class="text-center py-3 text-muted" style="font-size:.8rem;">
          <i class="fa-solid fa-shield-halved d-block mb-1" style="font-size:1.3rem;opacity:.3;"></i>No CVEs found
        </div>
        <div v-for="v in filteredCves" :key="v.name"
             class="cpf-dropdown-item"
             :class="selectedCves.includes(v.name) && 'cpf-dropdown-item--selected'"
             @click.stop="toggleCve(v.name)">
          <i class="fa-solid fa-triangle-exclamation text-danger" style="font-size:.75rem;flex-shrink:0;"></i>
          <span style="font-size:.82rem;">[[ v.name ]]</span>
          <span v-if="v.usage_count" style="font-size:.68rem;color:var(--subtle-text-color);">([[ v.usage_count ]])</span>
          <i v-if="selectedCves.includes(v.name)" class="fa-solid fa-check text-primary ms-auto" style="font-size:.75rem;"></i>
        </div>
        <!-- Manual add when nothing matches -->
        <div v-if="cveSearch && filteredCves.length===0"
             class="cpf-dropdown-item cpf-dropdown-item--manual"
             @click.stop="addCveManually(cveSearch); cveSearch=''">
          <i class="fa-solid fa-plus text-primary" style="font-size:.75rem;"></i>
          <span>Add <strong>[[ cveSearch ]]</strong> manually</span>
        </div>
      </div>
    </div>
    <!-- Manual input -->
    <manual-input placeholder="Or type CVE-2024-…, GHSA-… and press Enter" @add="addCveManually"></manual-input>
  </div>

  <!-- ── ATT&CK Techniques ─────────────────────────────── -->
  <div class="cpf-section">
    <div class="cpf-section-label">
      <i class="fa-solid fa-crosshairs text-warning"></i> ATT&CK Techniques
    </div>
    <div v-if="selectedAttacks.length" class="cpf-chips mb-2">
      <span v-for="tid in selectedAttacks" :key="tid"
            class="cpf-chip"
            @click="toggleAttack(tid)">
        <i class="fa-solid fa-xmark me-1" style="font-size:.6rem;"></i>[[ tid ]]
      </span>
    </div>
    <!-- Browser dropdown -->
    <div class="dropdown mb-2">
      <div class="cpf-search-box" data-bs-toggle="dropdown" data-bs-auto-close="outside">
        <i class="fa-solid fa-magnifying-glass cpf-search-icon"></i>
        <input type="text" class="cpf-search-input" placeholder="Browse techniques…" v-model="attackSearch" @click.stop>
        <div v-if="attacksLoading" class="spinner-border spinner-border-sm text-warning" style="width:14px;height:14px;flex-shrink:0;"></div>
      </div>
      <div class="dropdown-menu shadow-lg border-0 cpf-dropdown"
           style="min-width:340px;max-height:280px;overflow-y:auto;border-radius:12px;z-index:2000;padding:.5rem;">
        <div v-if="filteredAttacks.length===0 && !attacksLoading" class="text-center py-3 text-muted" style="font-size:.8rem;">
          <i class="fa-solid fa-crosshairs d-block mb-1" style="font-size:1.3rem;opacity:.3;"></i>No techniques found
        </div>
        <div v-for="t in filteredAttacks" :key="t.technique_id"
             class="cpf-dropdown-item"
             :class="selectedAttacks.includes(t.technique_id) && 'cpf-dropdown-item--selected'"
             @click.stop="toggleAttack(t.technique_id)">
          <code class="text-warning" style="font-size:.72rem;flex-shrink:0;">[[ t.technique_id ]]</code>
          <span style="font-size:.82rem;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">[[ t.name ]]</span>
          <span v-if="t.count" style="font-size:.68rem;color:var(--subtle-text-color);flex-shrink:0;">([[ t.count ]])</span>
          <i v-if="selectedAttacks.includes(t.technique_id)" class="fa-solid fa-check text-primary ms-auto" style="font-size:.75rem;flex-shrink:0;"></i>
        </div>
        <div v-if="attackSearch && filteredAttacks.length===0"
             class="cpf-dropdown-item cpf-dropdown-item--manual"
             @click.stop="addAttackManually(attackSearch); attackSearch=''">
          <i class="fa-solid fa-plus text-primary" style="font-size:.75rem;"></i>
          <span>Add <strong>[[ attackSearch.toUpperCase() ]]</strong> manually</span>
        </div>
      </div>
    </div>
    <!-- Manual input -->
    <manual-input placeholder="Or type T1071, T1059.001… and press Enter" @add="addAttackManually"></manual-input>
  </div>

  <!-- ── Licenses ───────────────────────────────────────── -->
  <div class="cpf-section">
    <div class="cpf-section-label">
      <i class="fa-solid fa-scale-balanced text-info"></i> Licenses
    </div>
    <div class="d-flex align-items-center gap-2 mb-2 flex-wrap">
      <div class="cpf-logic-toggle">
        <button :class="['cpf-logic-btn', licenseMode==='OR'  && 'cpf-logic-btn--active']" @click="licenseMode='OR';  emitFilter()">OR</button>
        <button :class="['cpf-logic-btn', licenseMode==='AND' && 'cpf-logic-btn--active']" @click="licenseMode='AND'; emitFilter()">AND</button>
      </div>
      <button :class="['cpf-excl-btn', licenseExclude && 'cpf-excl-btn--active']" @click="licenseExclude=!licenseExclude; emitFilter()">
        <i :class="licenseExclude ? 'fa-solid fa-ban' : 'fa-solid fa-check'"></i>
        [[ licenseExclude ? 'Exclude' : 'Include' ]]
      </button>
    </div>
    <div v-if="selectedLicenses.length" class="cpf-chips mb-2">
      <span v-for="name in selectedLicenses" :key="name"
            class="cpf-chip cpf-chip--license" :class="licenseExclude && 'cpf-chip--exclude'"
            @click="toggleLicense(name)">
        <i class="fa-solid fa-xmark me-1" style="font-size:.6rem;"></i>[[ name ]]
      </span>
      <span class="cpf-logic-badge">[[ licenseMode ]]</span>
    </div>
    <!-- Browser dropdown -->
    <div class="dropdown mb-2">
      <div class="cpf-search-box" data-bs-toggle="dropdown" data-bs-auto-close="outside">
        <i class="fa-solid fa-magnifying-glass cpf-search-icon"></i>
        <input type="text" class="cpf-search-input" placeholder="Browse licenses…" v-model="licenseSearch" @click.stop>
        <div v-if="licensesLoading" class="spinner-border spinner-border-sm text-info" style="width:14px;height:14px;flex-shrink:0;"></div>
      </div>
      <div class="dropdown-menu shadow-lg border-0 cpf-dropdown"
           style="min-width:320px;max-height:280px;overflow-y:auto;border-radius:12px;z-index:2000;padding:.5rem;">
        <div v-if="filteredLicenses.length===0 && !licensesLoading" class="text-center py-3 text-muted" style="font-size:.8rem;">
          <i class="fa-solid fa-file-circle-question d-block mb-1" style="font-size:1.3rem;opacity:.3;"></i>No licenses found
        </div>
        <div v-for="l in filteredLicenses" :key="l.name"
             class="cpf-dropdown-item"
             :class="selectedLicenses.includes(l.name) && 'cpf-dropdown-item--selected'"
             @click.stop="toggleLicense(l.name)">
          <i class="fa-solid fa-scale-balanced text-info" style="font-size:.75rem;flex-shrink:0;"></i>
          <span style="font-size:.82rem;">[[ l.name ]]</span>
          <span v-if="l.count||l.usage_count" style="font-size:.68rem;color:var(--subtle-text-color);">([[ l.count||l.usage_count ]])</span>
          <i v-if="selectedLicenses.includes(l.name)" class="fa-solid fa-check text-primary ms-auto" style="font-size:.75rem;"></i>
        </div>
        <!-- Manual add when nothing matches -->
        <div v-if="licenseSearch && filteredLicenses.length===0"
             class="cpf-dropdown-item cpf-dropdown-item--manual"
             @click.stop="addLicenseManually(licenseSearch); licenseSearch=''">
          <i class="fa-solid fa-plus text-primary" style="font-size:.75rem;"></i>
          <span>Add <strong>[[ licenseSearch ]]</strong> manually</span>
        </div>
      </div>
    </div>
    <!-- Manual input -->
    <manual-input placeholder="Or type MIT, Apache-2.0, GPL-3.0… and press Enter" @add="addLicenseManually"></manual-input>
  </div>

  <!-- ── Authors ────────────────────────────────────────── -->
  <div class="cpf-section">
    <div class="cpf-section-label">
      <i class="fa-solid fa-user-pen text-secondary"></i> Authors
      <span class="cpf-section-hint">press Enter or comma to add</span>
    </div>
    <div v-if="authorList.length" class="cpf-chips mb-2">
      <span v-for="a in authorList" :key="a" class="cpf-chip cpf-chip--author" @click="removeAuthor(a)">
        <i class="fa-solid fa-xmark me-1" style="font-size:.6rem;"></i>[[ a ]]
      </span>
    </div>
    <manual-input placeholder="elastic, florian, @sigma-rules…" @add="addAuthor"></manual-input>
  </div>

</div>
`
}
