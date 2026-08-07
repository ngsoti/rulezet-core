import { getTextColor, mapIcon } from './utils/galaxie.js';

/**
 * TagInput
 * Searchable tag picker with namespace drill-down.
 * Unified badge style with the rest of the tag system.
 */
const TagInput = {
    props: {
        modelValue: { type: Array, default: () => [] },
        placeholder: { type: String, default: 'Search or select tags…' },
        label: { type: String, default: 'Associated Tags' },
        userId: { type: [Number, String], default: null },
        showNamespace: { type: Boolean, default: true },
        // Caps how many tags this picker holds — e.g. maxTags=1 turns it into
        // a single-tag picker (used by the platform-tag pattern config
        // editor, one tag per pattern row). Picking a new tag once the cap
        // is reached replaces the current selection instead of being a no-op,
        // which is the least surprising behavior for a "pick one" field.
        maxTags: { type: Number, default: null },
    },
    emits: ['update:modelValue'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const searchQuery = Vue.ref('');
        const availableTags = Vue.ref([]);
        const searchResults = Vue.ref([]);
        const isLoading = Vue.ref(false);
        const isSearching = Vue.ref(false);
        const isDropdownOpen = Vue.ref(false);
        const activeType = Vue.ref(null);
        const activeNamespace = Vue.ref(null);
        let searchDebounceTimer = null;
        let searchRequestId = 0;

        // ── label helpers ─────────────────────────────────────────────────────
        function namespaceOf(name) {
            if (!name || !name.includes(':')) return '';
            if (name.startsWith('misp-galaxy:') && name.includes('=')) return name.split(':')[1].split('=')[0];
            return name.split(':')[0];
        }
        function valueOf(name) {
            if (!name) return '';
            const m = name.match(/="(.+)"$/);
            if (m) return m[1];
            if (name.includes(':')) return name.split(':').slice(1).join(':');
            return name;
        }
        // Full-detail label: parses the RAW tag name directly rather than
        // going through namespaceOf() (which deliberately collapses
        // "misp-galaxy:tool=..." to just "tool" for the browse-folder
        // grouping). Previously this dropped the predicate entirely for
        // taxonomy tags (showed "ms-caro-malware-full:Trojan", hiding that
        // it's specifically the "malware-type" predicate) and dropped the
        // "misp-galaxy:" prefix for galaxy tags. This picker is used to build
        // a security-relevant config — the admin needs to see precisely
        // which tag they're about to attach, not an abbreviated guess.
        function tagLabel(name) {
            if (!name) return '';
            if (!props.showNamespace) return valueOf(name);
            const colonIdx = name.indexOf(':');
            if (colonIdx === -1) return name;
            const rawNs = name.slice(0, colonIdx);
            const rest  = name.slice(colonIdx + 1);
            const eqIdx = rest.indexOf('=');
            if (eqIdx === -1) return `${rawNs}:${rest}`;
            const pred = rest.slice(0, eqIdx);
            return `${rawNs}:${pred}=${valueOf(name)}`;
        }

        async function fetchAvailableTags() {
            isLoading.value = true;
            try {
                const params = new URLSearchParams();
                if (props.userId) params.append('user_id', String(props.userId));
                const res = await fetch(`/tags/get_all_tags?${params}`);
                if (res.ok) {
                    const data = await res.json();
                    availableTags.value = Array.isArray(data) ? data : (data.tags || []);
                }
            } catch (e) {
                console.error('TagInput fetch error:', e);
            } finally {
                isLoading.value = false;
            }
        }

        const sortedGroupedTags = Vue.computed(() => {
            const groups = { Public: {}, Private: {} };
            availableTags.value.forEach(tag => {
                const type = tag.visibility === 'public' ? 'Public' : 'Private';
                const ns = namespaceOf(tag.name)?.toUpperCase() || 'OTHER';
                if (!groups[type][ns]) groups[type][ns] = [];
                groups[type][ns].push({ ...tag, displayLabel: tagLabel(tag.name) });
            });
            if (!Object.keys(groups.Private).length) delete groups.Private;
            if (!Object.keys(groups.Public).length) delete groups.Public;
            return groups;
        });

        // Search is server-side (the /tags/get_all_tags `search` + `limit`
        // params already existed but went unused) instead of a client-side
        // .filter() over the full catalog on every keystroke — with the tag
        // count now in the thousands after bulk MISP taxonomy/galaxy imports,
        // that linear scan-per-keystroke was the main source of input lag.
        const SEARCH_DEBOUNCE_MS = 300;
        const SEARCH_LIMIT = 50;

        async function runSearch(q) {
            const myRequestId = ++searchRequestId;
            isSearching.value = true;
            try {
                const params = new URLSearchParams({ search: q, limit: String(SEARCH_LIMIT) });
                if (props.userId) params.append('user_id', String(props.userId));
                const res = await fetch(`/tags/get_all_tags?${params}`);
                if (myRequestId !== searchRequestId) return; // a newer keystroke already superseded this response
                if (res.ok) {
                    const data = await res.json();
                    searchResults.value = data.tags || [];
                }
            } catch (e) {
                console.error('TagInput search error:', e);
            } finally {
                if (myRequestId === searchRequestId) isSearching.value = false;
            }
        }

        const filteredSuggestions = Vue.computed(() => searchResults.value);

        const isTagSelected = (tagId) => props.modelValue.some(t => t.id === tagId);

        function toggleTag(tag) {
            if (isTagSelected(tag.id)) {
                emit('update:modelValue', props.modelValue.filter(t => t.id !== tag.id));
            } else if (props.maxTags != null && props.modelValue.length >= props.maxTags) {
                emit('update:modelValue', [tag]);
            } else {
                emit('update:modelValue', [...props.modelValue, tag]);
            }
        }

        // Explicit chevron button — a dedicated, always-reliable open/close
        // control, instead of relying only on the input's focus event.
        function toggleDropdown() {
            if (!isDropdownOpen.value && availableTags.value.length === 0) fetchAvailableTags();
            isDropdownOpen.value = !isDropdownOpen.value;
        }

        // Focusing the input should only ever OPEN the panel, never close an
        // already-open one — a toggle here misfired shut in some browsers
        // when the input re-gained focus while already open.
        function openDropdown() {
            if (availableTags.value.length === 0) fetchAvailableTags();
            isDropdownOpen.value = true;
        }

        Vue.watch(searchQuery, (val) => {
            clearTimeout(searchDebounceTimer);
            const q = val.trim();
            if (!q) {
                searchRequestId++; // invalidate any in-flight search response
                searchResults.value = [];
                isSearching.value = false;
                return;
            }
            // Typing must always surface the results panel — the "click
            // outside closes it" listener below could otherwise leave the
            // panel closed while the input (still focused) keeps accepting
            // keystrokes, making it look like typing "does nothing".
            isDropdownOpen.value = true;
            activeType.value = null;
            activeNamespace.value = null;
            searchDebounceTimer = setTimeout(() => runSearch(q), SEARCH_DEBOUNCE_MS);
        });

        Vue.onMounted(() => {
            window.addEventListener('click', (e) => {
                if (!e.target.closest('.tag-input-container')) isDropdownOpen.value = false;
            });
        });

        return {
            searchQuery, filteredSuggestions, isLoading, isSearching, isDropdownOpen,
            toggleTag, isTagSelected, toggleDropdown, openDropdown,
            getTextColor, mapIcon, tagLabel,
            sortedGroupedTags, activeType, activeNamespace,
        };
    },
    template: `
        <div class="tag-input-container text-start position-relative">
            <label class="form-label fw-bold text-muted small text-uppercase">[[ label ]]</label>

            <div class="input-group shadow-sm rounded-3 border" style="border-width:2px; background: var(--card-bg-color)">
                <span class="input-group-text border-0" style="background: var(--card-bg-color); cursor:pointer">
                    <i class="fas fa-tags small" style="color: #0d6efd"></i>
                </span>
                <input type="text" v-model="searchQuery" @focus="openDropdown"
                    class="form-control border-0 shadow-none px-2"
                    :placeholder="placeholder"
                    style="height:46px; background: var(--card-bg-color); color: var(--text-color)">
                <div v-if="isLoading || isSearching" class="input-group-text border-0" style="background: var(--card-bg-color)">
                    <div class="spinner-border spinner-border-sm text-primary"></div>
                </div>
                <span role="button" tabindex="0" @click.stop="toggleDropdown" @keydown.enter.stop="toggleDropdown"
                    class="input-group-text border-0" title="Show tag panel"
                    style="background: var(--card-bg-color); cursor:pointer">
                    <i class="fas fa-chevron-down small"
                       :style="{ color: 'var(--subtle-text-color)', transition: 'transform .15s', transform: isDropdownOpen ? 'rotate(180deg)' : 'none' }"></i>
                </span>
            </div>

            <!-- Dropdown -->
            <div v-if="isDropdownOpen" @click.stop
                 class="dropdown-menu show shadow-lg border-0 p-3 w-100 mt-1"
                 style="max-height:450px; overflow-y:auto; z-index:1060; min-width:350px; background: var(--card-bg-color); border-radius:12px;">

                <!-- Search results -->
                <div v-if="searchQuery">
                    <div v-if="isSearching && !filteredSuggestions.length" class="text-center py-4">
                        <div class="spinner-border spinner-border-sm text-primary"></div>
                    </div>
                    <div v-for="tag in filteredSuggestions" :key="tag.id" @click.stop="toggleTag(tag)"
                         class="dropdown-item rounded-2 py-2 d-flex align-items-center justify-content-between cursor-pointer mb-1 border"
                         :class="{ 'border-primary bg-primary-subtle': isTagSelected(tag.id) }"
                         style="cursor:pointer">
                        <span class="tag-split shadow-sm">
                            <span class="tag-left" v-html="mapIcon(tag.icon)"></span>
                            <span class="tag-right" :style="{ backgroundColor: tag.color || '#6c757d' }">
                                <span :style="{ color: getTextColor(tag.color || '#6c757d') }" class="fw-bold">
                                    [[ tagLabel(tag.name) ]]
                                </span>
                            </span>
                        </span>
                        <div class="d-flex align-items-center gap-2">
                            <i v-if="isTagSelected(tag.id)" class="fas fa-check-circle text-primary"></i>
                            <small :class="tag.visibility === 'public' ? 'text-success' : 'text-danger'">
                                <i :class="tag.visibility === 'public' ? 'fas fa-eye' : 'fas fa-eye-slash'"></i>
                            </small>
                        </div>
                    </div>
                    <div v-if="!isSearching && filteredSuggestions.length === 0" class="text-center py-4">
                        <i class="fas fa-search fa-2x mb-2 opacity-25 d-block" style="color: var(--text-color)"></i>
                        <p class="fw-bold small mb-0" style="color: var(--text-color)">No tags found.</p>
                    </div>
                </div>

                <!-- Type level -->
                <div v-else-if="!activeType">
                    <!-- Without this, a slow first fetch left the dropdown looking
                         empty/broken (neither the type rows nor "No tags available"
                         render while isLoading) — looked like clicking just did nothing. -->
                    <div v-if="isLoading" class="text-center py-4">
                        <div class="spinner-border spinner-border-sm text-primary"></div>
                    </div>
                    <template v-else>
                        <div v-for="(namespaces, type) in sortedGroupedTags" :key="type"
                             @click.stop="activeType = type"
                             class="p-2 rounded border d-flex align-items-center justify-content-between mb-2"
                             style="cursor:pointer">
                            <div class="d-flex align-items-center">
                                <i :class="type === 'Public' ? 'fas fa-eye text-success' : 'fas fa-eye-slash text-danger'" class="me-3"></i>
                                <span class="fw-bold" style="color: var(--text-color)">[[ type ]] Tags</span>
                            </div>
                            <i class="fas fa-chevron-right small opacity-50" style="color: var(--text-color)"></i>
                        </div>
                        <div v-if="Object.keys(sortedGroupedTags).length === 0" class="text-center py-3">
                            <p class="text-muted small fw-bold mb-0">No tags available.</p>
                        </div>
                    </template>
                </div>

                <!-- Namespace level -->
                <div v-else-if="!activeNamespace">
                    <button @click.stop="activeType = null" class="btn btn-sm text-primary p-0 fw-bold mb-2">
                        <i class="fas fa-chevron-left me-1"></i>Back
                    </button>
                    <div v-for="(tags, ns) in sortedGroupedTags[activeType]" :key="ns"
                         @click.stop="activeNamespace = ns"
                         class="p-2 rounded border d-flex align-items-center justify-content-between mb-2"
                         style="cursor:pointer">
                        <div class="d-flex align-items-center">
                            <i class="fas fa-folder text-primary opacity-75 me-3"></i>
                            <span class="fw-bold" style="color: var(--text-color)">[[ ns ]]</span>
                        </div>
                        <span class="badge rounded-pill border" style="background: var(--light-bg-color); color: var(--text-color)">[[ tags.length ]]</span>
                    </div>
                </div>

                <!-- Tag level -->
                <div v-else>
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <button @click.stop="activeNamespace = null" class="btn btn-sm text-primary p-0 fw-bold">
                            <i class="fas fa-chevron-left me-1"></i>Back
                        </button>
                        <small class="text-uppercase fw-bold text-muted">[[ activeNamespace ]]</small>
                    </div>
                    <div v-for="tag in sortedGroupedTags[activeType][activeNamespace]" :key="tag.id"
                         @click.stop="toggleTag(tag)"
                         class="dropdown-item rounded border mb-2 p-2 d-flex align-items-center justify-content-between"
                         :class="{ 'border-primary bg-primary-subtle shadow-sm': isTagSelected(tag.id) }"
                         style="cursor:pointer">
                        <span class="tag-split shadow-sm">
                            <span class="tag-left" v-html="mapIcon(tag.icon)"></span>
                            <span class="tag-right" :style="{ backgroundColor: tag.color || '#6c757d' }">
                                <span :style="{ color: getTextColor(tag.color || '#6c757d') }">
                                    [[ tag.displayLabel ]]
                                </span>
                            </span>
                        </span>
                        <i :class="isTagSelected(tag.id) ? 'fas fa-check-circle text-primary' : 'fas fa-plus-circle text-muted'"></i>
                    </div>
                </div>
            </div>

            <!-- Selected tags -->
            <div class="d-flex flex-wrap gap-2 mt-3">
                <span v-for="tag in modelValue" :key="tag.id" class="tag-split shadow-sm">
                    <span class="tag-left" v-html="mapIcon(tag.icon)"></span>
                    <span class="tag-right" :style="{ backgroundColor: tag.color || '#6c757d' }">
                        <span :style="{ color: getTextColor(tag.color || '#6c757d') }" class="fw-bold me-2">
                            [[ tagLabel(tag.name) ]]
                        </span>
                        <i class="fas fa-times-circle" style="cursor:pointer" @click.stop="toggleTag(tag)"></i>
                    </span>
                </span>
            </div>
        </div>
    `
};

export default TagInput;