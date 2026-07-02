import RuleBundleManager from './ruleBundleManager.js';
import BundleRuleSelector from '/static/js/bundle/BundleRuleSelector.js';
import { display_toast, message_list } from '/static/js/toaster.js'

// BundleStructureEditor reads window.vuedraggable / window.Sortable at
// import time (top-level `components: { draggable: window.vuedraggable }`),
// so those UMD libs must be on the page BEFORE the module is evaluated.
// Most pages that embed rule-list (and therefore this export modal) never
// otherwise need the bundle drag-and-drop editor, so we load both lazily —
// only once the user actually reaches the in-modal structure view — instead
// of forcing every host page to include the extra <script> tags.
let _draggableLibsPromise = null;
function _loadScriptOnce(src) {
    return new Promise((resolve, reject) => {
        const existing = document.querySelector(`script[src="${src}"]`);
        if (existing) {
            if (existing.dataset.loaded === 'true') return resolve();
            existing.addEventListener('load', () => resolve());
            existing.addEventListener('error', reject);
            return;
        }
        const s = document.createElement('script');
        s.src = src;
        s.onload = () => { s.dataset.loaded = 'true'; resolve(); };
        s.onerror = reject;
        document.head.appendChild(s);
    });
}
function _loadStylesheetOnce(href) {
    if (document.querySelector(`link[href="${href}"]`)) return;
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = href;
    document.head.appendChild(link);
}
function loadDraggableLibs() {
    // BundleStructureEditor pulls in SmartEditor + CodeViewer (for its file
    // preview/edit panes) plus its own layout — none of that CSS is
    // guaranteed to be on an arbitrary rule-list host page, so load it here.
    _loadStylesheetOnce('/static/css/components/theme-bridge.css');
    _loadStylesheetOnce('/static/css/components/smart-editor.css');
    _loadStylesheetOnce('/static/css/components/code-viewer.css');
    _loadStylesheetOnce('/static/css/components/dataTable.css');
    _loadStylesheetOnce('/static/css/bundle/bundle-editor.css');
    if (window.vuedraggable) return Promise.resolve();
    if (!_draggableLibsPromise) {
        _draggableLibsPromise = _loadScriptOnce('/static/js/bundle/jsdelivr_sortablejs.js')
            .then(() => _loadScriptOnce('/static/js/bundle/jsdelivr_vuedraggable.js'));
    }
    return _draggableLibsPromise;
}
const BundleStructureEditor = Vue.defineAsyncComponent(async () => {
    await loadDraggableLibs();
    const mod = await import('/static/js/bundle/BundleStructureEditor.js');
    return mod.default;
});

const RuleExportAction = {
    components: {
        RuleBundleManager,
        BundleStructureEditor,
        BundleRuleSelector,
    },
    props: {
        totalRules: { type: Number, default: 0 },
        searchQuery: { type: String, default: '' },
        sortBy: { type: String, default: 'newest' },
        searchField: { type: String, default: 'all' },
        ruleType: { type: String, default: '' },
        selectedSources: { type: Array, default: () => [] },
        selectedVulnerabilities: { type: Array, default: () => [] },
        selectedLicenses: { type: Array, default: () => [] },
        selectedTags: { type: Array, default: () => [] },
        userId: { type: Number, default: null },
        authorFilter: { type: String, default: '' },
        csrfToken: { type: String, default: '' },
        currentUserIsAuthenticated: { type: Boolean, default: false },
        // Explicit rule selection — takes precedence over filters when set
        ruleIds: { type: Array, default: null },
        // Hide the trigger button (modal opened programmatically by the host)
        showButton: { type: Boolean, default: true },
        modalId: { type: String, default: 'exportActionModal' },
        // Open modal at a specific view (programmatic trigger from host)
        startView: { type: String, default: 'main' },
    },
    delimiters: ['[[', ']]'],
    setup(props) {
        const MAX_LIMIT = 200;
        const isProcessing = Vue.ref(false);
        const currentView = Vue.ref('main');

        Vue.watch(() => props.startView, v => { if (v) currentView.value = v });
        const csrfToken = Vue.ref(props.csrfToken);
        const hasIdSelection = Vue.computed(() => !!(props.ruleIds && props.ruleIds.length));
        // For the limit check: when specific IDs are selected use that count, else totalRules
        const effectiveCount = Vue.computed(() => hasIdSelection.value ? props.ruleIds.length : props.totalRules);
        const isOverLimit = Vue.computed(() => effectiveCount.value > MAX_LIMIT);
        
        const current_user_is_authenticated = Vue.ref(props.currentUserIsAuthenticated);
       
        const currentFilters = Vue.computed(() => ({
            search: props.searchQuery,
            sort_by: props.sortBy,
            rule_type: props.ruleType,
            sources: props.selectedSources,
            vulnerabilities: props.selectedVulnerabilities,
            licenses: props.selectedLicenses,
            tags: props.selectedTags,
            user_id: props.userId,
            author: props.authorFilter
        }));

        const resetView = () => {
            currentView.value = 'main';
            bundleId.value = null;
            bundleRuleIds.value = new Set();
            pinnedRuleIds.value = null;
            structureReady.value = false;
            alreadyInBundle.value = [];
            alreadyInBundleOpen.value = false;
        };

        const bundleId = Vue.ref(null);
        const handleBundleId = (value) => {
            bundleId.value = value;
        };

        // ── In-modal structure editor ───────────────────────────────────
        // After the rules are added to a (new or existing) bundle, switch
        // the modal to the SAME structure editor used on the "Edit Bundle"
        // page — no navigation away — so the user can immediately drag the
        // newly added rules into folders, create sub-folders, etc.
        const structureEditor = Vue.ref(null);
        const bundleRuleIds   = Vue.ref(new Set());
        // Exact rule ids that matched at the moment "Add to Bundle" was
        // submitted — pins the rule-library panel to that snapshot instead
        // of the whole platform, so it only ever shrinks as rules get added.
        const pinnedRuleIds   = Vue.ref(null);
        const handleRuleIds = (value) => {
            pinnedRuleIds.value = value;
        };
        // Don't mount the rule library until the target bundle's EXISTING
        // structure has loaded — otherwise it fetches with an empty
        // exclude-set and briefly shows/counts rules that are already in
        // the bundle (e.g. it was added to before this session), self-
        // correcting a beat later. Gating the mount avoids that race
        // instead of relying on the correction.
        const structureReady = Vue.ref(false);

        const onBundleCompleted = () => {
            currentView.value = 'structure';
        };

        function onAddRules(rules) {
            if (structureEditor.value) structureEditor.value.addRules(rules);
            const updated = new Set(bundleRuleIds.value);
            rules.forEach(r => updated.add(r.id));
            bundleRuleIds.value = updated;
        }
        function onPreviewRule(rule) {
            if (structureEditor.value) structureEditor.value.setPreview(rule);
        }
        // Rules from the filtered/selected set that turned out to already
        // be in the bundle (e.g. added in an earlier session) — surfaced to
        // the user instead of just silently vanishing from the library.
        // Collapsed (2-line clamp) by default; click to expand the full list.
        const alreadyInBundle = Vue.ref([]);
        const alreadyInBundleOpen = Vue.ref(false);

        async function loadAlreadyInBundleDetails(overlapIds) {
            if (!overlapIds.length) { alreadyInBundle.value = []; return; }
            try {
                const params = new URLSearchParams({ ids: overlapIds.join(','), per_page: overlapIds.length });
                const res = await fetch(`/rule/data_table?${params.toString()}`);
                if (!res.ok) return;
                const data = await res.json();
                alreadyInBundle.value = (data.items || []).map(r => ({ id: r.id, title: r.title }));
            } catch { /* non-critical, just skip the notice */ }
        }

        function _setsEqual(a, b) {
            if (a.size !== b.size) return false;
            for (const x of a) if (!b.has(x)) return false;
            return true;
        }

        // Only replace bundleRuleIds when the content actually changed.
        // tree-ready fires synchronously (instant exclude-set update) right
        // before saveStructure() kicks off; tree-saved then fires again
        // ~100-300ms later once that save round-trips, usually with the
        // exact same ids — without this guard that second, redundant
        // assignment still creates a new Set reference, which re-triggers
        // BundleRuleSelector's exclude-set watcher and fires a second,
        // unnecessary /rule/data_table fetch for no reason.
        function _updateBundleRuleIds(ids) {
            const next = new Set(ids);
            if (!_setsEqual(next, bundleRuleIds.value)) bundleRuleIds.value = next;
        }

        function onTreeReady(ids) {
            _updateBundleRuleIds(ids);
            structureReady.value = true;
            if (pinnedRuleIds.value && pinnedRuleIds.value.length) {
                const existing = new Set(ids);
                loadAlreadyInBundleDetails(pinnedRuleIds.value.filter(id => existing.has(id)));
            }
        }
        function onTreeSaved(ids) { if (ids) _updateBundleRuleIds(ids); }

        // ── Floating window (structure view only) ──────────────────────
        // A plain Bootstrap modal is either small or truly fullscreen; the
        // structure editor wants a large-but-repositionable window that
        // still leaves the rule-list backdrop visible around its edges, and
        // that the user can resize/drag to taste — like a lightweight
        // desktop window rather than a fixed dialog.
        const winMargin = 40; // px of backdrop always left visible on open
        const win = Vue.reactive({ top: 0, left: 0, width: 0, height: 0 });

        function resetWindowGeometry() {
            const vw = window.innerWidth, vh = window.innerHeight;
            win.width  = Math.max(600, vw - winMargin * 2);
            win.height = Math.max(400, vh - winMargin * 2);
            win.left   = (vw - win.width) / 2;
            win.top    = (vh - win.height) / 2;
        }

        let dragState = null;
        function startDrag(ev) {
            if (ev.target.closest('button, a, input, select, textarea')) return;
            dragState = { startX: ev.clientX, startY: ev.clientY, top: win.top, left: win.left };
            document.addEventListener('mousemove', onDrag);
            document.addEventListener('mouseup', stopDrag);
            ev.preventDefault();
        }
        function onDrag(ev) {
            if (!dragState) return;
            const vw = window.innerWidth, vh = window.innerHeight;
            win.left = Math.min(Math.max(0, dragState.left + (ev.clientX - dragState.startX)), vw - 80);
            win.top  = Math.min(Math.max(0, dragState.top + (ev.clientY - dragState.startY)), vh - 40);
        }
        function stopDrag() {
            dragState = null;
            document.removeEventListener('mousemove', onDrag);
            document.removeEventListener('mouseup', stopDrag);
        }

        let resizeState = null;
        function startResize(ev) {
            resizeState = { startX: ev.clientX, startY: ev.clientY, width: win.width, height: win.height };
            document.addEventListener('mousemove', onResize);
            document.addEventListener('mouseup', stopResize);
            ev.preventDefault();
            ev.stopPropagation();
        }
        function onResize(ev) {
            if (!resizeState) return;
            const maxW = window.innerWidth - win.left;
            const maxH = window.innerHeight - win.top;
            win.width  = Math.min(Math.max(480, resizeState.width  + (ev.clientX - resizeState.startX)), maxW);
            win.height = Math.min(Math.max(360, resizeState.height + (ev.clientY - resizeState.startY)), maxH);
        }
        function stopResize() {
            resizeState = null;
            document.removeEventListener('mousemove', onResize);
            document.removeEventListener('mouseup', stopResize);
        }

        Vue.watch(currentView, (v) => {
            if (v === 'structure') Vue.nextTick(resetWindowGeometry);
        });

        // Reset to the main view on close (backdrop / X / Escape), not just
        // the trigger button's own @click, so a stale structure editor
        // doesn't linger for the next time the modal is opened.
        Vue.onMounted(() => {
            const modalEl = document.getElementById(props.modalId);
            if (modalEl) modalEl.addEventListener('hidden.bs.modal', resetView);
        });

        const downloadFormat = async (formatType) => {
            isProcessing.value = true;
            try {
                const params = new URLSearchParams();
                params.append('export_format', formatType);

                if (hasIdSelection.value) {
                    // Explicit selection: export exactly these rules
                    params.append('ids', props.ruleIds.join(','));
                } else {
                params.append('search', props.searchQuery || '');
                params.append('sort_by', props.sortBy);
                params.append('rule_type', props.ruleType || '');
                params.append('author', props.authorFilter || '');

                if (props.userId) params.append('user_id', props.userId);
                if (props.selectedSources.length) params.append('sources', props.selectedSources.join(','));
                if (props.selectedVulnerabilities.length) params.append('vulnerabilities', props.selectedVulnerabilities.join(','));
                if (props.selectedLicenses.length) params.append('licenses', props.selectedLicenses.join(','));
                if (props.selectedTags.length) params.append('tags', props.selectedTags.join(','));
                if (props.searchField) params.append('search_field', props.searchField);
                }

                const response = await fetch(`/rule/export/download?${params.toString()}`);
                if (!response.ok) throw new Error('Export failed');
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `export_${formatType}_${new Date().getTime()}.zip`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
            } catch (error) {
                console.error("Export error:", error);
            } finally {
                isProcessing.value = false;
            }
        };

        return {
            isProcessing,
            currentView,
            resetView,
            downloadFormat,
            isOverLimit,
            MAX_LIMIT,
            effectiveCount,
            currentFilters,
            onBundleCompleted,
            bundleId,
            handleBundleId,
            pinnedRuleIds,
            handleRuleIds,
            structureReady,
            alreadyInBundle,
            alreadyInBundleOpen,
            structureEditor,
            bundleRuleIds,
            win, startDrag, startResize,
            onAddRules,
            onPreviewRule,
            onTreeReady,
            onTreeSaved,
            message_list,
            current_user_is_authenticated,
            hasIdSelection,
            csrfToken,
        };
    },
    template: `
    <div :class="showButton ? 'export-action-container p-3 border-top bg-light-subtle' : ''" :style="showButton ? 'border-radius: 0 0 15px 15px;' : ''">
        <button v-if="showButton"
                class="btn btn-primary shadow-sm px-4 fw-bold rounded-pill"
                data-bs-toggle="modal"
                :data-bs-target="'#' + modalId"
                @click="resetView">
            <i class="fa-solid fa-file-export me-2"></i> Export / Bundle
        </button>

        <teleport to="body">
            <div class="modal fade" :id="modalId" tabindex="-1" aria-hidden="true" style="z-index: 2000;">
                <div :class="currentView === 'structure' ? 'modal-dialog' : 'modal-dialog modal-dialog-centered'"
                     :style="currentView === 'structure'
                        ? ('position:fixed;margin:0;max-width:none;top:' + win.top + 'px;left:' + win.left + 'px;width:' + win.width + 'px;height:' + win.height + 'px;')
                        : ''">
                    <div class="modal-content border-0 shadow-lg d-flex flex-column"
                         :style="currentView === 'structure' ? 'border-radius:16px;height:100%;overflow:hidden;' : 'border-radius: 20px;'">

                        <div class="modal-header border-0 pb-0"
                             :style="currentView === 'structure' ? 'cursor:move;user-select:none;' : ''"
                             @mousedown="currentView === 'structure' && startDrag($event)">
                            <div class="d-flex align-items-center">
                                <button v-if="currentView !== 'main' && currentView !== 'structure'" @click="resetView" class="btn btn-sm btn-light rounded-circle me-2">
                                    <i class="fa-solid fa-arrow-left"></i>
                                </button>
                                <h5 class="modal-title fw-bold">
                                    [[ currentView === 'main' ? 'Export Actions' : (currentView === 'download' ? 'Download Options' : (currentView === 'structure' ? 'Organize Bundle' : 'Bundle Management')) ]]
                                </h5>
                                <i v-if="currentView === 'structure'" class="fa-solid fa-up-down-left-right text-muted ms-2 opacity-50" title="Drag to move" style="font-size:.75rem;"></i>
                            </div>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>

                        <div :class="currentView === 'structure' ? 'modal-body p-3 flex-grow-1' : 'modal-body p-4'"
                             :style="currentView === 'structure' ? 'overflow:auto;' : ''">
                            <div v-if="currentView === 'main'" class="row g-3">
                                <p class="text-muted small mb-2 text-center">
                                    <span v-if="hasIdSelection">
                                        <strong>[[ ruleIds.length ]]</strong> rule(s) selected.
                                    </span>
                                    <span v-else>
                                        Matching <strong>[[ totalRules ]]</strong> rules.
                                    </span>
                                    Choose an action:
                                </p>
                                <div class="col-12">
                                    <div class="p-3 border rounded-4 cursor-pointer transition-all shadow-sm-hover" @click="currentView = 'download'">
                                        <div class="d-flex align-items-center text-start">
                                            <div class="bg-primary-subtle text-primary rounded-circle p-3 me-3">
                                                <i class="fa-solid fa-cloud-arrow-down fa-lg"></i>
                                            </div>
                                            <div class="flex-grow-1">
                                                <h6 class="mb-0 fw-bold">Download Files</h6>
                                                <small class="text-muted">Export rules to your device</small>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <template v-if="current_user_is_authenticated === 'True' && !hasIdSelection">
                                    <div class="col-12">
                                        <div class="p-3 border rounded-4 cursor-pointer transition-all shadow-sm-hover" @click="currentView = 'bundle'">
                                            <div class="d-flex align-items-center text-start">
                                                <div class="bg-success-subtle text-success rounded-circle p-3 me-3">
                                                    <i class="fa-solid fa-box-archive fa-lg"></i>
                                                </div>
                                                <div class="flex-grow-1">
                                                    <h6 class="mb-0 fw-bold">Add to Bundle</h6>
                                                    <small class="text-muted">Save to a new or existing collection</small>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </template>
                            </div>

                            <div v-if="currentView === 'download'" class="row g-3">
                                <p class="text-muted small mb-2">Select your preferred export format:</p>
                                <div class="col-12" v-for="opt in [
                                    {id: 'json_each', icon: 'fa-file-code', color: 'text-warning', title: 'JSON (Individual)', desc: 'Each rule as .json'},
                                    {id: 'ext_each', icon: 'fa-file-lines', color: 'text-info', title: 'Native Extensions', desc: 'Yara (.yar), Sigma (.yaml), etc.'},
                                    {id: 'merged_by_type', icon: 'fa-file-zipper', color: 'text-primary', title: 'Merged by Type', desc: 'One file per format type'}
                                ]" :key="opt.id">
                                    <div class="p-3 border rounded-4 cursor-pointer" @click="downloadFormat(opt.id)">
                                        <div class="d-flex align-items-center text-start">
                                            <i class="fa-solid fa-lg me-3" :class="[opt.icon, opt.color]"></i>
                                            <div>
                                                <h6 class="mb-0 fw-bold small">[[ opt.title ]]</h6>
                                                <small class="text-muted italic">[[ opt.desc ]]</small>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <template v-if="current_user_is_authenticated === 'True'">
                                <div v-if="currentView === 'bundle'">
                                    <rule-bundle-manager
                                        :total-rules="effectiveCount"
                                        :is-over-limit="isOverLimit"
                                        :max-limit="MAX_LIMIT"
                                        :filters="hasIdSelection ? null : currentFilters"
                                        :rule-ids="hasIdSelection ? ruleIds : null"
                                        @processing="(val) => isProcessing = val"
                                        @completed="onBundleCompleted"
                                        :csrf="csrfToken"
                                        @bundle-id="handleBundleId"
                                        @rule-ids="handleRuleIds"
                                    />
                                </div>

                                <!-- Same drag-and-drop structure editor as the "Edit Bundle" page,
                                     embedded in-modal so nothing needs to navigate away. -->
                                <div v-if="currentView === 'structure' && bundleId">
                                    <div v-if="alreadyInBundle.length" class="alert alert-info mb-2 py-2 px-3" style="font-size:.8rem;cursor:pointer;"
                                         @click="alreadyInBundleOpen = !alreadyInBundleOpen">
                                        <div class="d-flex align-items-start gap-2">
                                            <i class="fa-solid fa-circle-info mt-1"></i>
                                            <div class="flex-grow-1" :style="alreadyInBundleOpen ? '' : 'display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;'">
                                                <strong>[[ alreadyInBundle.length ]]</strong> rule[[ alreadyInBundle.length !== 1 ? 's' : '' ]]
                                                from your filter [[ alreadyInBundle.length !== 1 ? 'are' : 'is' ]] already in this bundle
                                                (not shown below, already counted out):
                                                <span class="fw-semibold">[[ alreadyInBundle.map(r => r.title).join(', ') ]]</span>
                                            </div>
                                            <i class="fa-solid ms-1 mt-1" :class="alreadyInBundleOpen ? 'fa-chevron-up' : 'fa-chevron-down'" style="font-size:.7rem;opacity:.6;"></i>
                                        </div>
                                    </div>
                                    <bundle-structure-editor
                                        ref="structureEditor"
                                        :bundle-id="bundleId"
                                        :csrf-token="csrfToken"
                                        @tree-ready="onTreeReady"
                                        @tree-saved="onTreeSaved">

                                        <template #rule-selector>
                                            <bundle-rule-selector v-if="structureReady"
                                                fetch-url="/rule/data_table"
                                                :initial-per-page="12"
                                                :exclude-ids="bundleRuleIds"
                                                :pinned-ids="pinnedRuleIds"
                                                @add-rules="onAddRules"
                                                @preview-rule="onPreviewRule">
                                            </bundle-rule-selector>
                                            <div v-else class="text-center text-muted small py-5">
                                                <div class="spinner-border spinner-border-sm me-2"></div>
                                                Loading bundle contents…
                                            </div>
                                        </template>
                                    </bundle-structure-editor>
                                </div>
                            </template>
                            <div v-if="isProcessing" class="text-center mt-4">
                                <div class="spinner-border spinner-border-sm text-primary me-2"></div>
                                <span class="small text-muted fw-bold">PROCESSING...</span>
                            </div>
                        </div>

                        <div v-if="currentView === 'structure'"
                             class="position-absolute"
                             style="right:2px;bottom:2px;width:16px;height:16px;cursor:nwse-resize;z-index:5;"
                             title="Drag to resize"
                             @mousedown="startResize">
                            <i class="fa-solid fa-up-right-and-down-left-from-center text-muted opacity-50" style="font-size:.7rem;transform:rotate(90deg);"></i>
                        </div>
                    </div>
                </div>
            </div>
        </teleport>
    </div>
    `
};

export default RuleExportAction;