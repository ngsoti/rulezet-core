import TagBadge from './TagBadge.js';
import { mapIcon, getTextColor } from '../utils/galaxie.js';


function familyOf(tag) {
    if (!tag || !tag.name || !tag.name.includes(':')) return null;
    if (tag.name.startsWith('misp-galaxy:') && tag.name.includes('=')) {
        return tag.name.split('=')[0];
    }
    return tag.name.split(':')[0];
}

function familyLabel(family) {
    if (!family) return '—';
    if (family.startsWith('misp-galaxy:')) return family.split(':')[1];
    return family;
}

function sourceColor(source) {
    if (source === 'Galaxy') return '#9b7ede';
    if (source === 'Taxonomy') return '#0d6efd';
    return '#198754';
}

function sourceIconClass(source) {
    if (source === 'Galaxy') return 'fas fa-atom';
    if (source === 'Taxonomy') return 'fas fa-list';
    return 'fas fa-tag';
}


// ─── ColPicker ────────────────────────────────────────────────────────────────

const COLUMNS = [
    { key: 'family', label: 'Family' },
    { key: 'description', label: 'Description' },
    { key: 'visibility', label: 'Visibility' },
    { key: 'status', label: 'Status' },
    { key: 'usage', label: 'Usage' },
];

const ColPicker = {
    props: {
        cols: { type: Array, required: true },
        visible: { type: Object, required: true },
    },
    emits: ['toggle', 'show-all', 'hide-all'],
    setup() {
        const { ref } = Vue;
        const open = ref(false);
        const btnRef = ref(null);
        const menuRef = ref(null);
        const menuStyle = ref({});

        function toggle() {
            open.value = !open.value;
            if (open.value && btnRef.value) {
                const rect = btnRef.value.getBoundingClientRect();
                menuStyle.value = {
                    position: 'fixed',
                    top: (rect.bottom + 4) + 'px',
                    right: (window.innerWidth - rect.right) + 'px',
                    minWidth: '155px',
                    zIndex: 9999,
                    background: 'var(--card-bg-color, #fff)',
                };
            }
        }

        function onClickOutside(e) {
            if (
                btnRef.value && !btnRef.value.contains(e.target) &&
                menuRef.value && !menuRef.value.contains(e.target)
            ) {
                open.value = false;
            }
        }

        Vue.onMounted(() => document.addEventListener('click', onClickOutside));
        Vue.onUnmounted(() => document.removeEventListener('click', onClickOutside));

        return { open, btnRef, menuRef, menuStyle, toggle };
    },
    template: `
    <div class="col-picker-wrapper d-inline-block" @click.stop>
        <button ref="btnRef" class="btn btn-xs btn-outline-secondary"
                @click="toggle"
                title="Show / hide columns"
                style="font-size:0.7rem; padding:2px 6px">
            <i class="fas fa-columns"></i>
        </button>
        <teleport to="body">
            <div v-if="open"
                 ref="menuRef"
                 class="shadow rounded-3 border p-2"
                 :style="menuStyle">
                <div class="d-flex justify-content-between align-items-center mb-2 px-1">
                    <button class="btn btn-xs btn-link p-0 text-primary text-decoration-none fw-bold"
                            style="font-size:0.75rem" @click="$emit('show-all')">All</button>
                    <span class="text-muted" style="font-size:0.72rem">Columns</span>
                    <button class="btn btn-xs btn-link p-0 text-secondary text-decoration-none fw-bold"
                            style="font-size:0.75rem" @click="$emit('hide-all')">None</button>
                </div>
                <label v-for="col in cols" :key="col.key"
                       class="d-flex align-items-center gap-2 px-1 py-1 rounded"
                       style="cursor:pointer; font-size:0.82rem; color: var(--text-color)">
                    <input type="checkbox" class="form-check-input m-0"
                           :checked="visible[col.key]"
                           @change="$emit('toggle', col.key)">
                    {{ col.label }}
                </label>
            </div>
        </teleport>
    </div>
`};

// ─── TagRow ───────────────────────────────────────────────────────────────────

const TagRow = {
    props: {
        tag: { type: Object, required: true },
        selected: { type: Boolean, default: false },
        csrfToken: { type: String, required: true },
        showNamespace: { type: Boolean, default: true },
        visibleCols: { type: Object, required: true },
    },
    emits: ['toggle-select', 'view-family', 'toggle-visibility', 'toggle-status', 'delete', 'refresh', 'notify'],
    components: { TagBadge },
    setup(props, { emit }) {
        const { ref, computed } = Vue;
        const editDraft = ref(null);
        const detailOpen = ref(false);
        const deleteOpen = ref(false);
        const editOpen = ref(false);

        const tagFamily = computed(() => familyOf(props.tag));

        function openEdit() {
            editDraft.value = { ...props.tag };
            editOpen.value = true;
        }

        async function saveEdit() {
            const tag = editDraft.value;
            const res = await fetch(`/tags/edit_tag/${tag.id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                body: JSON.stringify({
                    name: tag.name, description: tag.description,
                    color: tag.color, icon: tag.icon, external_id: tag.external_id,
                })
            });
            const data = await res.json();
            emit('notify', data.message, res.ok ? 'success-subtle' : 'danger-subtle');
            if (res.ok) { editOpen.value = false; emit('refresh'); }
        }

        function highlightJson(obj) {
            if (!obj) return '';
            const json = JSON.stringify(obj, null, 2)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            return json
                .replace(/("(?:\\.|[^"\\])*")(\s*:)/g, '<span style="color:#0d6efd">$1</span>$2')
                .replace(/:\s*("(?:\\.|[^"\\])*")/g, ': <span style="color:#198754">$1</span>')
                .replace(/:\s*(true|false|null)/g, ': <span style="color:#dc3545">$1</span>')
                .replace(/:\s*(-?\d+\.?\d*)/g, ': <span style="color:#fd7e14">$1</span>');
        }

        return {
            editDraft, detailOpen, deleteOpen, editOpen,
            tagFamily, familyLabel, sourceColor, sourceIconClass,
            openEdit, saveEdit, highlightJson,
        };
    },
    template: `
        <tr :class="{ 'table-active': selected }">
            <td>
                <input type="checkbox" class="form-check-input"
                       :checked="selected" @change="$emit('toggle-select')">
            </td>
            <td><tag-badge :tag="tag" :show-namespace="showNamespace"></tag-badge></td>

            <td v-if="visibleCols.family">
                <button v-if="tagFamily"
                        class="btn btn-xs btn-outline-secondary family-chip"
                        @click="$emit('view-family')"
                        :title="'Browse all tags in family: ' + tagFamily">
                    <i class="fas fa-folder me-1"></i>{{ familyLabel(tagFamily) }}
                </button>
                <span v-else class="text-muted small">—</span>
            </td>

            <td v-if="visibleCols.description"
                class="text-muted small text-truncate" style="max-width:200px"
                :title="tag.description">
                {{ tag.description || '—' }}
            </td>

            <td v-if="visibleCols.visibility">
                <button class="btn btn-xs rounded-pill"
                        :class="tag.visibility === 'public' ? 'btn-primary' : 'btn-outline-secondary'"
                        @click="$emit('toggle-visibility')">
                    <i :class="tag.visibility === 'public' ? 'fas fa-eye me-1' : 'fas fa-eye-slash me-1'"></i>
                    {{ tag.visibility }}
                </button>
            </td>

            <td v-if="visibleCols.status">
                <button class="btn btn-xs rounded-pill"
                        :class="tag.is_active ? 'btn-success' : 'btn-danger'"
                        @click="$emit('toggle-status')">
                    <i :class="tag.is_active ? 'fas fa-check me-1' : 'fas fa-ban me-1'"></i>
                    {{ tag.is_active ? 'Active' : 'Inactive' }}
                </button>
            </td>

            <td v-if="visibleCols.usage">
                <div class="d-flex gap-1">
                    <a v-if="tag.rule_count > 0" :href="'/rule/rules_list?tags=' + encodeURIComponent(tag.name)"
                        class="badge rounded-pill bg-light border text-dark text-decoration-none"
                        :title="tag.rule_count + ' rule(s) — click to view'"
                       >
                        <i class="fas fa-shield-alt me-1 text-primary" style="font-size:0.65rem"></i>{{ tag.rule_count }}
                    </a>
                    <a v-if="tag.bundle_count > 0"
                        :href="'/bundle/list?tags=' + encodeURIComponent(tag.name)"
                        class="badge rounded-pill bg-light border text-dark text-decoration-none"
                        :title="tag.bundle_count + ' bundle(s) — click to view'"
                       >
                        <i class="fas fa-box me-1 text-warning" style="font-size:0.65rem"></i>{{ tag.bundle_count }}
                    </a>
                    
                    <span v-if="!tag.rule_count && !tag.bundle_count" class="text-muted small">—</span>
                </div>
            </td>

            <td class="text-end">
                <div class="d-inline-flex gap-1">
                    <button class="btn btn-xs btn-outline-secondary icon-btn" @click="openEdit" title="Edit">
                        <i class="fas fa-pen"></i>
                    </button>
                    <button class="btn btn-xs btn-outline-secondary icon-btn" @click="detailOpen = true" title="Details">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-xs btn-outline-danger icon-btn" @click="deleteOpen = true" title="Delete">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        </tr>

        <teleport to="body">

            <!-- Edit Modal -->
            <div v-if="editOpen" class="modal fade show d-block" tabindex="-1"
                 @click.self="editOpen=false" style="background:rgba(0,0,0,0.5)">
                <div class="modal-dialog modal-dialog-centered modal-lg">
                    <div class="modal-content border-0 shadow rounded-4" style="background: var(--card-bg-color)">
                        <div class="modal-header border-0 pb-0">
                            <h5 class="modal-title fw-bold">
                                <i class="fas fa-pen me-2 text-primary"></i>Edit Tag
                            </h5>
                            <button class="btn-close" @click="editOpen=false"></button>
                        </div>
                        <div class="modal-body" v-if="editDraft">
                            <div class="row g-3">
                                <div class="col-md-8">
                                    <label class="form-label small fw-semibold">Name</label>
                                    <input type="text" class="form-control" v-model="editDraft.name">
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label small fw-semibold">Color</label>
                                    <div class="d-flex gap-2 align-items-center">
                                        <input type="color" class="form-control form-control-color"
                                               v-model="editDraft.color" style="width:48px">
                                        <input type="text" class="form-control form-control-sm font-monospace"
                                               v-model="editDraft.color" placeholder="#FFFFFF">
                                    </div>
                                </div>
                                <div class="col-12">
                                    <label class="form-label small fw-semibold">Description</label>
                                    <textarea class="form-control" rows="2" v-model="editDraft.description"></textarea>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label small fw-semibold">Icon (FontAwesome)</label>
                                    <div class="input-group input-group-sm">
                                        <span class="input-group-text">
                                            <i :class="'fa ' + (editDraft.icon || 'fa-tag')"></i>
                                        </span>
                                        <input type="text" class="form-control"
                                               v-model="editDraft.icon" placeholder="bug, shield-alt, ...">
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label small fw-semibold">External UUID</label>
                                    <input type="text" class="form-control form-control-sm font-monospace"
                                           v-model="editDraft.external_id" placeholder="Optional">
                                </div>
                                <div class="col-12">
                                    <div class="rounded-3 p-2 small text-muted"
                                         style="background: var(--light-bg-color)">
                                        UUID: {{ tag.uuid }} · Created by {{ tag.created_by_user_name || 'Unknown' }} · {{ tag.created_at }}
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer border-0 pt-0">
                            <button class="btn btn-sm btn-light rounded-pill px-4" @click="editOpen=false">Cancel</button>
                            <button class="btn btn-sm btn-primary rounded-pill px-4" @click="saveEdit">
                                <i class="fas fa-save me-1"></i>Save
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Detail Modal -->
            <div v-if="detailOpen" class="modal fade show d-block" tabindex="-1"
                 @click.self="detailOpen=false" style="background:rgba(0,0,0,0.5)">
                <div class="modal-dialog modal-dialog-centered modal-lg">
                    <div class="modal-content border-0 shadow-lg rounded-4 overflow-hidden"
                         style="background: var(--card-bg-color)">
                        <div class="position-relative px-4 pt-4 pb-3"
                             :style="{
                                 background: 'linear-gradient(135deg, ' + sourceColor(tag.source) + '15, ' + sourceColor(tag.source) + '05)',
                                 borderBottom: '1px solid var(--border-color)'
                             }">
                            <button class="btn-close position-absolute" style="top:1rem; right:1rem;"
                                    @click="detailOpen=false"></button>
                            <div class="d-flex align-items-center gap-3">
                                <div class="d-flex align-items-center justify-content-center flex-shrink-0 shadow-sm"
                                     :style="{
                                         background: tag.color || sourceColor(tag.source),
                                         width:'64px', height:'64px',
                                         borderRadius:'16px', color:'#fff', fontSize:'1.6rem'
                                     }">
                                    <i :class="'fa ' + (tag.icon ? (tag.icon.startsWith('fa-') ? tag.icon : 'fa-' + tag.icon) : 'fa-tag')"></i>
                                </div>
                                <div class="flex-grow-1 min-w-0">
                                    <div class="d-flex align-items-center gap-2 mb-1 flex-wrap">
                                        <span class="badge rounded-pill px-2 py-1"
                                              :style="{ background: sourceColor(tag.source), color: '#fff' }">
                                            <i :class="sourceIconClass(tag.source) + ' me-1'"></i>{{ tag.source || 'Manual' }}
                                        </span>
                                        <span class="badge rounded-pill"
                                              :class="tag.is_active ? 'bg-success-subtle text-success' : 'bg-danger-subtle text-danger'">
                                            <i :class="tag.is_active ? 'fas fa-check me-1' : 'fas fa-ban me-1'"></i>
                                            {{ tag.is_active ? 'Active' : 'Inactive' }}
                                        </span>
                                        <span class="badge rounded-pill"
                                              :class="tag.visibility === 'public' ? 'bg-primary-subtle text-primary' : 'bg-secondary-subtle text-secondary'">
                                            <i :class="tag.visibility === 'public' ? 'fas fa-eye me-1' : 'fas fa-eye-slash me-1'"></i>
                                            {{ tag.visibility }}
                                        </span>

                                         <a v-if="tag.rule_count > 0"
                                            :href="'/rule/rules_list?tags=' + encodeURIComponent(tag.name)"
                                            class="badge rounded-pill bg-light border text-dark text-decoration-none"
                                            :title="tag.rule_count + ' rule(s) — click to view'"
                                          >
                                            <i class="fas fa-shield-alt me-1 text-primary" style="font-size:0.65rem"></i>{{ tag.rule_count }}
                                        </a>
                                        <a v-if="tag.bundle_count > 0"
                                            :href="'/bundle/list?tags=' + encodeURIComponent(tag.name)"
                                            class="badge rounded-pill bg-light border text-dark text-decoration-none"
                                            :title="tag.bundle_count + ' bundle(s) — click to view'"
                                            >
                                            <i class="fas fa-box me-1 text-warning" style="font-size:0.65rem"></i>{{ tag.bundle_count }}
                                        </a>
                                        
                                    </div>
                                    <h5 class="mb-0 fw-bold font-monospace text-break" style="color: var(--text-color)">
                                        {{ tag.name }}
                                    </h5>
                                </div>
                            </div>
                        </div>
                        <div class="p-4">
                            <div class="mb-4">
                                <label class="text-uppercase fw-semibold small mb-2"
                                       style="color: var(--subtle-text-color); letter-spacing:0.05em; font-size:0.7rem">
                                    <i class="fas fa-align-left me-1"></i>Description
                                </label>
                                <p class="mb-0" style="color: var(--text-color); line-height:1.6">
                                    {{ tag.description || 'No description provided.' }}
                                </p>
                            </div>
                            <table class="detail-table mb-4">
                                <tbody>
                                    <tr>
                                        <th><i class="fas fa-fingerprint me-2"></i>UUID</th>
                                        <td><code class="font-monospace small">{{ tag.uuid }}</code></td>
                                    </tr>
                                    <tr>
                                        <th><i class="fas fa-link me-2"></i>External ID</th>
                                        <td>
                                            <code v-if="tag.external_id" class="font-monospace small">{{ tag.external_id }}</code>
                                            <span v-else class="text-muted small">—</span>
                                        </td>
                                    </tr>
                                    <tr>
                                        <th><i class="fas fa-user me-2"></i>Created by</th>
                                        <td>
                                            <a :href="'/account/detail_user/' + tag.created_by_user_id"
                                               class="fw-semibold text-decoration-none">
                                                {{ tag.created_by_user_name || 'Unknown' }}
                                            </a>
                                        </td>
                                    </tr>
                                    <tr>
                                        <th><i class="fas fa-clock me-2"></i>Created at</th>
                                        <td><strong class="small">{{ tag.created_at }}</strong></td>
                                    </tr>
                                    <tr v-if="tag.updated_at && tag.updated_at !== tag.created_at">
                                        <th><i class="fas fa-pen me-2"></i>Updated at</th>
                                        <td><strong class="small">{{ tag.updated_at }}</strong></td>
                                    </tr>
                                </tbody>
                            </table>
                            <template v-if="tag.galaxy_meta">
                                <label class="text-uppercase fw-semibold small mb-2 d-block"
                                       style="color: var(--subtle-text-color); letter-spacing:0.05em; font-size:0.7rem">
                                    <i class="fas fa-database me-1"></i>Galaxy Metadata
                                </label>
                                <div class="rounded-3 border p-3 font-monospace"
                                     style="background: var(--code-bg-color, #1e1e1e); color: var(--text-color);
                                            max-height:240px; overflow:auto; font-size:0.78rem; line-height:1.5;">
                                    <pre style="margin:0; white-space:pre-wrap; word-break:break-word;"
                                         v-html="highlightJson(tag.galaxy_meta)"></pre>
                                </div>
                            </template>
                            <div v-if="tagFamily" class="mt-4 pt-3 border-top">
                                <button class="btn btn-sm btn-outline-primary rounded-pill px-3"
                                        @click="$emit('view-family'); detailOpen=false">
                                    <i class="fas fa-folder-open me-1"></i>
                                    Browse all tags in <strong>{{ familyLabel(tagFamily) }}</strong>
                                </button>
                            </div>
                        </div>
                        <div class="modal-footer border-0 pt-0 px-4 pb-3">
                            <button class="btn btn-sm btn-outline-secondary rounded-pill px-4"
                                    @click="detailOpen=false">Close</button>
                            <button class="btn btn-sm btn-primary rounded-pill px-4"
                                    @click="detailOpen=false; openEdit()">
                                <i class="fas fa-pen me-1"></i>Edit
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Delete Modal -->
            <div v-if="deleteOpen" class="modal fade show d-block" tabindex="-1"
                 @click.self="deleteOpen=false" style="background:rgba(0,0,0,0.5)">
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content border-0 shadow rounded-4" style="background: var(--card-bg-color)">
                        <div class="modal-header border-0">
                            <h5 class="modal-title fw-bold text-danger">
                                <i class="fas fa-exclamation-triangle me-2"></i>Delete tag?
                            </h5>
                            <button class="btn-close" @click="deleteOpen=false"></button>
                        </div>
                        <div class="modal-body text-center py-3">
                            <p class="mb-1">Are you sure you want to permanently delete
                                <strong class="font-monospace">{{ tag.name }}</strong>?
                            </p>
                            <small class="text-muted">This action cannot be undone. Consider deactivating instead.</small>
                        </div>
                        <div class="modal-footer border-0">
                            <button class="btn btn-sm btn-light rounded-pill px-4"
                                    @click="deleteOpen=false">Cancel</button>
                            <button class="btn btn-sm btn-danger rounded-pill px-4"
                                    @click="$emit('delete'); deleteOpen=false">
                                <i class="fas fa-trash me-1"></i>Delete
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </teleport>
    `
};


// ─── TagTable ─────────────────────────────────────────────────────────────────

const TagTable = {
    components: { 'tag-row': TagRow, 'col-picker': ColPicker },
    props: {
        tags: { type: Array, required: true },
        groupedTags: { type: Object, default: null },
        showGrouped: { type: Boolean, default: true },
        selected: { type: Array, default: () => [] },
        csrfToken: { type: String, required: true },
        loading: { type: Boolean, default: false },
        showNamespace: { type: Boolean, default: true },
    },
    emits: ['toggle-select', 'toggle-all', 'refresh', 'view-family', 'notify'],
    setup(props, { emit }) {
        const { reactive } = Vue;

        // ── column visibility (all on by default) ──────────────────────────────
        const visibleCols = reactive(
            Object.fromEntries(COLUMNS.map(c => [c.key, true]))
        );

        function toggleCol(key) { visibleCols[key] = !visibleCols[key]; }
        function showAll() { COLUMNS.forEach(c => { visibleCols[c.key] = true; }); }
        function hideAll() { COLUMNS.forEach(c => { visibleCols[c.key] = false; }); }

        function isSelected(id) { return props.selected.includes(id); }

        function sourceIcon(source) {
            if (source === 'Galaxy') return 'fas fa-atom text-purple';
            if (source === 'Taxonomy') return 'fas fa-list text-primary';
            return 'fas fa-tag text-secondary';
        }

        async function toggleVisibility(tag) {
            const res = await fetch('/tags/toggle_visibility?' + new URLSearchParams({ tag_uuid: tag.uuid }));
            const data = await res.json();
            emit('notify', data.message, res.ok ? 'success-subtle' : 'danger-subtle');
            if (res.ok) emit('refresh');
        }

        async function toggleStatus(tag) {
            const res = await fetch('/tags/toggle_status?' + new URLSearchParams({ tag_uuid: tag.uuid }));
            const data = await res.json();
            emit('notify', data.message, res.ok ? 'success-subtle' : 'danger-subtle');
            if (res.ok) emit('refresh');
        }

        async function deleteTag(tag) {
            const res = await fetch('/tags/remove_tag?' + new URLSearchParams({ tag_id: tag.id }));
            const data = await res.json();
            emit('notify', data.message, res.ok ? 'success-subtle' : 'danger-subtle');
            if (res.ok) emit('refresh');
        }

        return {
            COLUMNS, visibleCols, toggleCol, showAll, hideAll,
            isSelected, sourceIcon, familyOf,
            toggleVisibility, toggleStatus, deleteTag,
            mapIcon, getTextColor,
        };
    },
    template: `
        <div class="tag-table-wrapper">
            <div v-if="loading" class="d-flex align-items-center justify-content-center py-5">
                <div class="spinner-border text-primary" role="status"></div>
            </div>

            <!-- ── Grouped view ───────────────────────────────────────────── -->
            <template v-else-if="showGrouped && groupedTags">
                <div v-for="(group, source) in groupedTags" :key="source" class="mb-4">
                    <div class="group-header d-flex align-items-center gap-2 mb-2 pb-1 border-bottom">
                        <i :class="sourceIcon(source)"></i>
                        <span class="fw-semibold" style="color: var(--text-color)">{{ source }}</span>
                        <span class="badge bg-secondary rounded-pill">{{ group.length }}</span>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-sm align-middle mb-0 tag-table">
                            <thead>
                                <tr>
                                    <th style="width:36px">
                                        <input type="checkbox" class="form-check-input"
                                               :checked="group.every(t => isSelected(t.id))"
                                               @change="$emit('toggle-all', group.map(t => t.id), $event.target.checked)">
                                    </th>
                                    <th>Tag</th>
                                    <th v-if="visibleCols.family">Family</th>
                                    <th v-if="visibleCols.description">Description</th>
                                    <th v-if="visibleCols.visibility">Visibility</th>
                                    <th v-if="visibleCols.status">Status</th>
                                    <th v-if="visibleCols.usage">Usage</th>
                                    <th class="text-end" style="white-space:nowrap; position:relative; overflow:visible;">
                                        Actions&nbsp;
                                        <col-picker :cols="COLUMNS" :visible="visibleCols"
                                                    @toggle="toggleCol"
                                                    @show-all="showAll"
                                                    @hide-all="hideAll">
                                        </col-picker>
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                <tag-row
                                    v-for="tag in group" :key="tag.uuid"
                                    :tag="tag"
                                    :selected="isSelected(tag.id)"
                                    :csrf-token="csrfToken"
                                    :show-namespace="showNamespace"
                                    :visible-cols="visibleCols"
                                    @toggle-select="$emit('toggle-select', tag.id)"
                                    @view-family="$emit('view-family', tag.source, familyOf(tag))"
                                    @toggle-visibility="toggleVisibility(tag)"
                                    @toggle-status="toggleStatus(tag)"
                                    @delete="deleteTag(tag)"
                                    @refresh="$emit('refresh')"
                                    @notify="(m,c) => $emit('notify', m, c)"
                                ></tag-row>
                            </tbody>
                        </table>
                    </div>
                </div>
                <div v-if="Object.keys(groupedTags).length === 0" class="text-center text-muted py-5">
                    <i class="fas fa-tags fa-2x mb-2 d-block opacity-25"></i>No tags found
                </div>
            </template>

            <!-- ── Flat view ──────────────────────────────────────────────── -->
            <template v-else>
                <div class="table-responsive">
                    <table class="table table-sm align-middle tag-table">
                        <thead>
                            <tr>
                                <th style="width:36px">
                                    <input type="checkbox" class="form-check-input"
                                           :checked="tags.length > 0 && tags.every(t => isSelected(t.id))"
                                           @change="$emit('toggle-all', tags.map(t => t.id), $event.target.checked)">
                                </th>
                                <th>Tag</th>
                                <th v-if="visibleCols.family">Family</th>
                                <th v-if="visibleCols.description">Description</th>
                                <th v-if="visibleCols.visibility">Visibility</th>
                                <th v-if="visibleCols.status">Status</th>
                                <th v-if="visibleCols.usage">Usage</th>
                                <th class="text-end" style="white-space:nowrap">
                                    Actions&nbsp;
                                    <col-picker :cols="COLUMNS" :visible="visibleCols"
                                                @toggle="toggleCol"
                                                @show-all="showAll"
                                                @hide-all="hideAll">
                                    </col-picker>
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            <tag-row
                                v-for="tag in tags" :key="tag.uuid"
                                :tag="tag"
                                :selected="isSelected(tag.id)"
                                :csrf-token="csrfToken"
                                :show-namespace="showNamespace"
                                :visible-cols="visibleCols"
                                @toggle-select="$emit('toggle-select', tag.id)"
                                @view-family="$emit('view-family', tag.source, familyOf(tag))"
                                @toggle-visibility="toggleVisibility(tag)"
                                @toggle-status="toggleStatus(tag)"
                                @delete="deleteTag(tag)"
                                @refresh="$emit('refresh')"
                                @notify="(m,c) => $emit('notify', m, c)"
                            ></tag-row>
                            <tr v-if="tags.length === 0">
                                <td colspan="8" class="text-center text-muted py-5">
                                    <i class="fas fa-tags fa-2x mb-2 d-block opacity-25"></i>No tags found
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </template>
        </div>
    `
};

export { TagTable, TagRow, familyOf, familyLabel, COLUMNS };
export default TagTable;