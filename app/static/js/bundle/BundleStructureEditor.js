/**
 * BundleStructureEditor.js
 *
 * Self-contained component for editing a bundle's file structure.
 * Renders:
 *   - Bundle Explorer (drag-and-drop tree, left panel)
 *   - A slot "rule-selector" for BundleRuleSelector (right panel)
 *   - Preview / Editor panel (full width below)
 *
 * Props:
 *   bundleId   String|Number  required
 *   csrfToken  String         default ''
 *
 * Emits:
 *   tree-saved — after a successful save
 *
 * Expose:
 *   addRules(rules)  — add an array of rule objects to the selected folder
 */

import SmartEditor from '/static/js/components/smart-editor.js'
import CodeViewer  from '/static/js/components/code-viewer.js'
import { create_message } from '/static/js/toaster.js'

const { ref, onMounted, onUnmounted, nextTick, watch } = Vue

// ── TreeItem sub-component ─────────────────────────────────────────

const TREE_ITEM_TEMPLATE = `
<li class="mb-1 bse-tree-item" style="list-style:none;" :data-id="node.id">
    <div
        class="bse-node-row"
        :class="{
            'bse-node-row--selected': selectedId === node.id,
            'bse-node-row--drop-target': localDropTarget && node.type === 'folder',
            'bse-node-row--multi': multiSet && multiSet.has(node.id),
        }"
        :title="multiSet && multiSet.size ? 'Ctrl/Cmd+click to add to selection' : ''"
        @click.stop="onRowClick($event, node)"
        @dragover="onDragOver($event, node)"
        @dragleave="onDragLeave($event)"
        @drop="onDrop($event, node)"
    >
        <span class="bse-node-drag-handle" title="Drag to move">
            <i class="fas fa-grip-vertical"></i>
        </span>

        <!-- Folder: chevron + folder icon -->
        <template v-if="node.type === 'folder'">
            <i class="fas bse-chevron"
               :class="collapsed ? 'fa-chevron-right' : 'fa-chevron-down'"
               style="font-size:.65rem;flex-shrink:0;color:var(--subtle-text-color);">
            </i>
            <i :class="collapsed ? 'fas fa-folder text-warning' : 'fas fa-folder-open text-warning'"
               style="font-size:.78rem;flex-shrink:0;"></i>
        </template>
        <!-- File: single icon -->
        <i v-else
            :class="isRule(node) ? 'fas fa-file-code text-primary' : 'fas fa-file-signature text-success'"
            style="font-size:.78rem;flex-shrink:0;">
        </i>

        <input v-if="renamingId === node.id" ref="renameInput" class="bse-node-name-input"
            :value="renameBaseName(node)"
            @click.stop @keydown.stop
            @keyup.enter="$emit('rename-confirm', node, $event.target.value)"
            @keyup.esc="$emit('rename-cancel')"
            @blur="$emit('rename-confirm', node, $event.target.value)">
        <span v-if="renamingId === node.id && renameExtOf(node)" class="bse-node-ext-lock">{{ renameExtOf(node) }}</span>
        <span v-if="renamingId !== node.id" class="bse-node-name" :title="node.name">{{ node.name }}</span>

        <div class="bse-node-actions" :class="{ 'bse-node-actions--force': armed }">
            <button v-if="!isRule(node)" class="bse-node-btn" title="Rename"
                @click.stop="$emit('rename', node)">
                <i class="fas fa-edit"></i>
            </button>
            <button v-if="node.type === 'folder'" class="bse-node-btn bse-node-btn--success" title="Add sub-folder"
                @click.stop="$emit('add-sub', node.children, 'folder')">
                <i class="fas fa-folder-plus"></i>
            </button>
            <button v-if="node.type === 'folder'" class="bse-node-btn" title="Create file"
                @click.stop="$emit('add-sub', node.children, 'file')">
                <i class="fas fa-file-medical"></i>
            </button>
            <span v-if="armed" class="bse-armed-hint">Click again to delete</span>
            <button class="bse-node-btn bse-node-btn--danger"
                :class="{ 'bse-node-btn--armed': armed }"
                :title="armed ? 'Click again to confirm removal' : 'Remove'"
                @click.stop="onDeleteClick(node)">
                <i class="fas fa-trash-alt"></i>
            </button>
        </div>
    </div>

    <div v-if="node.type === 'folder'" v-show="!collapsed"
         class="ps-3 border-start ms-2 mt-1">
        <draggable v-model="node.children" group="bse-tree" :item-key="n => n.id" tag="ul"
            class="ps-0 mb-0 bse-folder-drop-zone" :animation="150" ghost-class="bse-ghost"
            @end="$emit('sort-end', $event)">
            <template #item="{ element }">
                <tree-item
                    :node="element"
                    :selected-id="selectedId"
                    :multi-set="multiSet"
                    :renaming-id="renamingId"
                    @select="n => $emit('select', n)"
                    @rename="n => $emit('rename', n)"
                    @rename-confirm="(n, t) => $emit('rename-confirm', n, t)"
                    @rename-cancel="$emit('rename-cancel')"
                    @add-sub="(arr, kind) => $emit('add-sub', arr, kind)"
                    @remove="n => $emit('remove', n)"
                    @external-drop="(n, rules) => $emit('external-drop', n, rules)"
                    @toggle-multi="n => $emit('toggle-multi', n)"
                    @sort-end="ev => $emit('sort-end', ev)"
                />
            </template>
        </draggable>
    </div>
</li>
`

const TreeItem = {
    name: 'tree-item',
    props: ['node', 'selectedId', 'multiSet', 'renamingId'],
    template: TREE_ITEM_TEMPLATE,
    emits: ['select', 'rename', 'rename-confirm', 'rename-cancel', 'add-sub', 'remove', 'external-drop', 'toggle-multi', 'sort-end'],
    components: { draggable: window.vuedraggable },
    data() { return { localDropTarget: false, _leaveTimer: null, collapsed: false, armed: false, _armTimer: null } },
    updated() {
        // Autofocus the inline rename input the moment it appears.
        if (this.renamingId === this.node.id && this.$refs.renameInput && document.activeElement !== this.$refs.renameInput) {
            this.$refs.renameInput.focus()
            this.$refs.renameInput.select()
        }
    },
    methods: {
        isRule(node) { return node && String(node.id).startsWith('rule_') },
        toggleCollapse() { this.collapsed = !this.collapsed },

        // Custom (non-rule) files keep a locked extension while renaming —
        // only the base name is editable.
        renameBaseName(node) {
            if (node.type === 'file' && !this.isRule(node)) {
                const dot = node.name.lastIndexOf('.')
                return dot > 0 ? node.name.slice(0, dot) : node.name
            }
            return node.name
        },
        renameExtOf(node) {
            if (node.type === 'file' && !this.isRule(node)) {
                const dot = node.name.lastIndexOf('.')
                return dot > 0 ? node.name.slice(dot) : ''
            }
            return ''
        },

        // Plain click: preview (file) or expand/collapse (folder), as before.
        // Ctrl/Cmd+click: toggle this node in the multi-selection instead —
        // lets the user build up a set of rules/files to move or delete
        // together without touching each one's drag handle individually.
        onRowClick(ev, node) {
            if (ev.ctrlKey || ev.metaKey) {
                this.$emit('toggle-multi', node)
                return
            }
            if (node.type === 'folder') this.toggleCollapse()
            else this.$emit('select', node)
        },

        // First click arms the button (highlighted, no deletion yet); the
        // user must click again within 3s to actually confirm removal.
        // Replaces the old modal confirmation with a lighter two-click one.
        onDeleteClick(node) {
            clearTimeout(this._armTimer)
            if (this.armed) {
                this.armed = false
                this.$emit('remove', node)
            } else {
                this.armed = true
                this._armTimer = setTimeout(() => { this.armed = false }, 3000)
            }
        },

        // Only intercept dragover when an external rule is being dragged.
        // For internal tree reordering (SortableJS), let events propagate freely.
        onDragOver(ev, node) {
            if (!ev.dataTransfer.types.includes('application/rulezet-rule')) return
            if (node.type !== 'folder') return
            ev.preventDefault()
            ev.stopPropagation()
            clearTimeout(this._leaveTimer)
            this.localDropTarget = true
        },

        // Use a small delay to avoid flicker when moving between child elements.
        onDragLeave(ev) {
            this._leaveTimer = setTimeout(() => { this.localDropTarget = false }, 80)
        },

        // Only handle external rule drops; internal drops are handled by SortableJS.
        onDrop(ev, node) {
            this.localDropTarget = false
            const raw = ev.dataTransfer.getData('application/rulezet-rule')
            if (!raw) return               // internal SortableJS drop — ignore
            if (node.type !== 'folder') return
            ev.preventDefault()
            ev.stopPropagation()
            try { this.$emit('external-drop', node, JSON.parse(raw)) } catch {}
        },
    }
}

// ── Main component ─────────────────────────────────────────────────

export default {
    name: 'BundleStructureEditor',

    components: {
        'tree-item': TreeItem,
        'draggable': window.vuedraggable,
        SmartEditor,
        CodeViewer,
    },

    props: {
        bundleId:  { type: [String, Number], required: true },
        csrfToken: { type: String, default: '' },
    },

    emits: ['tree-saved', 'tree-ready'],

    expose: ['addRules', 'setPreview'],

    template: `
    <div class="bse-wrapper">

        <!-- ── Section header ── -->
        <div class="bse-section-header">
            <div class="bse-section-title">
                <i class="fas fa-sitemap text-primary"></i>
                Bundle Structure
            </div>
            <div class="d-flex align-items-center gap-2 flex-wrap">
                <div v-if="lastSavedAt" class="bse-last-saved">
                    <i class="fas fa-check-circle"></i>
                    <span>Last save</span>
                    <strong>{{ lastSavedAt }}</strong>
                </div>
                <button class="bse-save-btn" @click="saveNow" :disabled="saving">
                    <i :class="saving ? 'fas fa-spinner fa-spin' : 'fas fa-save'"></i>
                    {{ saving ? 'Saving…' : 'Save' }}
                    <i v-if="saveStatus === 'saved'" class="fas fa-check-circle bse-save-ok ms-1"></i>
                    <i v-else-if="saveStatus === 'error'" class="fas fa-times-circle bse-save-err ms-1"></i>
                </button>
            </div>
        </div>

        <!-- ── Top row: explorer + rule selector slot ── -->
        <div class="bse-top-row">

            <!-- Left: Bundle Explorer -->
            <div class="bse-explorer-card">
                <div class="bse-explorer-header">
                    <div class="bse-explorer-header-left">
                        <div class="bse-title"><i class="fas fa-folder-tree me-2"></i>Bundle Explorer</div>
                        <div class="bse-subtitle">
                            <i class="fas fa-up-down-left-right me-1 opacity-50"></i>Drag to reorganize ·
                            <i class="fas fa-grip-lines me-1 opacity-50"></i>Drop rules from the library onto a folder ·
                            <i class="fas fa-hand-pointer me-1 opacity-50"></i>Ctrl/Cmd+click to select several
                        </div>
                    </div>
                    <div class="bse-explorer-actions">
                        <button class="bse-action-btn" title="Add Folder"
                            @click="prepareTarget(treeData, 'folder')">
                            <i class="fas fa-folder-plus"></i>
                        </button>
                        <button class="bse-action-btn" title="Create File"
                            @click="prepareTarget(treeData, 'file')">
                            <i class="fas fa-file-code"></i>
                        </button>
                    </div>
                </div>

                <!-- Inline creation panel — replaces the old modal (nesting a
                     Bootstrap modal inside the "Organize Bundle" modal wasn't
                     reliable), opens right under the header instead. -->
                <div v-if="creationMode === 'folder'" class="bse-create-bar">
                    <i class="fas fa-folder-plus text-warning"></i>
                    <input class="bse-create-input" placeholder="Folder name" v-model="folderText"
                           @keyup.enter="confirmAddFolder" @keyup.esc="cancelCreation" autofocus>
                    <button class="bse-bulk-btn" @click="confirmAddFolder">Create</button>
                    <button class="bse-bulk-btn bse-bulk-btn--ghost" @click="cancelCreation" title="Cancel">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>
                <div v-if="creationMode === 'file'" class="bse-create-bar">
                    <i class="fas fa-file-code text-success"></i>
                    <input class="bse-create-input" placeholder="File name" v-model="fileNameText"
                           @keyup.enter="confirmAddFile" @keyup.esc="cancelCreation" autofocus>
                    <select class="bse-create-select" v-model="fileExt">
                        <option value=".txt">.txt</option>
                        <option value=".json">.json</option>
                        <option value=".yaml">.yaml</option>
                        <option value=".md">.md</option>
                    </select>
                    <button class="bse-bulk-btn" @click="confirmAddFile">Create</button>
                    <button class="bse-bulk-btn bse-bulk-btn--ghost" @click="cancelCreation" title="Cancel">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>

                <!-- Bulk action bar — appears once 2+ nodes are Ctrl/Cmd-selected.
                     "Move" is drag-and-drop: grab any selected node's drag
                     handle and the rest of the selection follows it to the
                     drop target (see onTreeSortEnd). -->
                <div v-if="multiSelected.size > 0" class="bse-bulk-bar">
                    <span class="bse-bulk-count">
                        <i class="fas fa-check-square me-1"></i>{{ multiSelected.size }} selected
                        <span class="bse-bulk-hint">— drag any of them to move the group</span>
                    </span>
                    <button class="bse-bulk-btn bse-bulk-btn--danger" :class="{ 'bse-bulk-btn--armed': bulkDeleteArmed }" @click="confirmBulkDelete">
                        <i class="fas fa-trash-alt me-1"></i>{{ bulkDeleteArmed ? 'Click again to delete' : 'Delete' }}
                    </button>
                    <button class="bse-bulk-btn bse-bulk-btn--ghost" @click="clearMultiSelect" title="Clear selection">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>

                <!-- Tree body with root drop zone -->
                <div class="bse-tree-body"
                    @dragover.prevent="onRootDragOver"
                    @dragleave="onRootDragLeave"
                    @drop.prevent="onRootDrop">
                    <draggable v-model="treeData" group="bse-tree" :item-key="i => i.id" tag="ul"
                        class="ps-0 mb-0 bse-root-drop-zone" :animation="150" ghost-class="bse-ghost"
                        @end="onTreeSortEnd">
                        <template #item="{ element }">
                            <tree-item
                                :node="element"
                                :selected-id="selectedNode?.id"
                                :multi-set="multiSelected"
                                :renaming-id="nodeToRename?.id"
                                @select="selectNode"
                                @rename="beginRename"
                                @rename-confirm="confirmRename"
                                @rename-cancel="cancelRename"
                                @add-sub="prepareTarget"
                                @remove="beginDelete"
                                @external-drop="onExternalDropOnFolder"
                                @toggle-multi="toggleMultiSelect"
                                @sort-end="onTreeSortEnd"
                            />
                        </template>
                    </draggable>
                    <div v-if="treeData.length === 0" class="bse-empty-tree text-center py-4 text-muted small">
                        <i class="fas fa-folder-open fa-2x opacity-25 d-block mb-2"></i>
                        Empty — add folders or drag rules here
                    </div>
                </div>
            </div>

            <!-- Right: rule selector slot -->
            <slot name="rule-selector" />
        </div>

        <!-- ── Preview / Editor panel ── -->
        <div class="bse-preview-card">
            <div v-if="!selectedNode && !previewContent" class="bse-preview-empty">
                <i class="fas fa-terminal fa-2x"></i>
                <strong>Preview &amp; Editor</strong>
                <span class="small">Select a file in the explorer or drag a rule from the right panel</span>
            </div>
            <template v-else>
                <div class="bse-preview-header">
                    <span class="bse-preview-filename">
                        <i v-if="selectedNode"
                           :class="selectedNode.type === 'folder' ? 'fas fa-folder text-warning' : 'fas fa-file-code text-primary'"
                           class="me-2"></i>
                        <i v-else class="fas fa-eye text-success me-2"></i>
                        {{ selectedNode ? selectedNode.name : 'Preview: ' + previewName }}
                    </span>
                    <div class="d-flex align-items-center gap-2">
                        <span v-if="!selectedNode || isRule(selectedNode)"
                              class="badge bg-secondary" style="font-size:.7rem;">Read-Only</span>
                        <template v-else>
                            <span class="badge bg-primary" style="font-size:.7rem;">Editable</span>
                            <button class="bse-editor-save-btn" @click="saveNow" :disabled="saving"
                                    :title="saving ? 'Saving…' : 'Save file'">
                                <i :class="saving ? 'fas fa-spinner fa-spin' : 'fas fa-save'"></i>
                                {{ saving ? 'Saving…' : 'Save' }}
                                <i v-if="saveStatus === 'saved'" class="fas fa-check-circle bse-save-ok ms-1"></i>
                                <i v-else-if="saveStatus === 'error'" class="fas fa-times-circle bse-save-err ms-1"></i>
                            </button>
                        </template>
                        <button class="btn btn-sm btn-outline-secondary py-0 px-2" @click="clearDisplay">
                            <i class="fas fa-times" style="font-size:.7rem;"></i>
                        </button>
                    </div>
                </div>

                <!-- Editable custom file -->
                <smart-editor
                    v-if="selectedNode && selectedNode.type === 'file' && !isRule(selectedNode)"
                    :model-value="selectedNode.content ?? ''"
                    @update:model-value="onContentChange"
                    mode="code"
                    language="text"
                    min-height="300px"
                    max-height="300px">
                </smart-editor>

                <!-- Save bar below the editor -->
                <div v-if="selectedNode && selectedNode.type === 'file' && !isRule(selectedNode)"
                     class="bse-editor-bottom-bar">
                    <span v-if="lastSavedAt" class="bse-last-saved">
                        <i class="fas fa-check-circle"></i>
                        <span>Last save</span>
                        <strong>{{ lastSavedAt }}</strong>
                    </span>
                    <button class="bse-save-btn ms-auto" @click="saveNow" :disabled="saving">
                        <i :class="saving ? 'fas fa-spinner fa-spin' : 'fas fa-save'"></i>
                        {{ saving ? 'Saving…' : 'Save file' }}
                        <i v-if="saveStatus === 'saved'" class="fas fa-check-circle bse-save-ok ms-1"></i>
                        <i v-else-if="saveStatus === 'error'" class="fas fa-times-circle bse-save-err ms-1"></i>
                    </button>
                </div>

                <!-- Read-only rule node -->
                <code-viewer
                    v-else-if="selectedNode && isRule(selectedNode)"
                    :code="selectedNode.content || ''"
                    :language="hlxLang(selectedNode.format)"
                    :title="selectedNode.name"
                    max-height="32vh">
                </code-viewer>

                <!-- Rule preview from selector panel -->
                <code-viewer
                    v-else-if="previewContent"
                    :code="previewContent"
                    :language="hlxLang(previewFormat)"
                    :title="previewName"
                    max-height="32vh">
                </code-viewer>

                <!-- Folder selected -->
                <div v-else class="p-5 text-center text-muted d-flex flex-column justify-content-center"
                     style="min-height:32vh;">
                    <i class="fas fa-folder-open fa-2x mb-2 opacity-25"></i>
                    <p class="small mb-0">
                        Folder <strong>{{ selectedNode.name }}</strong> is selected.<br>
                        Click a file to edit, or drop a rule here.
                    </p>
                </div>
            </template>
        </div>

    </div>
    `,

    setup(props, { emit }) {

        // ── Tree state ─────────────────────────────────────────────
        const treeData    = ref([{ id: 'root', name: 'Main Bundle', type: 'folder', children: [], content: '' }])
        const selectedNode   = ref(null)
        const lastFolder     = ref(null)  // last folder the user selected
        const previewContent = ref('')
        const previewName    = ref('')
        const previewFormat  = ref('')
        const saving         = ref(false)
        const saveStatus     = ref('')    // '' | 'saved' | 'error'
        const lastSavedAt    = ref('')
        const rootDropActive = ref(false)
        let saveStatusTimer  = null
        let autoSaveTimer    = null
        const treeLoaded     = ref(false)

        // Extract all rule_id values from the tree recursively
        function extractRuleIds(nodes) {
            const ids = new Set()
            function walk(list) {
                for (const n of list) {
                    if (n.rule_id) ids.add(n.rule_id)
                    if (n.children?.length) walk(n.children)
                }
            }
            walk(nodes)
            return ids
        }

        // Auto-save: fires 1200ms after any tree change (reorder, rename, content edit)
        watch(treeData, () => {
            if (!treeLoaded.value) return
            clearTimeout(autoSaveTimer)
            autoSaveTimer = setTimeout(() => saveStructure(), 1200)
        }, { deep: true })

        // ── Multi-select (Ctrl/Cmd+click) — move or delete several
        // nodes together instead of one at a time ─────────────────────
        const multiSelected = ref(new Set())
        const bulkDeleteArmed = ref(false)
        let bulkDeleteTimer = null

        function toggleMultiSelect(node) {
            const s = new Set(multiSelected.value)
            if (s.has(node.id)) s.delete(node.id)
            else s.add(node.id)
            multiSelected.value = s
            bulkDeleteArmed.value = false
        }
        function clearMultiSelect() {
            multiSelected.value = new Set()
            bulkDeleteArmed.value = false
        }

        // Remove and return the node with this id from the tree (or null).
        function extractNode(list, id) {
            const idx = list.findIndex(i => i.id === id)
            if (idx > -1) return list.splice(idx, 1)[0]
            for (const item of list) {
                if (item.children) {
                    const found = extractNode(item.children, id)
                    if (found) return found
                }
            }
            return null
        }

        // Which array currently holds this node id (its parent's children,
        // or treeData itself for a root-level node)?
        function findParentList(list, id) {
            if (list.some(n => n.id === id)) return list
            for (const item of list) {
                if (item.children) {
                    const found = findParentList(item.children, id)
                    if (found) return found
                }
            }
            return null
        }

        // Dragging one node when it's part of a multi-selection drags the
        // whole selection: SortableJS only physically moves the one item the
        // user grabbed, so once that drop lands we move every other selected
        // node alongside it into the same destination.
        function onTreeSortEnd(evt) {
            if (multiSelected.value.size < 2) return
            const draggedId = evt?.item?.dataset?.id
            if (!draggedId || !multiSelected.value.has(draggedId)) return
            const destination = findParentList(treeData.value, draggedId)
            if (!destination) return
            for (const id of multiSelected.value) {
                if (id === draggedId) continue
                const node = extractNode(treeData.value, id)
                if (node) destination.push(node)
            }
            clearMultiSelect()
            emit('tree-ready', [...extractRuleIds(treeData.value)])
            saveStructure()
        }

        // Same two-click "arm" pattern as single-node delete.
        function confirmBulkDelete() {
            if (!bulkDeleteArmed.value) {
                bulkDeleteArmed.value = true
                clearTimeout(bulkDeleteTimer)
                bulkDeleteTimer = setTimeout(() => { bulkDeleteArmed.value = false }, 3000)
                return
            }
            const ids = [...multiSelected.value]
            for (const id of ids) extractNode(treeData.value, id)
            if (selectedNode.value && ids.includes(selectedNode.value.id)) clearDisplay()
            clearMultiSelect()
            emit('tree-ready', [...extractRuleIds(treeData.value)])
            saveStructure()
        }

        // ── Inline create/rename state (was modal-based — nesting a
        // Bootstrap modal inside another open modal, like the in-modal
        // "Organize Bundle" view, doesn't reliably show/stack) ──────────
        const folderText    = ref('')
        const fileNameText  = ref('')
        const fileExt       = ref('.txt')
        const nodeToRename  = ref(null)   // node currently being renamed inline
        const currentTarget = ref(null)   // the array we add to
        const creationMode  = ref(null)   // 'folder' | 'file' | null — inline creation panel

        // ── Helpers ────────────────────────────────────────────────
        const isRule = (node) => node && String(node.id).startsWith('rule_')

        // Map Rulezet format names to highlight.js language identifiers
        function hlxLang(format) {
            const map = {
                sigma: 'yaml', wazuh: 'xml', elastic: 'json',
                nova: 'yaml', crs: 'nginx',
            }
            return map[(format || '').toLowerCase()] || 'plaintext'
        }

        const _ext = (format) => {
            const map = {
                yara: '.yar', sigma: '.yaml', nova: '.yaml', suricata: '.rules',
                zeek: '.zeek', wazuh: '.xml', nse: '.nse', crs: '.conf',
            }
            return map[(format || '').toLowerCase()] || '.txt'
        }

        // ── Load / save ────────────────────────────────────────────
        async function loadTree() {
            treeLoaded.value = false
            try {
                const res = await fetch(`/bundle/get_bundle_json/${props.bundleId}`)
                const data = await res.json()
                if (data.success && data.structure) treeData.value = data.structure
            } catch {}
            await nextTick()
            treeLoaded.value = true
            emit('tree-ready', [...extractRuleIds(treeData.value)])
        }

        function _timeStr() {
            return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        }

        let saveQueued = false
        async function saveStructure() {
            if (saving.value) {
                // Don't silently drop this change — a save is already in
                // flight (e.g. two quick drag-drops back to back). Queue one
                // retry so it still gets persisted once the current save ends.
                saveQueued = true
                return false
            }
            clearTimeout(autoSaveTimer)  // cancel pending auto-save; we're saving now
            saving.value = true
            saveStatus.value = ''
            clearTimeout(saveStatusTimer)
            try {
                const res = await fetch(`/bundle/save_workspace/${props.bundleId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body: JSON.stringify({ structure: treeData.value }),
                })
                const data = await res.json()
                if (data.success) {
                    saveStatus.value = 'saved'
                    lastSavedAt.value = _timeStr()
                    const ruleIds = [...extractRuleIds(treeData.value)]
                    emit('tree-saved', ruleIds)
                    saveStatusTimer = setTimeout(() => { saveStatus.value = '' }, 2500)
                    return true
                } else {
                    saveStatus.value = 'error'
                    saveStatusTimer = setTimeout(() => { saveStatus.value = '' }, 4000)
                }
            } catch {
                saveStatus.value = 'error'
                saveStatusTimer = setTimeout(() => { saveStatus.value = '' }, 4000)
            } finally {
                saving.value = false
                if (saveQueued) {
                    saveQueued = false
                    saveStructure()
                }
            }
            return false
        }

        // Manual save: cancel any pending auto-save then save immediately
        function saveNow() {
            clearTimeout(autoSaveTimer)
            saveStructure()
        }

        // Traverse treeData and set content on the node matching id
        function _setNodeContent(nodes, id, val) {
            for (const n of nodes) {
                if (n.id === id) { n.content = val; return true }
                if (n.children?.length && _setNodeContent(n.children, id, val)) return true
            }
            return false
        }

        // Called on every SmartEditor keystroke (debounced 800ms for auto-save)
        function onContentChange(val) {
            if (!selectedNode.value) return
            _setNodeContent(treeData.value, selectedNode.value.id, val)
            if (!treeLoaded.value) return
            clearTimeout(autoSaveTimer)
            autoSaveTimer = setTimeout(() => saveStructure(), 800)
        }

        // ── Node actions ───────────────────────────────────────────
        function selectNode(node) {
            previewContent.value = ''
            previewFormat.value  = ''
            previewName.value    = ''
            selectedNode.value   = node
            if (node && node.type === 'folder') lastFolder.value = node
        }

        function clearDisplay() {
            selectedNode.value   = null
            previewContent.value = ''
            previewName.value    = ''
            previewFormat.value  = ''
        }

        function setPreview(rule) {
            selectedNode.value   = null
            previewContent.value = rule.to_string || ''
            previewName.value    = rule.title || ''
            previewFormat.value  = rule.format || ''
        }

        // arr = the children array to create into; kind = 'folder' | 'file'
        // (undefined when triggered from the explorer header — defaults to
        // whichever the caller sets right after via creationMode.value = ...)
        function prepareTarget(arr, kind) {
            currentTarget.value = arr
            folderText.value    = ''
            fileNameText.value  = ''
            fileExt.value       = '.txt'
            if (kind) creationMode.value = kind
        }

        function cancelCreation() {
            creationMode.value = null
            folderText.value   = ''
            fileNameText.value = ''
        }

        // Add folder
        function confirmAddFolder() {
            const name = folderText.value.trim()
            if (!name) { create_message('Folder name required', 'warning-subtle'); return }
            const target = currentTarget.value || treeData.value
            const node = { id: 'f_' + Date.now(), name, type: 'folder', children: [], content: '' }
            target.push(node)
            selectNode(node)
            cancelCreation()
            saveStructure()
        }

        // Add file
        function confirmAddFile() {
            const base = fileNameText.value.trim()
            if (!base) { create_message('File name required', 'warning-subtle'); return }
            const target = currentTarget.value || treeData.value
            const fullName = base.endsWith(fileExt.value) ? base : base + fileExt.value
            const node = { id: 'fi_' + Date.now(), name: fullName, type: 'file', children: [], content: '' }
            target.push(node)
            selectNode(node)
            cancelCreation()
            saveStructure()
        }

        // Rename — inline on the row itself (see TreeItem's renameBaseName /
        // renameExtOf: custom files keep their extension locked while the
        // base name is edited).
        function beginRename(node) {
            nodeToRename.value = node
        }

        function cancelRename() {
            nodeToRename.value = null
        }

        function confirmRename(node, text) {
            // Guards against a stale/duplicate event (Enter fires
            // rename-confirm, then unmounting the input on the next render
            // fires a native blur which fires rename-confirm again).
            if (!nodeToRename.value || nodeToRename.value.id !== node.id) return
            const base = (text || '').trim()
            if (base) {
                const dot = (node.type === 'file' && !isRule(node)) ? node.name.lastIndexOf('.') : -1
                const ext = dot > 0 ? node.name.slice(dot) : ''
                node.name = base + ext
            }
            nodeToRename.value = null
            saveStructure()
        }

        // Delete
        function beginDelete(node) {
            if (!node) return
            const id = node.id
            const findAndRemove = (list) => {
                const idx = list.findIndex(i => i.id === id)
                if (idx > -1) { list.splice(idx, 1); return true }
                for (const item of list)
                    if (item.children && findAndRemove(item.children)) return true
                return false
            }
            if (findAndRemove(treeData.value)) {
                if (selectedNode.value?.id === id) clearDisplay()
            }
            emit('tree-ready', [...extractRuleIds(treeData.value)])
            saveStructure()
        }

        // ── Add rules from BundleRuleSelector ─────────────────────
        // Priority: selected folder > last clicked folder > first root folder > tree root
        function _targetFolder() {
            if (selectedNode.value?.type === 'folder') return selectedNode.value.children
            if (lastFolder.value) return lastFolder.value.children
            const first = treeData.value[0]
            if (first?.type === 'folder') return first.children
            return treeData.value
        }

        function addRules(rules) {
            const target = _targetFolder()
            for (const rule of rules) {
                const ext = _ext(rule.format)
                target.push({
                    id:       'rule_' + rule.id + '_' + Date.now(),
                    rule_id:  rule.id,
                    name:     rule.title + ext,
                    type:     'file',
                    format:   rule.format || '',
                    content:  rule.to_string || '',
                    children: [],
                })
            }
            emit('tree-ready', [...extractRuleIds(treeData.value)])
            saveStructure()
        }

        // ── External DnD (rules dragged from BundleRuleSelector) ──
        // payload is always an array of rule objects
        function _pushRules(target, rules) {
            for (const rule of rules) {
                target.push({
                    id:       'rule_' + rule.id + '_' + Date.now(),
                    rule_id:  rule.id,
                    name:     rule.title + _ext(rule.format),
                    type:     'file',
                    format:   rule.format || '',
                    content:  rule.to_string || '',
                    children: [],
                })
            }
        }

        function onExternalDropOnFolder(folderNode, rawPayload) {
            const rules = Array.isArray(rawPayload) ? rawPayload : [rawPayload]
            _pushRules(folderNode.children, rules)
            // Tell the rule library what's now in the tree BEFORE the network
            // save resolves — otherwise a second quick drop of the same rule
            // (dropped while the first save is still in flight) creates a
            // duplicate node instead of being excluded from the library.
            emit('tree-ready', [...extractRuleIds(treeData.value)])
            saveStructure()
        }

        // DnD on tree root
        function onRootDragOver(ev) {
            if (ev.dataTransfer.types.includes('application/rulezet-rule')) {
                ev.preventDefault()
                rootDropActive.value = true
            }
        }
        function onRootDragLeave() { rootDropActive.value = false }
        function onRootDrop(ev) {
            rootDropActive.value = false
            const raw = ev.dataTransfer.getData('application/rulezet-rule')
            if (!raw) return
            try {
                const parsed = JSON.parse(raw)
                const rules = Array.isArray(parsed) ? parsed : [parsed]
                _pushRules(treeData.value, rules)
                emit('tree-ready', [...extractRuleIds(treeData.value)])
                saveStructure()
            } catch {}
        }

        // ── Lifecycle ──────────────────────────────────────────────
        onMounted(() => loadTree())
        onUnmounted(() => { clearTimeout(saveStatusTimer); clearTimeout(autoSaveTimer) })

        return {
            treeData, selectedNode, previewContent, previewName, previewFormat,
            saving, saveStatus, lastSavedAt, rootDropActive,
            folderText, fileNameText, fileExt, nodeToRename, creationMode,
            isRule, hlxLang, selectNode, clearDisplay, setPreview, prepareTarget,
            confirmAddFolder, confirmAddFile, cancelCreation,
            beginRename, confirmRename, cancelRename,
            beginDelete, saveStructure, saveNow, onContentChange,
            addRules, setPreview,
            onExternalDropOnFolder, onRootDragOver, onRootDragLeave, onRootDrop, onTreeSortEnd,
            multiSelected, toggleMultiSelect, clearMultiSelect,
            bulkDeleteArmed, confirmBulkDelete,
        }
    },
}
