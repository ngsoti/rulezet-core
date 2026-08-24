/**
 * TaskCanvas — free-form drag-and-drop pipeline editor, the second way to
 * build a workflow's graph (the first being the "After another task" picker
 * in the task modal). Complements TaskWorkflowGraph (the fixed-column DAG
 * used to WATCH a workflow execute) rather than replacing it: this view is
 * for BUILDING the pipeline by hand — drag a node to reposition it, drag
 * from its connector handle onto another node to wire a dependency, pan by
 * dragging the background, zoom with the wheel.
 *
 * Positions are stored server-side per task (AdminTaskSchedule.position_x/y)
 * so the layout survives a reload; a task that has never been dragged falls
 * back to a simple auto-grid until it is.
 *
 * Deliberately does NOT show the focus/dim treatment or a "view logs" action
 * that TaskWorkflowGraph has — this view is for BUILDING the pipeline, not
 * for watching it run; logs/focus live entirely in the Pipeline view.
 *
 * Props:
 *   schedules   — full (unpaginated) array of schedule objects for this workflow.
 *   taskTypes   — the TASK_TYPES registry (icon/label per task_type).
 *   liveStatus  — optional {task_uuid: {job_status, done, total}} map — same
 *                 live-run highlighting as TaskWorkflowGraph, just for
 *                 at-a-glance state while editing (no focus/dim here).
 * Emits:
 *   'edit'   (schedule)              — pencil icon clicked. No 'run' here —
 *                                     Edit mode is for building the graph,
 *                                     not for triggering jobs.
 *   'delete' (schedule)              — trash icon clicked.
 *   'move'   (schedule, x, y)        — node dropped after a drag — persist.
 *   'connect'(fromSchedule, toSchedule) — a connector handle was dropped onto
 *                                     another node — the page asks for the
 *                                     success/failure/always condition next.
 *   'edge-click' (childSchedule)     — an existing connection line was
 *                                     clicked — the page offers to change
 *                                     its condition or remove it.
 *   'add-node' (x, y)                — the "+" button was clicked at this
 *                                     canvas-space position — the page opens
 *                                     the task creation modal.
 *   'duplicate' (schedule)           — "Duplicate" chosen from a node's
 *                                     right-click menu — the page recreates
 *                                     the task with the same settings.
 */
const GRID_COL_WIDTH = 220;
const GRID_ROW_HEIGHT = 140;
const GRID_COLS = 4;

const TaskCanvas = {
    props: {
        schedules: { type: Array, default: () => [] },
        taskTypes: { type: Object, default: () => ({}) },
        liveStatus: { type: Object, default: () => ({}) },
    },
    emits: ['edit', 'delete', 'move', 'connect', 'edge-click', 'add-node', 'duplicate'],
    delimiters: ['[[', ']]'],
    data() {
        return {
            pan: { x: 40, y: 40 },
            scale: 1,
            localPositions: {},   // uuid -> {x, y} — optimistic, overrides schedule.position_* while dragging
            dragNode: null,       // schedule currently being dragged
            dragStart: null,      // {mouseX, mouseY, nodeX, nodeY}
            panning: false,
            panStart: null,       // {mouseX, mouseY, panX, panY}
            connectingFrom: null, // schedule currently dragging a connection from
            connectPoint: null,   // {x, y} in canvas space — live end of the connection line
            contextMenu: null,    // {schedule, x, y} in viewport (client) coords while a right-click menu is open
        };
    },
    computed: {
        // Dependency-depth columns (same left-to-right grouping as
        // TaskWorkflowGraph's pipeline view) — used only to place a task that
        // has never been dragged, so an untouched graph already reads left
        // to right instead of wrapping into an arbitrary 4-wide grid that
        // ignores which task depends on which.
        autoLayoutColumns() {
            const byId = new Map(this.schedules.map(s => [s.id, s]));
            const childrenOf = new Map();
            for (const s of this.schedules) {
                if (s.trigger_mode === 'after_task' && s.depends_on_schedule_id != null && byId.has(s.depends_on_schedule_id)) {
                    if (!childrenOf.has(s.depends_on_schedule_id)) childrenOf.set(s.depends_on_schedule_id, []);
                    childrenOf.get(s.depends_on_schedule_id).push(s);
                }
            }
            const roots = this.schedules.filter(s =>
                s.trigger_mode !== 'after_task' || s.depends_on_schedule_id == null || !byId.has(s.depends_on_schedule_id));
            const cols = [];
            const visit = (node, depth, seen) => {
                if (seen.has(node.id)) return;
                seen.add(node.id);
                if (!cols[depth]) cols[depth] = [];
                cols[depth].push(node);
                for (const child of (childrenOf.get(node.id) || [])) visit(child, depth + 1, seen);
            };
            for (const root of roots) visit(root, 0, new Set());
            return cols.filter(Boolean);
        },
        nodePositions() {
            const positions = {};
            this.autoLayoutColumns.forEach((col, depth) => {
                col.forEach((s, row) => {
                    if (this.localPositions[s.uuid]) {
                        positions[s.uuid] = this.localPositions[s.uuid];
                    } else if (s.position_x != null && s.position_y != null) {
                        positions[s.uuid] = { x: s.position_x, y: s.position_y };
                    } else {
                        positions[s.uuid] = {
                            x: 60 + depth * GRID_COL_WIDTH,
                            y: 40 + row * GRID_ROW_HEIGHT,
                        };
                    }
                });
            });
            return positions;
        },
        edges() {
            const byId = new Map(this.schedules.map(s => [s.id, s]));
            const edges = [];
            for (const s of this.schedules) {
                if (s.trigger_mode !== 'after_task' || s.depends_on_schedule_id == null) continue;
                const parent = byId.get(s.depends_on_schedule_id);
                if (!parent) continue;
                const p1 = this.nodePositions[parent.uuid];
                const p2 = this.nodePositions[s.uuid];
                if (!p1 || !p2) continue;
                const x1 = p1.x + 170, y1 = p1.y + 28;
                const x2 = p2.x, y2 = p2.y + 28;
                const midX = (x1 + x2) / 2;
                const color = { success: '#198754', failure: '#dc3545', always: '#6c757d' }[s.depends_on_condition] || '#0d6efd';
                edges.push({
                    id: `${parent.uuid}-${s.uuid}`,
                    d: `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`,
                    color, child: s,
                });
            }
            return edges;
        },
        canvasSize() {
            let maxX = 800, maxY = 500;
            Object.values(this.nodePositions).forEach(p => {
                maxX = Math.max(maxX, p.x + 400);
                maxY = Math.max(maxY, p.y + 300);
            });
            return { w: maxX, h: maxY };
        },
        transformStyle() {
            return `transform: translate(${this.pan.x}px, ${this.pan.y}px) scale(${this.scale}); transform-origin: 0 0;`;
        },
    },
    mounted() {
        window.addEventListener('mousemove', this.onMouseMove);
        window.addEventListener('mouseup', this.onMouseUp);
    },
    beforeUnmount() {
        window.removeEventListener('mousemove', this.onMouseMove);
        window.removeEventListener('mouseup', this.onMouseUp);
    },
    methods: {
        liveFor(s) { return this.liveStatus[s.uuid] || null; },
        statusClass(s) {
            // Reuses .twg-node--* from taskWorkflowGraph.css (colors + the
            // running pulse animation) so both graph views look consistent.
            const live = this.liveFor(s);
            if (live && ['pending', 'running'].includes(live.job_status)) return 'twg-node--running';
            if (live && live.job_status === 'failed') return 'twg-node--failed';
            if (!s.is_active) return 'twg-node--paused';
            if (s.last_run_status === 'failed') return 'twg-node--failed';
            return 'twg-node--active';
        },
        typeIcon(taskType) { return (this.taskTypes[taskType] || {}).icon || 'fa-solid fa-gear'; },
        typeLabel(taskType) { return (this.taskTypes[taskType] || {}).label || taskType; },

        toCanvasSpace(clientX, clientY) {
            const rect = this.$refs.wrap.getBoundingClientRect();
            return {
                x: (clientX - rect.left - this.pan.x) / this.scale,
                y: (clientY - rect.top - this.pan.y) / this.scale,
            };
        },

        // ── Node dragging ────────────────────────────────────────────────────
        startNodeDrag(schedule, evt) {
            if (evt.button !== 0) return; // right-click opens the context menu instead — see onNodeContextMenu
            evt.stopPropagation();
            const pos = this.nodePositions[schedule.uuid] || { x: 0, y: 0 };
            this.dragNode = schedule;
            this.dragStart = { mouseX: evt.clientX, mouseY: evt.clientY, nodeX: pos.x, nodeY: pos.y };
        },

        // ── Right-click menu — Duplicate ─────────────────────────────────────
        onNodeContextMenu(schedule, evt) {
            this.contextMenu = { schedule, x: evt.clientX, y: evt.clientY };
        },
        closeContextMenu() {
            this.contextMenu = null;
        },
        duplicateFromMenu() {
            if (!this.contextMenu) return;
            this.$emit('duplicate', this.contextMenu.schedule);
            this.contextMenu = null;
        },

        // ── Background panning ──────────────────────────────────────────────
        startPan(evt) {
            this.panning = true;
            this.panStart = { mouseX: evt.clientX, mouseY: evt.clientY, panX: this.pan.x, panY: this.pan.y };
        },

        // ── Connection dragging ──────────────────────────────────────────────
        startConnect(schedule, evt) {
            evt.stopPropagation();
            this.connectingFrom = schedule;
            this.connectPoint = this.toCanvasSpace(evt.clientX, evt.clientY);
        },

        onMouseMove(evt) {
            if (this.dragNode) {
                const dx = (evt.clientX - this.dragStart.mouseX) / this.scale;
                const dy = (evt.clientY - this.dragStart.mouseY) / this.scale;
                this.localPositions = {
                    ...this.localPositions,
                    [this.dragNode.uuid]: { x: this.dragStart.nodeX + dx, y: this.dragStart.nodeY + dy },
                };
            } else if (this.panning) {
                this.pan = {
                    x: this.panStart.panX + (evt.clientX - this.panStart.mouseX),
                    y: this.panStart.panY + (evt.clientY - this.panStart.mouseY),
                };
            } else if (this.connectingFrom) {
                this.connectPoint = this.toCanvasSpace(evt.clientX, evt.clientY);
            }
        },

        onMouseUp(evt) {
            if (this.dragNode) {
                // A plain click (mousedown+mouseup with no mousemove in
                // between) never populates localPositions — nothing moved,
                // so there's nothing to persist.
                const pos = this.localPositions[this.dragNode.uuid];
                if (pos) this.$emit('move', this.dragNode, pos.x, pos.y);
                this.dragNode = null;
                this.dragStart = null;
            } else if (this.panning) {
                this.panning = false;
                this.panStart = null;
            } else if (this.connectingFrom) {
                const el = document.elementFromPoint(evt.clientX, evt.clientY);
                const nodeEl = el ? el.closest('.tc-node') : null;
                if (nodeEl) {
                    const targetUuid = nodeEl.dataset.uuid;
                    const target = this.schedules.find(s => s.uuid === targetUuid);
                    if (target && target.uuid !== this.connectingFrom.uuid) {
                        this.$emit('connect', this.connectingFrom, target);
                    }
                }
                this.connectingFrom = null;
                this.connectPoint = null;
            }
        },

        onWheel(evt) {
            evt.preventDefault();
            const delta = evt.deltaY > 0 ? -0.1 : 0.1;
            this.scale = Math.min(1.6, Math.max(0.4, this.scale + delta));
        },

        resetView() {
            this.pan = { x: 40, y: 40 };
            this.scale = 1;
        },

        onAddNode() {
            // Center of the currently visible viewport, not the toolbar
            // button's own screen position (which sits above .tc-wrap and
            // would place the new node off-screen above the visible frame).
            const rect = this.$refs.wrap.getBoundingClientRect();
            const pos = {
                x: (rect.width / 2 - this.pan.x) / this.scale,
                y: (rect.height / 2 - this.pan.y) / this.scale,
            };
            this.$emit('add-node', pos.x, pos.y);
        },
    },
    template: `
    <div class="tc-container">
        <div class="tc-toolbar">
            <div class="twg-legend">
                <span class="twg-legend-item"><span class="twg-dot" style="background:#198754;"></span>on success</span>
                <span class="twg-legend-item"><span class="twg-dot" style="background:#dc3545;"></span>on failure</span>
                <span class="twg-legend-item"><span class="twg-dot" style="background:#6c757d;"></span>always</span>
            </div>
            <div class="tc-toolbar-actions">
                <button class="btn btn-sm btn-outline-secondary rounded-pill" @click="resetView" title="Reset pan/zoom">
                    <i class="fa-solid fa-compress"></i>
                </button>
                <button class="btn btn-sm btn-primary rounded-pill px-3" @click="onAddNode" title="Add a task here">
                    <i class="fa-solid fa-plus me-1"></i>Add task
                </button>
            </div>
        </div>

        <div class="tc-wrap" ref="wrap" @mousedown="startPan" @wheel="onWheel">
            <div class="tc-inner" :style="[transformStyle, { width: canvasSize.w + 'px', height: canvasSize.h + 'px' }]">
                <svg class="tc-edges" :width="canvasSize.w" :height="canvasSize.h">
                    <path v-for="e in edges" :key="e.id" :d="e.d" :stroke="e.color" fill="none" stroke-width="2" opacity="0.8"></path>
                    <!-- Wide, invisible overlay on top of each edge — a real
                         click target much easier to hit than the 2px line. -->
                    <path v-for="e in edges" :key="e.id + '-hit'" :d="e.d" stroke="transparent" stroke-width="16" fill="none"
                          class="tc-edge-hit" @click="$emit('edge-click', e.child)"></path>
                    <path v-if="connectingFrom" :d="'M ' + (nodePositions[connectingFrom.uuid].x + 170) + ' ' + (nodePositions[connectingFrom.uuid].y + 28) + ' L ' + connectPoint.x + ' ' + connectPoint.y"
                          stroke="#0d6efd" stroke-width="2" stroke-dasharray="4,4" fill="none"></path>
                </svg>

                <div v-for="s in schedules" :key="s.id" class="tc-node" :data-uuid="s.uuid"
                     :class="statusClass(s)"
                     :style="{ left: nodePositions[s.uuid].x + 'px', top: nodePositions[s.uuid].y + 'px' }"
                     @mousedown="startNodeDrag(s, $event)"
                     @contextmenu.prevent="onNodeContextMenu(s, $event)">
                    <div class="twg-node-icon"><i :class="typeIcon(s.task_type)"></i></div>
                    <div class="twg-node-body">
                        <div class="twg-node-title">[[ s.title ]]</div>
                        <div class="twg-node-sub-row">
                            <span class="twg-node-sub">[[ typeLabel(s.task_type) ]]</span>
                            <span class="twg-status-badge" :class="s.is_active ? 'twg-status-badge--active' : 'twg-status-badge--paused'">[[ s.is_active ? 'Active' : 'Paused' ]]</span>
                        </div>
                    </div>
                    <div class="twg-node-actions" @mousedown.stop @click.stop>
                        <button class="twg-node-action-btn" title="Edit" @click="$emit('edit', s)"><i class="fa-solid fa-pen"></i></button>
                        <button class="twg-node-action-btn twg-node-action-btn--danger" title="Delete" @click="$emit('delete', s)"><i class="fa-solid fa-trash"></i></button>
                    </div>
                    <!-- Grab anywhere along this strip (not just a tiny dot)
                         to start a connection to another task. -->
                    <div class="tc-node-handle" title="Drag onto another task to connect them" @mousedown.stop="startConnect(s, $event)">
                        <i class="fa-solid fa-arrow-right"></i>
                    </div>
                </div>
            </div>
        </div>
        <p class="text-muted small mt-2 mb-0"><i class="fa-solid fa-circle-info me-1"></i>Drag a task to move it, drag from the arrow handle onto another task to connect them, drag the background to pan, scroll to zoom, right-click to duplicate.</p>

        <!-- Right-click menu — kept OUTSIDE .tc-inner (which is CSS-transformed
             for pan/zoom) so this can safely use position:fixed in viewport
             coordinates instead of fighting the canvas transform. -->
        <template v-if="contextMenu">
            <div class="tc-context-backdrop" @click="closeContextMenu" @contextmenu.prevent="closeContextMenu"></div>
            <div class="tc-context-menu" :style="{ left: contextMenu.x + 'px', top: contextMenu.y + 'px' }">
                <div class="tc-context-menu-header">[[ contextMenu.schedule.title ]]</div>
                <button class="tc-context-menu-item" @click="duplicateFromMenu">
                    <i class="fa-solid fa-copy me-2"></i>Duplicate
                </button>
            </div>
        </template>
    </div>
    `,
};

export default TaskCanvas;
