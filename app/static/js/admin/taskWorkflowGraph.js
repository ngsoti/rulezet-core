/**
 * TaskWorkflowGraph — lightweight pipeline/DAG visualization for the Admin
 * Task Scheduler, modeled on GitHub Actions' workflow graph: tasks laid out
 * in fixed columns by dependency depth (not force-directed — PivoTick was
 * considered but its force-directed layout is unstable/organic, the wrong
 * fit for a left-to-right pipeline where read order matters). Phase 1's
 * dependency model is single-parent only, so this is always a forest of
 * trees — no cycle handling needed beyond the visited-set safety net below.
 *
 * This is also the ONLY way tasks are browsed in a workflow (no table/card
 * view) — search and every per-task action (run/edit/delete) live here.
 *
 * Props:
 *   schedules   — full (unpaginated) array of schedule objects, as returned
 *                 by GET /admin/tasks/list (needs id, depends_on_schedule_id).
 *   taskTypes   — the TASK_TYPES registry (for icon/label per task_type).
 *   liveStatus  — optional {task_uuid: {job_status, done, total}} map, as
 *                 returned by GET /admin/tasks/workflows/<uuid>/live. When a
 *                 task's job_status is 'pending'/'running', its node pulses
 *                 and shows a done/total progress readout.
 *   searchQuery — free-text filter; non-matching nodes are dimmed (not
 *                 hidden — hiding would break the tree's parent/child lines).
 *   focusedUuids — uuids of the tasks currently "in focus" (the ones whose
 *                 logs are shown below the graph) — an array, not a single
 *                 uuid, so two tasks running in parallel both stay lit up
 *                 instead of one dimming the other. Every non-focused node
 *                 dims when the array is non-empty.
 * Emits:
 *   'select' (schedule) — node body clicked: show that task's logs.
 *   'edit'   (schedule) — pencil icon clicked.
 *   'run'    (schedule) — play icon clicked.
 *   'delete' (schedule) — trash icon clicked.
 */
const TaskWorkflowGraph = {
    props: {
        schedules: { type: Array, default: () => [] },
        taskTypes: { type: Object, default: () => ({}) },
        liveStatus: { type: Object, default: () => ({}) },
        searchQuery: { type: String, default: '' },
        focusedUuids: { type: Array, default: () => [] },
    },
    emits: ['select', 'edit', 'run', 'delete'],
    delimiters: ['[[', ']]'],
    data() {
        return {
            edges: [],       // [{ d: 'M...', color, dimmed }]
            svgSize: { w: 0, h: 0 },
            nodeRefs: new Map(),
        };
    },
    computed: {
        columns() {
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
                if (seen.has(node.id)) return; // safety net — Phase 1 forbids cycles server-side
                seen.add(node.id);
                if (!cols[depth]) cols[depth] = [];
                cols[depth].push(node);
                for (const child of (childrenOf.get(node.id) || [])) visit(child, depth + 1, seen);
            };
            for (const root of roots) visit(root, 0, new Set());

            return cols.filter(Boolean);
        },
    },
    watch: {
        schedules: {
            deep: false,
            handler() { this.$nextTick(() => this.recomputeEdges()); },
        },
        focusedUuids() { this.$nextTick(() => this.recomputeEdges()); },
    },
    mounted() {
        this.$nextTick(() => this.recomputeEdges());
        this._onResize = () => this.recomputeEdges();
        window.addEventListener('resize', this._onResize);
    },
    beforeUnmount() {
        window.removeEventListener('resize', this._onResize);
    },
    methods: {
        setNodeRef(id, el) {
            if (el) this.nodeRefs.set(id, el); else this.nodeRefs.delete(id);
        },
        liveFor(s) { return this.liveStatus[s.uuid] || null; },
        matchesSearch(s) {
            if (!this.searchQuery) return true;
            const q = this.searchQuery.toLowerCase();
            return s.title.toLowerCase().includes(q) || this.typeLabel(s.task_type).toLowerCase().includes(q);
        },
        isDimmed(s) {
            if (this.focusedUuids.length) return !this.focusedUuids.includes(s.uuid);
            if (this.searchQuery) return !this.matchesSearch(s);
            return false;
        },
        statusClass(s) {
            const live = this.liveFor(s);
            if (live && ['pending', 'running'].includes(live.job_status)) return 'twg-node--running';
            if (live && live.job_status === 'failed') return 'twg-node--failed';
            if (!s.is_active) return 'twg-node--paused';
            if (s.last_run_status === 'failed') return 'twg-node--failed';
            return 'twg-node--active';
        },
        liveProgressLabel(s) {
            const live = this.liveFor(s);
            if (!live || !['pending', 'running'].includes(live.job_status)) return null;
            if (live.job_status === 'pending') return 'Queued…';
            return live.total > 0 ? `Running — ${live.done}/${live.total}` : 'Running…';
        },
        // Small check/cross/ban overlay on the icon once a task has actually
        // concluded — lets you trace which branch a run took at a glance
        // after the fact, not just while it's live. Prefers the live job
        // status (mirrors cancellation, which last_run_status never reflects)
        // and falls back to the schedule's own last recorded outcome.
        outcomeStatus(s) {
            const live = this.liveFor(s);
            return (live && live.job_status) || s.last_run_status;
        },
        outcomeIcon(s) {
            const status = this.outcomeStatus(s);
            if (status === 'done') return 'fa-solid fa-check';
            if (status === 'failed') return 'fa-solid fa-xmark';
            if (status === 'cancelled') return 'fa-solid fa-ban';
            return null;
        },
        hasLogs(s) {
            return !!((this.liveFor(s) || {}).job_uuid || s.last_run_job_uuid);
        },
        typeIcon(taskType) { return (this.taskTypes[taskType] || {}).icon || 'fa-solid fa-gear'; },
        typeLabel(taskType) { return (this.taskTypes[taskType] || {}).label || taskType; },
        recomputeEdges() {
            const wrap = this.$refs.wrap;
            if (!wrap) return;
            const wrapRect = wrap.getBoundingClientRect();
            this.svgSize = { w: wrap.scrollWidth, h: wrap.scrollHeight };

            const byId = new Map(this.schedules.map(s => [s.id, s]));
            const edges = [];
            for (const s of this.schedules) {
                if (s.trigger_mode !== 'after_task' || s.depends_on_schedule_id == null) continue;
                const parent = byId.get(s.depends_on_schedule_id);
                const parentEl = this.nodeRefs.get(s.depends_on_schedule_id);
                const childEl = this.nodeRefs.get(s.id);
                if (!parentEl || !childEl) continue;

                const pr = parentEl.getBoundingClientRect();
                const cr = childEl.getBoundingClientRect();
                const x1 = pr.right - wrapRect.left + wrap.scrollLeft;
                const y1 = pr.top - wrapRect.top + wrap.scrollTop + pr.height / 2;
                const x2 = cr.left - wrapRect.left + wrap.scrollLeft;
                const y2 = cr.top - wrapRect.top + wrap.scrollTop + cr.height / 2;
                const midX = (x1 + x2) / 2;

                const color = { success: '#198754', failure: '#dc3545', always: '#6c757d' }[s.depends_on_condition] || '#0d6efd';
                const dimmed = this.focusedUuids.length > 0 && !this.focusedUuids.includes(s.uuid) && !(parent && this.focusedUuids.includes(parent.uuid));
                edges.push({
                    id: `${s.depends_on_schedule_id}-${s.id}`,
                    d: `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`,
                    color, dimmed,
                });
            }
            this.edges = edges;
        },
    },
    template: `
    <div class="twg-container">
        <div class="twg-legend mb-2">
            <span class="twg-legend-item"><span class="twg-dot" style="background:#198754;"></span>on success</span>
            <span class="twg-legend-item"><span class="twg-dot" style="background:#dc3545;"></span>on failure</span>
            <span class="twg-legend-item"><span class="twg-dot" style="background:#6c757d;"></span>always</span>
        </div>
        <div class="twg-wrap" ref="wrap">
            <svg class="twg-edges" :width="svgSize.w" :height="svgSize.h">
                <path v-for="e in edges" :key="e.id" :d="e.d" :stroke="e.color" fill="none" stroke-width="2"
                      :opacity="e.dimmed ? 0.15 : 0.8"></path>
            </svg>
            <div class="twg-columns">
                <div v-for="(col, depth) in columns" :key="depth" class="twg-column">
                    <div v-for="node in col" :key="node.id"
                         :ref="el => setNodeRef(node.id, el)"
                         class="twg-node" :class="[statusClass(node), { 'twg-node--dimmed': isDimmed(node), 'twg-node--focused': focusedUuids.includes(node.uuid) }]"
                         @click="$emit('select', node)">
                        <div class="twg-node-icon">
                            <i :class="typeIcon(node.task_type)"></i>
                            <span v-if="outcomeIcon(node)" class="twg-outcome-badge" :class="'twg-outcome-badge--' + outcomeStatus(node)">
                                <i :class="outcomeIcon(node)"></i>
                            </span>
                        </div>
                        <div class="twg-node-body">
                            <div class="twg-node-title">[[ node.title ]]</div>
                            <div class="twg-node-sub-row">
                                <span class="twg-node-sub" v-if="liveProgressLabel(node)">[[ liveProgressLabel(node) ]]</span>
                                <span class="twg-node-sub" v-else>[[ typeLabel(node.task_type) ]]</span>
                                <span class="twg-status-badge" :class="node.is_active ? 'twg-status-badge--active' : 'twg-status-badge--paused'">[[ node.is_active ? 'Active' : 'Paused' ]]</span>
                            </div>
                        </div>
                        <div class="twg-node-actions" @click.stop>
                            <button v-if="hasLogs(node)" class="twg-node-action-btn" title="View logs" @click="$emit('select', node)">
                                <i class="fa-solid fa-terminal"></i>
                            </button>
                            <button class="twg-node-action-btn" title="Run now" @click="$emit('run', node)">
                                <i class="fa-solid fa-play"></i>
                            </button>
                            <button class="twg-node-action-btn" title="Edit" @click="$emit('edit', node)">
                                <i class="fa-solid fa-pen"></i>
                            </button>
                            <button class="twg-node-action-btn twg-node-action-btn--danger" title="Delete" @click="$emit('delete', node)">
                                <i class="fa-solid fa-trash"></i>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <p v-if="columns.length === 0" class="text-muted small text-center py-4 mb-0">No tasks to visualize yet.</p>
    </div>
    `,
};

export default TaskWorkflowGraph;
