/**
 * TaskWorkflowGraph — lightweight pipeline/DAG visualization for the Admin
 * Task Scheduler, modeled on GitHub Actions' workflow graph: tasks laid out
 * in fixed columns by dependency depth (not force-directed — PivoTick was
 * considered but its force-directed layout is unstable/organic, the wrong
 * fit for a left-to-right pipeline where read order matters). Phase 1's
 * dependency model is single-parent only, so this is always a forest of
 * trees — no cycle handling needed beyond the visited-set safety net below.
 *
 * Props:
 *   schedules  — full (unpaginated) array of schedule objects, as returned
 *                by GET /admin/tasks/list (needs id, depends_on_schedule_id).
 *   taskTypes  — the TASK_TYPES registry (for icon/label per task_type).
 * Emits:
 *   'select' (schedule) — a node was clicked; the page opens its edit modal.
 */
const TaskWorkflowGraph = {
    props: {
        schedules: { type: Array, default: () => [] },
        taskTypes: { type: Object, default: () => ({}) },
    },
    emits: ['select'],
    delimiters: ['[[', ']]'],
    data() {
        return {
            edges: [],       // [{ d: 'M...', color }]
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

            const depthOf = new Map();
            const cols = [];
            const visit = (node, depth, seen) => {
                if (seen.has(node.id)) return; // safety net — Phase 1 forbids cycles server-side
                seen.add(node.id);
                depthOf.set(node.id, depth);
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
        statusClass(s) {
            if (!s.is_active) return 'twg-node--paused';
            if (s.last_run_status === 'failed') return 'twg-node--failed';
            return 'twg-node--active';
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
                edges.push({
                    id: `${s.depends_on_schedule_id}-${s.id}`,
                    d: `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`,
                    color,
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
                <path v-for="e in edges" :key="e.id" :d="e.d" :stroke="e.color" fill="none" stroke-width="2" opacity="0.8"></path>
            </svg>
            <div class="twg-columns">
                <div v-for="(col, depth) in columns" :key="depth" class="twg-column">
                    <div v-for="node in col" :key="node.id"
                         :ref="el => setNodeRef(node.id, el)"
                         class="twg-node" :class="statusClass(node)"
                         @click="$emit('select', node)">
                        <div class="twg-node-icon"><i :class="typeIcon(node.task_type)"></i></div>
                        <div class="twg-node-body">
                            <div class="twg-node-title">[[ node.title ]]</div>
                            <div class="twg-node-sub">[[ typeLabel(node.task_type) ]]</div>
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
