import TagBadge from './TagBadge.js';

const FamilyDrawer = {
    props: {
        source: { type: String, default: null },
        family: { type: String, default: null },
        csrfToken: { type: String, required: true },
        show: { type: Boolean, default: false },
        showNamespace: { type: Boolean, default: true },
    },
    emits: ['close', 'notify', 'refresh-main'],
    components: { TagBadge },
    setup(props, { emit }) {
        const { ref, watch, computed } = Vue;

        const tags = ref([]);
        const loading = ref(false);
        const selected = ref([]);
        const searchQ = ref('');

        watch(() => props.show, async (val) => {
            if (val) {
                selected.value = [];
                searchQ.value = '';
                await load();
            }
        });

        async function load() {
            if (!props.family) return;
            loading.value = true;
            try {
                const res = await fetch('/tags/get_family?' + new URLSearchParams({
                    family: props.family,
                    source: props.source || 'all',
                }));
                const data = await res.json();
                tags.value = data.tags || [];
            } catch (e) {
                emit('notify', 'Failed to load family tags', 'danger-subtle');
            } finally {
                loading.value = false;
            }
        }

        const filtered = computed(() => {
            if (!searchQ.value) return tags.value;
            const q = searchQ.value.toLowerCase();
            return tags.value.filter(t => t.name.toLowerCase().includes(q));
        });

        const shortTitle = computed(() => {
            if (!props.family) return 'Family';
            if (props.family.startsWith('misp-galaxy:')) return props.family.split(':')[1].toUpperCase();
            return props.family;
        });

        function toggleSelect(id) {
            const i = selected.value.indexOf(id);
            if (i >= 0) selected.value.splice(i, 1);
            else selected.value.push(id);
        }
        function isSelected(id) { return selected.value.includes(id); }
        function toggleAll(checked) {
            selected.value = checked ? filtered.value.map(t => t.id) : [];
        }
        const allSelected = computed(() =>
            filtered.value.length > 0 && filtered.value.every(t => selected.value.includes(t.id))
        );

        async function deleteSelected() {
            if (!selected.value.length) return;
            if (!confirm(`Delete ${selected.value.length} tag(s) from "${shortTitle.value}"?`)) return;
            const res = await fetch('/tags/remove_tags_bulk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                body: JSON.stringify({ ids: selected.value }),
            });
            const data = await res.json();
            emit('notify', data.message, res.ok ? 'success-subtle' : 'danger-subtle');
            if (res.ok) { selected.value = []; await load(); emit('refresh-main'); }
        }

        async function deleteFamily() {
            if (!confirm(`Delete ALL ${tags.value.length} tags from "${shortTitle.value}"? This cannot be undone.`)) return;
            const res = await fetch('/tags/delete_family', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                body: JSON.stringify({ family: props.family, source: props.source }),
            });
            const data = await res.json();
            emit('notify', data.message, res.ok ? 'success-subtle' : 'danger-subtle');
            if (res.ok) { emit('refresh-main'); emit('close'); }
        }

        async function toggleStatusSelected() {
            for (const id of selected.value) {
                const tag = tags.value.find(t => t.id === id);
                if (tag) await fetch('/tags/toggle_status?' + new URLSearchParams({ tag_uuid: tag.uuid }));
            }
            emit('notify', `Updated ${selected.value.length} tag(s)`, 'success-subtle');
            await load();
            emit('refresh-main');
        }

        function exportTags(list) {
            const blob = new Blob([JSON.stringify(list, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = Object.assign(document.createElement('a'), {
                href: url,
                download: `tags_${(props.family || 'export').replace(/[:=]/g, '_')}.json`,
            });
            a.click();
            URL.revokeObjectURL(url);
        }
        const exportSelected = () => exportTags(tags.value.filter(t => selected.value.includes(t.id)));
        const exportAll = () => exportTags(tags.value);

        // ── Inline styles (no external CSS required) ──────────────────────────
        const backdropStyle = {
            position: 'fixed', inset: '0', background: 'rgba(0,0,0,0.35)', zIndex: '1040',
        };
        const drawerStyle = {
            position: 'fixed', top: '0', right: '0', width: '440px', maxWidth: '95vw',
            height: '100vh', zIndex: '1050', display: 'flex', flexDirection: 'column',
            borderLeft: '1px solid var(--border-color, #dee2e6)',
            background: 'var(--card-bg-color, #fff)',
            boxShadow: '-8px 0 24px rgba(0,0,0,0.15)',
        };
        const drawerBodyStyle = {
            flex: '1', minHeight: '0', overflowY: 'auto',
        };
        const itemStyle = (sel) => ({
            cursor: 'pointer', borderRadius: '6px', border: '1px solid transparent',
            background: sel ? 'rgba(13,110,253,0.08)' : 'transparent',
        });

        return {
            tags, loading, selected, searchQ, filtered, shortTitle,
            toggleSelect, isSelected, toggleAll, allSelected,
            deleteSelected, deleteFamily, toggleStatusSelected,
            exportSelected, exportAll, load,
            backdropStyle, drawerStyle, drawerBodyStyle, itemStyle,
        };
    },
    template: `
        <teleport to="body">
            <div v-if="show" :style="backdropStyle" @click.self="$emit('close')"></div>
            <div v-if="show" :style="drawerStyle">

                <!-- Header -->
                <div class="d-flex align-items-center gap-2 p-3 border-bottom flex-shrink-0">
                    <div class="flex-grow-1 min-w-0">
                        <div class="d-flex align-items-center gap-2">
                            <i :class="source === 'Galaxy' ? 'fas fa-atom' : 'fas fa-list text-primary'" :style="source === 'Galaxy' ? { color: '#9b7ede' } : {}"></i>
                            <span class="fw-bold text-truncate" :title="family">{{ shortTitle }}</span>
                            <span class="badge bg-secondary rounded-pill">{{ tags.length }}</span>
                        </div>
                        <small class="text-muted text-truncate d-block" :title="family">{{ source }} · {{ family }}</small>
                    </div>
                    <button class="btn btn-sm btn-outline-secondary" @click="$emit('close')">
                        <i class="fas fa-times"></i>
                    </button>
                </div>

                <!-- Search -->
                <div class="p-3 border-bottom flex-shrink-0">
                    <div class="input-group input-group-sm">
                        <span class="input-group-text bg-transparent border-end-0"><i class="fas fa-search text-muted"></i></span>
                        <input type="text" v-model="searchQ" class="form-control border-start-0" placeholder="Filter within family…">
                    </div>
                </div>

                <!-- Action bar -->
                <div class="p-2 border-bottom d-flex gap-2 flex-wrap align-items-center flex-shrink-0" style="background: var(--light-bg-color, #f1f1f1)">
                    <input type="checkbox" class="form-check-input m-0" :checked="allSelected" @change="toggleAll($event.target.checked)">
                    <small class="text-muted me-auto">
                        {{ selected.length ? selected.length + ' selected' : filtered.length + ' tags' }}
                    </small>
                    <template v-if="selected.length > 0">
                        <button class="btn btn-sm btn-outline-success" @click="toggleStatusSelected" title="Toggle status"><i class="fas fa-toggle-on"></i></button>
                        <button class="btn btn-sm btn-outline-primary" @click="exportSelected" title="Export selected"><i class="fas fa-download"></i></button>
                        <button class="btn btn-sm btn-outline-danger" @click="deleteSelected" title="Delete selected"><i class="fas fa-trash"></i></button>
                    </template>
                    <template v-else>
                        <button class="btn btn-sm btn-outline-primary" @click="exportAll" title="Export all"><i class="fas fa-download me-1"></i>Export</button>
                        <button class="btn btn-sm btn-outline-danger" @click="deleteFamily" title="Delete entire family"><i class="fas fa-trash me-1"></i>Delete all</button>
                    </template>
                </div>

                <!-- Body -->
                <div :style="drawerBodyStyle" class="p-2">
                    <div v-if="loading" class="text-center py-4">
                        <div class="spinner-border spinner-border-sm text-primary"></div>
                    </div>
                    <div v-else-if="filtered.length === 0" class="text-center text-muted py-4 small">
                        <i class="fas fa-folder-open fa-2x d-block mb-2 opacity-25"></i>
                        No tags found in this family.
                    </div>
                    <div v-else>
                        <label
                            v-for="tag in filtered" :key="tag.uuid"
                            class="d-flex align-items-center gap-2 p-2 mb-1"
                            :style="itemStyle(isSelected(tag.id))"
                        >
                            <input type="checkbox" class="form-check-input flex-shrink-0 m-0"
                                :checked="isSelected(tag.id)" @change="toggleSelect(tag.id)">
                            <tag-badge :tag="tag" size="sm" :show-namespace="showNamespace"></tag-badge>
                            <span class="ms-auto badge rounded-pill"
                                :class="tag.is_active ? 'bg-success-subtle text-success' : 'bg-danger-subtle text-danger'">
                                {{ tag.is_active ? 'active' : 'off' }}
                            </span>
                        </label>
                    </div>
                </div>

            </div>
        </teleport>
    `
};

export default FamilyDrawer;