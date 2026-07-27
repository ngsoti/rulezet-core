/**
 * meta-change-list.js — Renders a rule metadata diff (title/author/owner/tags/...)
 * as readable rows, instead of ever showing the raw old_snapshot/new_snapshot JSON.
 *
 * Props:
 *   changes  Array    Required. Output of the backend's `diff_rule_snapshots()`:
 *                      [{ field, label, type: 'scalar', old, new }, ...]
 *                      [{ field, label, type: 'list', added: [...], removed: [...] }, ...]
 *   compact  Boolean  Smaller variant for embedding inside a timeline row (default: false)
 *
 * Usage:
 *   import MetaChangeList from '/static/js/components/meta-change-list.js'
 *   <meta-change-list :changes="item.metadata_changes"></meta-change-list>
 */

const FIELD_ICONS = {
    title:       'fa-heading',
    author:      'fa-user-pen',
    owner:       'fa-user-shield',
    license:     'fa-scale-balanced',
    description: 'fa-align-left',
    status:      'fa-toggle-on',
    format:      'fa-file-code',
    version:     'fa-code-branch',
    source:      'fa-file-import',
    original_uuid: 'fa-fingerprint',
    tags:        'fa-tags',
    cve_ids:            'fa-bug',
    attack_techniques:  'fa-crosshairs',
}

function field_icon(field) {
    return FIELD_ICONS[field] || 'fa-pen'
}

export default {
    name: 'MetaChangeList',

    props: {
        changes: { type: Array,   default: () => [] },
        compact: { type: Boolean, default: false },
    },

    setup(props) {
        return { field_icon }
    },

    template: `
<div v-if="changes.length" class="mcl" :class="{ 'mcl--compact': compact }">
    <div v-for="c in changes" :key="c.field" class="mcl-row">
        <i :class="['fas', field_icon(c.field), 'mcl-icon']"></i>
        <span class="mcl-label">{{ c.label }}</span>

        <template v-if="c.type === 'list'">
            <span class="mcl-tags">
                <span v-for="t in c.added"   :key="'add-'+t" class="mcl-tag mcl-tag--added">+{{ t }}</span>
                <span v-for="t in c.removed" :key="'rem-'+t" class="mcl-tag mcl-tag--removed">-{{ t }}</span>
            </span>
        </template>
        <template v-else>
            <span class="mcl-old">{{ c.old || '—' }}</span>
            <i class="fas fa-arrow-right-long mcl-arrow"></i>
            <span class="mcl-new">{{ c.new || '—' }}</span>
        </template>
    </div>
</div>
    `,
}
