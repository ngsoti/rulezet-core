// ─────────────────────────────────────────────────────────────────────────────
//  adminStyleConfig.js — Vue logic for the /admin/pivotick page.
//  The markup lives in app/templates/pivotick/admin_style.html (Vue mounts in
//  place, same convention as config/settings.html); this module only exports
//  the data/computed/methods used to build the app.
// ─────────────────────────────────────────────────────────────────────────────

import { create_message } from '/static/js/toaster.js'
import SmartEditor from '/static/js/components/smart-editor.js'

const { createApp, reactive } = Vue

const SECTION_META = [
    { key: 'rule',   label: 'Rule graph',   icon: 'fa-solid fa-shield-halved',
      hint: 'The "Graph" tab on a rule detail page (bundleMispGraph.js).' },
    { key: 'bundle', label: 'Bundle graph', icon: 'fa-solid fa-box-archive',
      hint: 'The "Graph" tab on a bundle detail page (bundleMispGraph.js).' },
    { key: 'attack', label: 'ATT&CK graph', icon: 'fa-solid fa-crosshairs',
      hint: 'The "Graph" view of the MITRE ATT&CK heatmap (attackGraph.js). Technique/sub-technique color is always inherited from their parent tactic.' },
]

const SHAPES = ['circle', 'square', 'triangle', 'hexagon']

function newNodeTypeRow(graphKey) {
    if (graphKey === 'attack') {
        return { shape: 'circle', icon: '', size_min: 10, size_max: 24 }
    }
    return { shape: 'circle', color: '#64748b', dark_color: '#94a3b8', size: 16, icon: '' }
}

function newEdgeTypeRow() {
    return { color: '#94a3b8', dark_color: '#475569', width: 2, dashed: false }
}

function paletteToText(arr) {
    return (arr || []).join(', ')
}

function textToPalette(text) {
    return String(text || '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean)
}

function csrfHeader() {
    const el = document.getElementById('csrf_token')
    return { 'X-CSRFToken': el ? el.value : '' }
}

export function createPivotickAdminApp(initialConfigs, defaultConfigs) {
    return createApp({
        delimiters: ['[[', ']]'],

        components: { 'smart-editor': SmartEditor },

        data() {
            return {
                shapes: SHAPES,
                sections: SECTION_META.map(meta => reactive({
                    ...meta,
                    mode: 'form',            // 'form' | 'json'
                    config: initialConfigs[meta.key],
                    defaultConfig: defaultConfigs[meta.key],
                    jsonText: JSON.stringify(initialConfigs[meta.key], null, 2),
                    jsonError: '',
                    newNodeTypeName: '',
                    newEdgeTypeName: '',
                    saving: false,
                    savedAt: null,
                })),
            }
        },

        methods: {
            isAttack(section) { return section.key === 'attack' },

            setMode(section, mode) {
                if (mode === 'json') {
                    section.jsonText = JSON.stringify(section.config, null, 2)
                    section.jsonError = ''
                } else {
                    if (!this._applyJsonText(section)) return
                }
                section.mode = mode
            },

            addNodeType(section) {
                const name = section.newNodeTypeName.trim()
                if (!name) return
                if (section.config.nodes.types[name]) {
                    create_message(`Node type "${name}" already exists`, 'warning')
                    return
                }
                section.config.nodes.types[name] = newNodeTypeRow(section.key)
                section.newNodeTypeName = ''
            },

            removeNodeType(section, key) {
                delete section.config.nodes.types[key]
            },

            addEdgeType(section) {
                const name = section.newEdgeTypeName.trim()
                if (!name) return
                if (section.config.edges.types[name]) {
                    create_message(`Relation type "${name}" already exists`, 'warning')
                    return
                }
                section.config.edges.types[name] = newEdgeTypeRow()
                section.newEdgeTypeName = ''
            },

            removeEdgeType(section, key) {
                delete section.config.edges.types[key]
            },

            paletteText(type, field) {
                return paletteToText(type[field])
            },

            setPaletteText(type, field, text) {
                type[field] = textToPalette(text)
            },

            _applyJsonText(section) {
                try {
                    const parsed = JSON.parse(section.jsonText)
                    if (!parsed || typeof parsed !== 'object' || !parsed.nodes || !parsed.edges) {
                        throw new Error('JSON must contain "nodes" and "edges" keys')
                    }
                    section.config = parsed
                    section.jsonError = ''
                    return true
                } catch (e) {
                    section.jsonError = e.message
                    return false
                }
            },

            async save(section) {
                if (section.mode === 'json' && !this._applyJsonText(section)) {
                    create_message('Invalid JSON: ' + section.jsonError, 'danger')
                    return
                }
                section.saving = true
                try {
                    const res = await fetch(`/admin/pivotick/style/${section.key}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', ...csrfHeader() },
                        body: JSON.stringify(section.config),
                    })
                    const data = await res.json()
                    if (data.success) {
                        section.config = data.config
                        section.jsonText = JSON.stringify(data.config, null, 2)
                        section.savedAt = new Date().toLocaleTimeString()
                        create_message(`${section.label}: style saved`, 'success')
                    } else {
                        create_message(data.message || 'Error saving style', 'danger')
                    }
                } catch (e) {
                    create_message('Network error: ' + e.message, 'danger')
                } finally {
                    section.saving = false
                }
            },

            async reset(section) {
                if (!confirm(`Reset the "${section.label}" render to its default values?`)) return
                section.saving = true
                try {
                    const res = await fetch(`/admin/pivotick/style/${section.key}/reset`, {
                        method: 'POST',
                        headers: csrfHeader(),
                    })
                    const data = await res.json()
                    if (data.success) {
                        section.config = data.config
                        section.jsonText = JSON.stringify(data.config, null, 2)
                        section.jsonError = ''
                        create_message(`${section.label}: reset to default`, 'success')
                    } else {
                        create_message(data.message || 'Error resetting style', 'danger')
                    }
                } catch (e) {
                    create_message('Network error: ' + e.message, 'danger')
                } finally {
                    section.saving = false
                }
            },
        },
    })
}

export { SHAPES }
