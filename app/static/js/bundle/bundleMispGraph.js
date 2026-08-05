// ─────────────────────────────────────────────────────────────────────────────
//  bundleMispGraph.js — MISP event graph for Rulezet bundle/rule detail pages.
//  Parses the Rulezet MISP JSON structure and renders it with Pivotick directly.
//  Call initBundleGraph(containerId, jsonText, { graphType }) after the
//  container is visible.
//
//  Node/edge look (shape, color, icon, size) is NOT hardcoded here — it's
//  fetched from /pivotick/style/<graphType> ('rule' or 'bundle'), which an
//  admin can customize at /admin/pivotick. See app/features/pivotick/.
// ─────────────────────────────────────────────────────────────────────────────

import { fetchPivotickStyle, buildNodeStyleMap, edgeStyleFor, isDarkMode } from '../pivotick/pivotickStyle.js'

// Raw rule content: too large to display or add as nodes.
const SKIP_CONTENT_RELATIONS = new Set(['yara', 'nse', 'suricata', 'snort', 'sigma', 'zeek'])

// Name attributes already used as the rule node label — skip as property nodes.
const SKIP_NAME_RELATIONS = new Set([
    'yara-rule-name', 'nse-script-name',
    'suricata-rule-name', 'snort-rule-name', 'zeek-script-name',
])

// Attributes to expand as leaf property nodes for each parent object type.
const BUNDLE_PROP_ATTRS = ['author', 'description', 'date']
const META_PROP_ATTRS   = ['format', 'author', 'version', 'license', 'source', 'description']

export const GRAPH_CONFIG = {
    maxNodes: 2000,
    layout: { type: 'force' },
    pivotickUI: { mode: 'full', sidebar: { collapsed: 'auto' } },
}

// Track live Pivotick instances and the theme observer so we can clean up.
const _instances = new Map()  // containerId → { pivotick, jsonText }
let _themeObserver = null

// ─────────────────────────────────────────────────────────────────────────────
//  Parsing helpers
// ─────────────────────────────────────────────────────────────────────────────

// Prefer yara-rule-name / nse-script-name over the MISP template description
// which is identical for every yara/nse object and causes all rule nodes to
// collapse on top of each other in the graph.
function _getRuleLabel(ruleObj) {
    const attrs = ruleObj.Attribute || []
    const nameAttr = attrs.find(a =>
        a.object_relation.endsWith('-rule-name') ||
        a.object_relation.endsWith('-script-name')
    )
    if (nameAttr?.value) return nameAttr.value
    const contentAttr = attrs.find(a => ['suricata', 'snort'].includes(a.object_relation))
    const sid = contentAttr?.value?.match(/sid:(\d+)/)?.[1]
    if (sid) return `${ruleObj.name} sid:${sid}`
    return ruleObj.name
}

function _attr(obj, relation) {
    return (obj.Attribute || []).find(a => a.object_relation === relation)?.value ?? null
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public: parseMispBundle
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Parse a Rulezet MISP event JSON into Pivotick { nodes, edges }.
 *
 * Graph hierarchy:
 *   Bundle ──contains──► Metadata ──contains──► Rule
 *          ──tagged────► Tag
 *          ──property──► (author / description / date)
 *          Metadata ───► (format / author / version / license / source / description)
 *          Rule ────────► (any non-content, non-name attribute)
 *
 * Every edge carries a `type` used purely for style lookup (contains / related-to
 * / tagged / property) — its `label` keeps the original, more descriptive text.
 */
export function parseMispBundle(json) {
    const nodes = [], edges = []
    const ev = json?.Event ?? json

    const objByUuid  = {}
    const attrByUuid = {}
    ;(ev.Attribute || []).forEach(a => { attrByUuid[a.uuid] = a })
    ;(ev.Object    || []).forEach(o => { objByUuid[o.uuid]  = o })

    const seen = new Set()
    function addNode(n) { if (!seen.has(n.id)) { seen.add(n.id); nodes.push(n) } }

    // Helper: create leaf property nodes attached to a parent node
    function _addPropNodes(parentId, obj, attrKeys) {
        for (const key of attrKeys) {
            const val = _attr(obj, key)
            if (!val) continue
            const propId = `${parentId}_prop_${key}`
            addNode({
                id: propId,
                data: {
                    label: String(val).substring(0, 38),
                    sublabel: key,
                    type: 'property',
                    raw: { key, value: val },
                },
            })
            edges.push({ from: parentId, to: propId, data: { label: key, type: 'property' } })
        }
    }

    // Helper: create ATT&CK technique leaf nodes attached to a parent node.
    // Sourced from an object's "Attribute" array, same as any other MISP
    // object attribute (object_relation "attack-id" — see
    // create_rulezet_metadata_misp_object in app/features/misp/rule/misp_object.py,
    // added the same way "cve-id" already is).
    function _addAttackNodes(parentId, attributes) {
        for (const attr of (attributes || [])) {
            if (attr.object_relation !== 'attack-id' || !attr.value) continue
            const techId = `${parentId}_attack_${attr.uuid}`
            addNode({
                id: techId,
                data: { label: attr.value, sublabel: 'ATT&CK', type: 'attack', raw: attr },
            })
            edges.push({ from: parentId, to: techId, data: { label: 'uses', type: 'attack' } })
        }
    }

    // Helper: create property nodes from a rule's Attribute array,
    // skipping raw content and name attributes already used as the node label.
    function _addRulePropNodes(ruleId, ruleObj) {
        for (const attr of (ruleObj.Attribute || [])) {
            if (SKIP_CONTENT_RELATIONS.has(attr.object_relation)) continue
            if (SKIP_NAME_RELATIONS.has(attr.object_relation)) continue
            if (!attr.value) continue
            const propId = `${ruleId}_prop_${attr.object_relation}`
            addNode({
                id: propId,
                data: {
                    label: String(attr.value).substring(0, 38),
                    sublabel: attr.object_relation,
                    type: 'property',
                    raw: attr,
                },
            })
            edges.push({ from: ruleId, to: propId, data: { label: attr.object_relation, type: 'property' } })
        }
    }

    const bundleObj = (ev.Object || []).find(o => o.name === 'rulezet-bundle')

    if (bundleObj) {
        const bName   = _attr(bundleObj, 'name')  || 'Bundle'
        const bAuthor = _attr(bundleObj, 'author') || ''
        addNode({
            id: bundleObj.uuid,
            data: { label: bName.substring(0, 38), sublabel: bAuthor || 'Bundle', type: 'bundle', raw: bundleObj },
        })

        // Bundle-level property nodes (author, description, date)
        _addPropNodes(bundleObj.uuid, bundleObj, BUNDLE_PROP_ATTRS)

        ;(bundleObj.ObjectReference || []).forEach(ref => {
            const rel = ref.relationship_type
            const tgt = ref.referenced_uuid

            if (rel === 'contains' && objByUuid[tgt]) {
                const meta   = objByUuid[tgt]
                const title  = _attr(meta, 'title')  || meta.name
                const format = _attr(meta, 'format') || ''
                addNode({
                    id: meta.uuid,
                    data: { label: title.substring(0, 34), sublabel: format || 'metadata', type: 'metadata', raw: meta },
                })
                edges.push({ from: bundleObj.uuid, to: meta.uuid, data: { label: 'contains', type: 'contains' } })

                // Metadata-level property nodes (format, author, version, license, source, description)
                _addPropNodes(meta.uuid, meta, META_PROP_ATTRS)

                ;(meta.ObjectReference || []).forEach(mref => {
                    const ruleObj = objByUuid[mref.referenced_uuid]
                    if (!ruleObj) return
                    const ruleLabel = _getRuleLabel(ruleObj)
                    addNode({
                        id: ruleObj.uuid,
                        data: { label: ruleLabel.substring(0, 38), sublabel: ruleObj.name, type: 'rule', raw: ruleObj },
                    })
                    edges.push({
                        from: meta.uuid, to: ruleObj.uuid,
                        data: { label: mref.relationship_type || 'related-to', type: 'contains' },
                    })

                    // Rule-level property nodes (any non-content, non-name attribute)
                    _addRulePropNodes(ruleObj.uuid, ruleObj)

                    // ATT&CK techniques used by this rule (stored as "attack-id"
                    // attributes on the metadata object, same as "cve-id")
                    _addAttackNodes(ruleObj.uuid, meta.Attribute)
                })

            } else if (rel === 'related-to' && attrByUuid[tgt]) {
                const attr = attrByUuid[tgt]
                addNode({
                    id: attr.uuid,
                    data: { label: String(attr.value || attr.type).substring(0, 28), sublabel: attr.type, type: 'vulnerability', raw: attr },
                })
                edges.push({ from: bundleObj.uuid, to: attr.uuid, data: { label: rel, type: 'related-to' } })
            }
        })

        // Tags connected to the bundle
        ;(ev.Tag || []).forEach((tag, i) => {
            const id = 'tag_' + i
            addNode({ id, data: { label: String(tag.name || 'tag').substring(0, 30), sublabel: 'tag', type: 'tag', raw: tag } })
            edges.push({ from: bundleObj.uuid, to: id, data: { label: 'tagged', type: 'tagged' } })
        })

    } else {
        // Fallback — no rulezet-bundle object, flat render of everything
        const evId = 'ev'
        addNode({ id: evId, data: { label: String(ev.info || 'Event').substring(0, 38), sublabel: 'event', type: 'bundle', raw: ev } })
        ;(ev.Object || []).forEach((obj, i) => {
            const objId = obj.uuid || ('o' + i)
            addNode({ id: objId, data: { label: obj.name, sublabel: obj['meta-category'] || '', type: 'metadata', raw: obj } })
            edges.push({ from: evId, to: objId, data: { label: '', type: 'contains' } })

            // ATT&CK techniques used by this rule ("attack-id" attributes on the metadata object)
            _addAttackNodes(objId, obj.Attribute)
        })
        ;(ev.Attribute || []).forEach((attr, i) => {
            addNode({ id: attr.uuid || ('a' + i), data: { label: String(attr.value || '').substring(0, 26), sublabel: attr.type, type: 'vulnerability', raw: attr } })
            edges.push({ from: evId, to: attr.uuid || ('a' + i), data: { label: '', type: 'related-to' } })
        })
        ;(ev.Tag || []).forEach((tag, i) => {
            addNode({ id: 'tag_' + i, data: { label: String(tag.name || '').substring(0, 28), sublabel: 'tag', type: 'tag', raw: tag } })
            edges.push({ from: evId, to: 'tag_' + i, data: { label: 'tagged', type: 'tagged' } })
        })
    }

    return { nodes, edges }
}

// ─────────────────────────────────────────────────────────────────────────────
//  UI helpers
// ─────────────────────────────────────────────────────────────────────────────

function _nodeProperties(node) {
    const d   = node.getData()
    const raw = d?.raw ?? {}
    const props = []

    if (raw.key !== undefined) {
        // Property leaf node — show key + full value
        props.push({ name: raw.key, value: String(raw.value ?? '') })
    } else if (Array.isArray(raw.Attribute)) {
        for (const attr of raw.Attribute) {
            if (SKIP_CONTENT_RELATIONS.has(attr.object_relation)) continue
            const val = attr.value
            if (val === null || val === undefined || val === '') continue
            props.push({ name: attr.object_relation || attr.type, value: String(val).substring(0, 200) })
        }
    } else {
        if (raw.value !== undefined) props.push({ name: 'Value',    value: String(raw.value).substring(0, 200) })
        if (raw.name)                props.push({ name: 'Name',     value: raw.name })
        if (raw.type)                props.push({ name: 'Type',     value: raw.type })
        if (raw.category)            props.push({ name: 'Category', value: raw.category })
        if (raw.colour)              props.push({ name: 'Colour',   value: raw.colour })
    }

    return props.filter(p => p.value !== '')
}

function _showSpinner(container, message) {
    container.innerHTML =
        `<div style="display:flex;align-items:center;justify-content:center;height:100%;gap:.75rem;
                     color:var(--subtle-text-color,#6c757d);font-size:.875rem;">
            <div class="spinner-border spinner-border-sm text-primary" role="status"></div>
            <span>${message}</span>
        </div>`
}

// Apply per-type edge styling (from the fetched config) onto parsed edges in place.
function _applyEdgeStyles(edges, edgeConfig, dark) {
    for (const edge of edges) {
        const type = edge.data?.type
        edge.style = edgeStyleFor(edgeConfig, type, dark)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public: initBundleGraph
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Render the MISP bundle graph inside `containerId`.
 * Must be called when the container is visible (tab shown).
 *
 * @param {string} containerId  DOM id of the target div
 * @param {string} jsonText     Raw JSON string of the MISP event
 * @param {object} [opts]       Optional overrides: { sizeScale, graphType }
 *   graphType: 'bundle' (default) or 'rule' — selects which admin-configurable
 *   style (/pivotick/style/<graphType>) to render with.
 */
export function initBundleGraph(containerId, jsonText, opts = {}) {
    const container = document.getElementById(containerId)
    if (!container) return

    // Destroy any existing Pivotick instance for this container.
    const prev = _instances.get(containerId)
    if (prev?.destroy) { try { prev.destroy() } catch {} }
    _instances.delete(containerId)

    // Disconnect any running theme observer before setting a new one.
    if (_themeObserver) { _themeObserver.disconnect(); _themeObserver = null }

    // Load pivotick.iife.js if not yet present, then poll until window.Pivotick is ready.
    if (typeof window.Pivotick !== 'function') {
        _showSpinner(container, 'Loading Pivotick…')

        if (!document.querySelector('script[data-pivotick]')) {
            const s = document.createElement('script')
            s.src = '/static/js/pivotick.iife.js'
            s.dataset.pivotick = '1'
            document.head.appendChild(s)
        }

        let attempts = 0
        const poll = setInterval(() => {
            attempts++
            if (typeof window.Pivotick === 'function') {
                clearInterval(poll)
                initBundleGraph(containerId, jsonText, opts)
            } else if (attempts > 50) {
                clearInterval(poll)
                container.innerHTML = '<p style="padding:2rem;text-align:center;color:#888">Could not load Pivotick.</p>'
            }
        }, 200)
        return
    }

    _showSpinner(container, 'Parsing MISP event…')

    const graphType = opts.graphType === 'rule' ? 'rule' : 'bundle'

    Promise.all([
        Promise.resolve().then(() => {
            try { return parseMispBundle(JSON.parse(jsonText)) } catch { return null }
        }),
        fetchPivotickStyle(graphType),
    ]).then(([parsed, styleConfig]) => {
        if (!parsed) {
            container.innerHTML = '<p style="padding:2rem;text-align:center;color:#888">Could not parse MISP JSON.</p>'
            return
        }

        if (!parsed.nodes.length) {
            container.innerHTML = '<p style="padding:2rem;text-align:center;color:#888">No graph data found.</p>'
            return
        }

        const { maxNodes, layout, pivotickUI } = GRAPH_CONFIG
        const dark = isDarkMode()
        const nodeStyles = buildNodeStyleMap(styleConfig.nodes, dark, opts.sizeScale ?? 1)
        _applyEdgeStyles(parsed.edges, styleConfig.edges, dark)

        if (parsed.nodes.length > maxNodes) {
            const degree = {}
            for (const e of parsed.edges) {
                degree[e.from] = (degree[e.from] || 0) + 1
                degree[e.to]   = (degree[e.to]   || 0) + 1
            }
            parsed.nodes.sort((a, b) => (degree[b.id] || 0) - (degree[a.id] || 0))
            const kept = new Set(parsed.nodes.slice(0, maxNodes).map(n => n.id))
            parsed.nodes = parsed.nodes.filter(n => kept.has(n.id))
            parsed.edges = parsed.edges.filter(e => kept.has(e.from) && kept.has(e.to))
        }

        container.innerHTML = ''

        const instance = new window.Pivotick(container, parsed, {
            isDirected: true,
            layout,
            simulation: {
                useWorker: false,
                warmupTicks: parsed.nodes.length > 200 ? 0 : 'auto',
            },
            render: {
                nodeTypeAccessor: (node) => node.getData()?.type ?? '_default',
                nodeStyleMap: nodeStyles,
                defaultNodeStyle: nodeStyles['_default'],
                defaultEdgeStyle: { markerEnd: 'arrow' },
                nodeHeaderMap: {
                    title:    (node) => node.getData()?.label    ?? '',
                    subtitle: (node) => node.getData()?.sublabel ?? '',
                },
            },
            UI: {
                ...pivotickUI,
                theme: dark ? 'dark' : 'light',
                mainHeader: {
                    nodeHeaderMap: {
                        title:    (node) => node.getData()?.label    ?? String(node.id),
                        subtitle: (node) => node.getData()?.sublabel ?? node.getData()?.type ?? '',
                    },
                    edgeHeaderMap: {
                        title:    (edge) => edge.getData()?.label || 'Relationship',
                        subtitle: (edge) => `${edge.from} → ${edge.to}`,
                    },
                },
                propertiesPanel: {
                    nodePropertiesMap: (node) => _nodeProperties(node),
                    edgePropertiesMap: (edge) => [
                        { name: 'Relationship', value: edge.getData()?.label || '—' },
                        { name: 'From',         value: String(edge.from) },
                        { name: 'To',           value: String(edge.to)   },
                    ],
                },
                tooltip: {
                    nodeHeaderMap: {
                        title:    (node) => node.getData()?.label    ?? '',
                        subtitle: (node) => node.getData()?.sublabel ?? '',
                    },
                },
                contextMenu: {
                    menuNode: {
                        topbar: [{
                            text: 'Copy label',
                            iconClass: 'fas fa-copy',
                            onclick: (_evt, node) => {
                                navigator.clipboard.writeText(node.getData()?.label ?? '').catch(() => {})
                            },
                        }],
                        menu: [{
                            text: 'Open raw JSON',
                            iconClass: 'fas fa-code',
                            onclick: (_evt, node) => {
                                const raw = node.getData()?.raw ?? {}
                                const win = window.open('', '_blank')
                                win.document.write(
                                    `<html><body style="margin:0;background:#1e1e1e;color:#d4d4d4">` +
                                    `<pre style="font-family:monospace;font-size:13px;padding:1.5rem;white-space:pre-wrap;word-break:break-all">` +
                                    `${JSON.stringify(raw, null, 2)}</pre></body></html>`
                                )
                            },
                        }],
                    },
                },
            },
        })

        _instances.set(containerId, instance)

        // Re-render with new colors whenever the user toggles dark/light mode.
        _themeObserver = new MutationObserver(() => {
            _themeObserver.disconnect()
            _themeObserver = null
            initBundleGraph(containerId, jsonText, opts)
        })
        _themeObserver.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['class'],
        })
    })
}
