// ─────────────────────────────────────────────────────────────────────────────
//  attackGraph.js — Global ATT&CK coverage graph (Tactic → Technique → Sub-technique).
//  Renders the /attack/heatmap_data payload with Pivotick.
//  Call initAttackGraph(containerId, coverage) only when the graph view is shown —
//  it lazy-loads pivotick.iife.js on first call, it is not bundled on the page.
//
//  Node/edge look (shape, icon, size range, tactic color palette) is NOT
//  hardcoded here — it's fetched from /pivotick/style/attack, which an admin
//  can customize at /admin/pivotick. See app/features/pivotick/. Technique and
//  sub-technique nodes always inherit their parent tactic's resolved color, so
//  a tactic's cluster still reads as one visual group.
// ─────────────────────────────────────────────────────────────────────────────

import { fetchPivotickStyle, isDarkMode, edgeStyleFor } from '../pivotick/pivotickStyle.js'

const _TACTIC_ORDER = [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact',
]

const _instances = new Map()
let _themeObserver = null

function _clamp(n, min, max) {
    return Math.max(min, Math.min(max, n))
}

function _showSpinner(container, message) {
    container.innerHTML =
        `<div style="display:flex;align-items:center;justify-content:center;height:100%;gap:.75rem;
                     color:var(--subtle-text-color,#6c757d);font-size:.875rem;">
            <div class="spinner-border spinner-border-sm text-primary" role="status"></div>
            <span>${message}</span>
        </div>`
}

function _tacticStyle(cfg, dark) {
    const t = (cfg?.nodes?.types?.tactic) || {}
    const palette = (dark ? t.palette_dark : t.palette) || []
    return {
        shape:    t.shape || 'hexagon',
        icon:     t.icon || undefined,
        sizeMin:  t.size_min ?? 30,
        sizeMax:  t.size_max ?? 56,
        palette,
        fallbackColor: (dark ? t.dark_color : t.color) || '#0ea5e9',
    }
}

function _techStyle(cfg, key, defaultSizeMin, defaultSizeMax) {
    const t = (cfg?.nodes?.types?.[key]) || {}
    return {
        shape:   t.shape || 'circle',
        icon:    t.icon || undefined,
        sizeMin: t.size_min ?? defaultSizeMin,
        sizeMax: t.size_max ?? defaultSizeMax,
    }
}

function _tacticColor(tacticStyle, tacticKey) {
    if (!tacticStyle.palette.length) return tacticStyle.fallbackColor
    const idx = Math.max(0, _TACTIC_ORDER.indexOf(tacticKey))
    return tacticStyle.palette[idx % tacticStyle.palette.length]
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public: buildAttackGraphData
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Turn the /attack/heatmap_data payload into a Pivotick { nodes, edges } graph.
 *
 * Hierarchy:
 *   Tactic (hub) ──covers──────────► Technique
 *   Technique    ──sub-technique──► Sub-technique
 *
 * @param {object} coverage    The /attack/heatmap_data payload
 * @param {object} styleConfig Resolved /pivotick/style/attack config
 * @param {boolean} dark       Whether to use the dark-mode color variants
 */
export function buildAttackGraphData(coverage, styleConfig, dark) {
    const nodes = [], edges = []
    const seen = new Set()
    function addNode(n) { if (!seen.has(n.id)) { seen.add(n.id); nodes.push(n) } }

    const tacticStyle = _tacticStyle(styleConfig, dark)
    const techStyle    = _techStyle(styleConfig, 'technique', 10, 30)
    const subStyle      = _techStyle(styleConfig, 'subtechnique', 7, 20)

    const tactics = (coverage?.tactics || []).filter(t => t.covered)

    // technique id -> { count, color, tacticKeys: [], rules, parentAdded }
    const techMap = new Map()

    for (const tactic of tactics) {
        const color = _tacticColor(tacticStyle, tactic.key)
        const tacticId = `tactic_${tactic.key}`
        addNode({
            id: tacticId,
            data: {
                label: tactic.label,
                sublabel: `${tactic.rule_count} rule${tactic.rule_count === 1 ? '' : 's'}`,
                type: 'tactic',
                raw: tactic,
            },
            style: {
                shape: tacticStyle.shape,
                color,
                size: _clamp(tacticStyle.sizeMin + Math.round(Math.sqrt(tactic.rule_count) * 3), tacticStyle.sizeMin, tacticStyle.sizeMax),
                iconClass: tacticStyle.icon,
            },
        })

        for (const tech of (tactic.techniques || [])) {
            if (!tech.count) continue
            if (!techMap.has(tech.id)) {
                techMap.set(tech.id, { count: 0, color, tacticKeys: [], tacticIds: [], rules: tech.rules || [] })
            }
            const entry = techMap.get(tech.id)
            entry.count = Math.max(entry.count, tech.count)
            entry.tacticKeys.push(tactic.key)
            entry.tacticIds.push(tacticId)
        }
    }

    // Technique + sub-technique nodes, sized by how many rules cover them.
    for (const [id, entry] of techMap) {
        const isSub = id.includes('.')
        const s = isSub ? subStyle : techStyle
        addNode({
            id,
            data: {
                label: id,
                sublabel: `${entry.count} rule${entry.count === 1 ? '' : 's'}`,
                type: isSub ? 'subtechnique' : 'technique',
                raw: entry,
            },
            style: {
                shape: s.shape,
                color: entry.color,
                size: isSub
                    ? _clamp(s.sizeMin + Math.round(Math.sqrt(entry.count) * 2.5), s.sizeMin, s.sizeMax)
                    : _clamp(s.sizeMin + Math.round(Math.sqrt(entry.count) * 4), s.sizeMin, s.sizeMax),
                iconClass: s.icon,
            },
        })

        if (isSub) {
            // Prefer hanging off the parent technique for a clean 3-tier layout;
            // fall back to the tactic hub if the parent technique itself has 0 rules.
            const parentId = id.split('.')[0]
            if (techMap.has(parentId)) {
                edges.push({ from: parentId, to: id, data: { label: 'sub-technique', type: 'sub-technique' } })
            } else {
                edges.push({ from: entry.tacticIds[0], to: id, data: { label: 'covers', type: 'covers' } })
            }
        } else {
            entry.tacticIds.forEach(tacticId => {
                edges.push({ from: tacticId, to: id, data: { label: 'covers', type: 'covers' } })
            })
        }
    }

    for (const edge of edges) {
        edge.style = edgeStyleFor(styleConfig?.edges, edge.data?.type, dark)
    }

    return { nodes, edges }
}

function _nodeProperties(node) {
    const d = node.getData()
    const raw = d?.raw ?? {}
    const props = []
    if (d?.type === 'tactic') {
        props.push({ name: 'Tactic', value: raw.label || '' })
        props.push({ name: 'Techniques covered', value: String(raw.technique_count ?? 0) })
        props.push({ name: 'Rules', value: String(raw.rule_count ?? 0) })
    } else {
        props.push({ name: 'Technique', value: d?.label || '' })
        props.push({ name: 'Rules', value: String(raw.count ?? 0) })
        for (const r of (raw.rules || []).slice(0, 10)) {
            props.push({ name: 'Rule', value: r.name || r.uuid || '' })
        }
    }
    return props.filter(p => p.value !== '')
}

// Pure helper — given the plain data + id of a selected node (as handed to
// opts.onSelect), returns the rules_list URL it maps to, or null. Kept
// outside Pivotick so the caller's own "View rules" button can use it
// without touching Pivotick's internal panels.
export function rulesUrlForSelection(nodeData, nodeId) {
    if (!nodeData) return null
    if (nodeData.type === 'tactic') {
        const ids = (nodeData.raw?.techniques || []).filter(t => t.count > 0).map(t => t.id).join(',')
        return ids ? `/rule/rules_list?attacks=${ids}` : null
    }
    if (nodeData.type === 'technique' || nodeData.type === 'subtechnique') {
        return nodeId ? `/rule/rules_list?attacks=${nodeId}` : null
    }
    return null
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public: initAttackGraph
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Render the global ATT&CK graph inside `containerId`.
 * Must be called when the container is visible (view/tab shown) — lazily
 * injects pivotick.iife.js on first use so it never loads on page mount.
 *
 * Left untouched on purpose: no custom entry in Pivotick's own selection
 * panel/menu. We only listen for selection changes and hand the plain node
 * data back to the caller via opts.onSelect — the caller renders its own
 * "View rules" button (see rulesUrlForSelection) wherever it wants.
 *
 * @param {string} containerId    DOM id of the target div
 * @param {object} coverage       The /attack/heatmap_data payload
 * @param {object} [opts]
 * @param {(data: object|null, id: string|null) => void} [opts.onSelect]
 *        Called with (nodeData, nodeId) when a node is clicked, or (null, null)
 *        when the selection is cleared (canvas click).
 */
export function initAttackGraph(containerId, coverage, opts = {}) {
    const container = document.getElementById(containerId)
    if (!container) return

    const prev = _instances.get(containerId)
    if (prev?.destroy) { try { prev.destroy() } catch {} }
    _instances.delete(containerId)

    if (_themeObserver) { _themeObserver.disconnect(); _themeObserver = null }

    if (typeof window.Pivotick !== 'function') {
        _showSpinner(container, 'Loading graph engine…')

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
                initAttackGraph(containerId, coverage, opts)
            } else if (attempts > 50) {
                clearInterval(poll)
                container.innerHTML = '<p style="padding:2rem;text-align:center;color:#888">Could not load the graph engine.</p>'
            }
        }, 200)
        return
    }

    _showSpinner(container, 'Building coverage graph…')

    fetchPivotickStyle('attack').then((styleConfig) => {
        const dark = isDarkMode()
        const parsed = buildAttackGraphData(coverage, styleConfig, dark)

        if (!parsed.nodes.length) {
            container.innerHTML = '<p style="padding:2rem;text-align:center;color:#888">No ATT&CK coverage to graph yet.</p>'
            return
        }

        container.innerHTML = ''

        const instance = new window.Pivotick(container, parsed, {
            isDirected: true,
            layout: { type: 'force' },
            simulation: {
                useWorker: false,
                warmupTicks: parsed.nodes.length > 200 ? 0 : 'auto',
            },
            render: {
                defaultEdgeStyle: { markerEnd: 'arrow' },
                nodeHeaderMap: {
                    title:    (node) => node.getData()?.label    ?? '',
                    subtitle: (node) => node.getData()?.sublabel ?? '',
                },
            },
            UI: {
                mode: 'full',
                sidebar: { collapsed: 'auto' },
                mainHeader: {
                    nodeHeaderMap: {
                        title:    (node) => node.getData()?.label    ?? String(node.id),
                        subtitle: (node) => node.getData()?.sublabel ?? node.getData()?.type ?? '',
                    },
                },
                propertiesPanel: {
                    nodePropertiesMap: (node) => _nodeProperties(node),
                },
                tooltip: {
                    nodeHeaderMap: {
                        title:    (node) => node.getData()?.label    ?? '',
                        subtitle: (node) => node.getData()?.sublabel ?? '',
                    },
                },
            },
            callbacks: {
                // Just report the selection — no navigation, no Pivotick UI changes.
                onNodeClick: (_evt, node) => {
                    opts.onSelect?.(node.getData() ?? null, String(node.id))
                },
                onCanvasClick: () => {
                    opts.onSelect?.(null, null)
                },
            },
        })

        _instances.set(containerId, instance)

        _themeObserver = new MutationObserver(() => {
            _themeObserver.disconnect()
            _themeObserver = null
            initAttackGraph(containerId, coverage, opts)
        })
        _themeObserver.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['class'],
        })
    })
}

export function destroyAttackGraph(containerId) {
    const prev = _instances.get(containerId)
    if (prev?.destroy) { try { prev.destroy() } catch {} }
    _instances.delete(containerId)
}
