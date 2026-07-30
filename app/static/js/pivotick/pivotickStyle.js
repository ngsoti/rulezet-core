// ─────────────────────────────────────────────────────────────────────────────
//  pivotickStyle.js — shared helpers to turn an admin-configured PivoTick style
//  config (see app/features/pivotick/) into the node/edge style objects the
//  Pivotick renderer understands (nodeStyleMap / per-edge style).
//
//  Used by app/static/js/bundle/bundleMispGraph.js and
//  app/static/js/attack/attackGraph.js — kept independent from the pivotick
//  submodule and from any one feature so it survives both a PivoTick version
//  bump and future graph types.
// ─────────────────────────────────────────────────────────────────────────────

const _cache = new Map()  // graphType → Promise<config>

// Used only if the /pivotick/style/<type> request itself fails (e.g. offline).
// The server always returns a full config (falls back to its own built-in
// defaults when unset), so this is a last-resort, deliberately minimal.
const _FALLBACK_STYLE = {
    nodes: { default: { shape: 'circle', color: '#64748b', dark_color: '#94a3b8', size: 14, icon: null }, types: {} },
    edges: { default: { color: '#94a3b8', dark_color: '#475569', width: 2, dashed: false }, types: {} },
}

export function fetchPivotickStyle(graphType) {
    if (!_cache.has(graphType)) {
        _cache.set(graphType, fetch(`/pivotick/style/${graphType}`)
            .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
            .then(payload => payload.config || _FALLBACK_STYLE)
            .catch(() => _FALLBACK_STYLE))
    }
    return _cache.get(graphType)
}

export function isDarkMode() {
    if (document.documentElement.getAttribute('data-bs-theme') === 'dark') return true
    if (document.documentElement.classList.contains('dark-mode')) return true
    if (document.body.classList.contains('dark-mode')) return true
    return false
}

// Build a Pivotick `nodeStyleMap` (keyed by node type, plus `_default`) from a
// { default, types } node style config. Sizes are fixed per type here — graphs
// that scale node size dynamically (e.g. the ATT&CK coverage graph) read the
// config directly instead of going through this helper.
export function buildNodeStyleMap(nodesConfig, dark, sizeScale = 1) {
    const cfg   = nodesConfig || {}
    const def   = cfg.default || {}
    const types = cfg.types   || {}

    const build = (t) => ({
        shape:     t.shape || 'circle',
        color:     (dark ? t.dark_color : t.color) || t.color || '#64748b',
        size:      Math.round((t.size ?? 14) * sizeScale),
        iconClass: t.icon || undefined,
    })

    const map = { _default: build(def) }
    for (const [key, t] of Object.entries(types)) {
        map[key] = build(t)
    }
    return map
}

// Resolve the Pivotick per-edge `style` object for a given edge `type`
// ('contains' / 'related-to' / 'tagged' / 'property' / 'covers' / ...),
// falling back to the graph's default edge style.
export function edgeStyleFor(edgesConfig, type, dark) {
    const cfg = edgesConfig || {}
    const t   = (type && cfg.types && cfg.types[type]) || cfg.default || {}
    return {
        strokeColor: (dark ? t.dark_color : t.color) || t.color || '#94a3b8',
        strokeWidth: t.width ?? 2,
        dashed:      !!t.dashed,
    }
}
