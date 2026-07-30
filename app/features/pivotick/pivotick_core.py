import copy

from ... import db
from ...core.db_class.db import PivotickGraphStyle


# ── Built-in defaults ─────────────────────────────────────────────────────────
# These are the fallback used when an admin hasn't customized a graph yet (or
# used a "reset" action), AND the fallback baked into the front-end JS in case
# the /pivotick/style/<type> fetch itself fails. Living in Python (not inside
# app/modules/pivotick) they are never touched by a PivoTick submodule update.

_TACTIC_PALETTE_LIGHT = [
    '#0ea5e9', '#14b8a6', '#22c55e', '#84cc16', '#eab308', '#f97316', '#ef4444',
    '#ec4899', '#a855f7', '#6366f1', '#3b82f6', '#06b6d4', '#f43f5e', '#7c3aed',
]
_TACTIC_PALETTE_DARK = [
    '#38bdf8', '#2dd4bf', '#4ade80', '#a3e635', '#facc15', '#fb923c', '#f87171',
    '#f472b6', '#c084fc', '#818cf8', '#60a5fa', '#22d3ee', '#fb7185', '#a78bfa',
]

_RULE_BUNDLE_STYLE = {
    'nodes': {
        'default': {'shape': 'circle', 'color': '#64748b', 'dark_color': '#94a3b8', 'size': 14, 'icon': None},
        'types': {
            'bundle':        {'shape': 'hexagon',  'color': '#2563eb', 'dark_color': '#60a5fa', 'size': 42, 'icon': 'fa-solid fa-box-archive'},
            'metadata':      {'shape': 'square',   'color': '#16a34a', 'dark_color': '#4ade80', 'size': 28, 'icon': 'fa-solid fa-file-lines'},
            'rule':          {'shape': 'circle',   'color': '#ea580c', 'dark_color': '#fb923c', 'size': 22, 'icon': 'fa-solid fa-shield-halved'},
            'property':      {'shape': 'circle',   'color': '#94a3b8', 'dark_color': '#475569', 'size': 12, 'icon': None},
            # circle, not triangle: a triangle's narrow area clips the FontAwesome glyph.
            'vulnerability': {'shape': 'circle',   'color': '#dc2626', 'dark_color': '#f87171', 'size': 20, 'icon': 'fa-solid fa-bug'},
            'tag':           {'shape': 'circle',   'color': '#9333ea', 'dark_color': '#c084fc', 'size': 16, 'icon': 'fa-solid fa-tag'},
            'attack':        {'shape': 'circle',   'color': '#0891b2', 'dark_color': '#22d3ee', 'size': 18, 'icon': 'fa-solid fa-crosshairs'},
        },
    },
    'edges': {
        'default': {'color': '#94a3b8', 'dark_color': '#475569', 'width': 2, 'dashed': False},
        'types': {
            'contains':   {'color': '#2563eb', 'dark_color': '#60a5fa', 'width': 2, 'dashed': False},
            'related-to': {'color': '#dc2626', 'dark_color': '#f87171', 'width': 2, 'dashed': True},
            'tagged':     {'color': '#9333ea', 'dark_color': '#c084fc', 'width': 1, 'dashed': True},
            'property':   {'color': '#94a3b8', 'dark_color': '#475569', 'width': 1, 'dashed': False},
            'attack':     {'color': '#0891b2', 'dark_color': '#22d3ee', 'width': 1, 'dashed': True},
        },
    },
}

PIVOTICK_DEFAULT_STYLES = {
    # Same node/edge vocabulary today (bundleMispGraph.js serves both pages),
    # kept as two independently-editable configs since the two pages don't
    # necessarily want the same look.
    'rule':   copy.deepcopy(_RULE_BUNDLE_STYLE),
    'bundle': copy.deepcopy(_RULE_BUNDLE_STYLE),
    'attack': {
        'nodes': {
            'default': {'shape': 'circle', 'color': '#64748b', 'dark_color': '#94a3b8', 'size_min': 10, 'size_max': 30, 'icon': None},
            'types': {
                # Technique/sub-technique color is always inherited from their parent
                # tactic (keeps clusters visually grouped) — only shape/icon/size are
                # configurable for them. Tactic color comes from `palette`, rotated by
                # tactic order; `color`/`dark_color` are only used if palette is empty.
                'tactic': {
                    'shape': 'hexagon', 'icon': 'fa-solid fa-crosshairs',
                    'size_min': 30, 'size_max': 56,
                    'color': '#0ea5e9', 'dark_color': '#38bdf8',
                    'palette': list(_TACTIC_PALETTE_LIGHT),
                    'palette_dark': list(_TACTIC_PALETTE_DARK),
                },
                'technique':    {'shape': 'circle', 'icon': None, 'size_min': 10, 'size_max': 30},
                'subtechnique': {'shape': 'circle', 'icon': None, 'size_min': 7,  'size_max': 20},
            },
        },
        'edges': {
            'default': {'color': '#94a3b8', 'dark_color': '#475569', 'width': 2, 'dashed': False},
            'types': {
                'covers':        {'color': '#94a3b8', 'dark_color': '#475569', 'width': 2, 'dashed': False},
                'sub-technique': {'color': '#94a3b8', 'dark_color': '#475569', 'width': 1, 'dashed': True},
            },
        },
    },
}

GRAPH_TYPES = tuple(PIVOTICK_DEFAULT_STYLES.keys())


def get_default_style(graph_type):
    default = PIVOTICK_DEFAULT_STYLES.get(graph_type)
    return copy.deepcopy(default) if default is not None else None


def _deep_merge(base, override):
    """Merge `override` onto `base`, recursing into nested dicts.

    Lets a newly-introduced default node/edge type still show up even if an
    admin's stored config predates it, while any type/field the admin did set
    always wins.
    """
    if not isinstance(override, dict):
        return override if override is not None else base
    result = dict(base) if isinstance(base, dict) else {}
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def get_style_config(graph_type):
    """Effective config for a graph type: built-in default deep-merged with
    whatever the admin has customized (or just the default if untouched)."""
    default = get_default_style(graph_type)
    if default is None:
        return None
    row = PivotickGraphStyle.query.filter_by(graph_type=graph_type).first()
    if not row or not row.config:
        return default
    return _deep_merge(default, row.config)


def save_style_config(graph_type, data, user_id):
    if graph_type not in GRAPH_TYPES:
        return None, 'Unknown graph type'
    if not isinstance(data, dict) or not isinstance(data.get('nodes'), dict) or not isinstance(data.get('edges'), dict):
        return None, 'Config must be a JSON object with "nodes" and "edges" keys'
    try:
        row = PivotickGraphStyle.query.filter_by(graph_type=graph_type).first()
        if not row:
            row = PivotickGraphStyle(graph_type=graph_type)
            db.session.add(row)
        row.config = data
        row.updated_by = user_id
        db.session.commit()
        return get_style_config(graph_type), 'Style saved'
    except Exception as e:
        db.session.rollback()
        return None, f'Error saving style: {e}'


def reset_style_config(graph_type):
    if graph_type not in GRAPH_TYPES:
        return None, 'Unknown graph type'
    try:
        row = PivotickGraphStyle.query.filter_by(graph_type=graph_type).first()
        if row:
            row.config = None
            db.session.commit()
        return get_default_style(graph_type), 'Style reset to default'
    except Exception as e:
        db.session.rollback()
        return None, f'Error resetting style: {e}'
