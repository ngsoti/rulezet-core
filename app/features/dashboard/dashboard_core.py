from flask_login import current_user

from app import db
from app.core.db_class.db import UserConfig
from app.features.config.config_core import get_user_config, create_default_config_core

MAX_WIDGETS = 30

# First-time layout — a small, useful starting point rather than an empty
# grid. All data comes from endpoints that already exist (see the widgets'
# own JS for the fetch/path convention) — nothing here is dashboard-specific
# backend logic.
DEFAULT_LAYOUT = {
    'widgets': [
        {
            'id': 'w-stats', 'type': 'stats_row', 'x': 0, 'y': 0, 'w': 12, 'h': 2,
            'params': {},
        },
        {
            'id': 'w-attack', 'type': 'attack_heatmap', 'x': 0, 'y': 2, 'w': 12, 'h': 9,
            'params': {},
        },
        {
            'id': 'w-vulns', 'type': 'trending_vulns', 'x': 0, 'y': 11, 'w': 6, 'h': 4,
            'params': {'limit': 10},
        },
        {
            'id': 'w-rules-chart', 'type': 'chart', 'x': 6, 'y': 11, 'w': 6, 'h': 4,
            'params': {'endpoint': '/platform/insights_data', 'path': 'charts.rules_over_time', 'view': 'area'},
        },
        {
            'id': 'w-last-rules', 'type': 'rule_list', 'x': 0, 'y': 15, 'w': 6, 'h': 5,
            'params': {'variant': 'last_rules', 'limit': 5, 'view': 'card'},
        },
        {
            'id': 'w-top-rated', 'type': 'rule_list', 'x': 6, 'y': 15, 'w': 6, 'h': 5,
            'params': {'variant': 'top_rated', 'limit': 5, 'view': 'card'},
        },
        {
            'id': 'w-activity', 'type': 'activity_feed', 'x': 0, 'y': 20, 'w': 6, 'h': 5,
            'params': {'limit': 8},
        },
    ],
}


def _get_or_create_config():
    uid = current_user.id
    config = get_user_config(uid)
    if not config:
        config, msg = create_default_config_core(uid)
        if not config:
            return None
    return config


def get_dashboard_layout() -> dict:
    """This user's saved widget layout, or DEFAULT_LAYOUT if they have none yet."""
    config = _get_or_create_config()
    if not config or not config.meta or 'dashboard_layout' not in config.meta:
        return DEFAULT_LAYOUT
    return config.meta['dashboard_layout']


def save_dashboard_layout(layout: dict) -> tuple:
    widgets = layout.get('widgets') if isinstance(layout, dict) else None
    if widgets is None or not isinstance(widgets, list):
        return False, 'Invalid layout: expected {"widgets": [...]}'
    if len(widgets) > MAX_WIDGETS:
        return False, f'Too many widgets — maximum {MAX_WIDGETS}'
    for w in widgets:
        if not isinstance(w, dict) or not all(k in w for k in ('id', 'type', 'x', 'y', 'w', 'h')):
            return False, 'Invalid widget: missing required fields (id, type, x, y, w, h)'

    config = _get_or_create_config()
    if not config:
        return False, 'Could not load or create your settings'

    meta = dict(config.meta) if config.meta else {}
    meta['dashboard_layout'] = {'widgets': widgets}
    config.meta = meta
    db.session.commit()
    return True, 'Layout saved'
