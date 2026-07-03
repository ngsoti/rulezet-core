"""
log_definitions_core.py — Admin-editable overrides for activity-log action display.

Backs the "Log Definitions" tab on /admin/logs: lets an admin browse every known
action key (registered defaults + anything already logged in the DB) and change
its icon/title/visibility without touching code. Actual `log_activity("some.new_action", ...)`
calls still have to be added in code — this only manages the presentational layer,
consulted by app/core/utils/activity_log.py at write time.
"""

from __future__ import annotations

from typing import Any

from app.core.utils.activity_log import _default_icon, _auto_title, _auto_category, _auto_level
from app.features.admin.log_action_defaults import ICONS, TITLES, PUBLIC_ACTIONS

# ── Override cache ────────────────────────────────────────────────────────────
# Small table (one row per customized action), re-read lazily and invalidated
# on every save/reset so log_activity() never pays more than one query per
# process between edits.

_cache: dict[str, dict[str, Any]] | None = None


def _load_cache() -> dict[str, dict[str, Any]]:
    from app.core.db_class.db import LogActionDefinition
    rows = LogActionDefinition.query.all()
    return {
        r.action_key: {
            'icon': r.icon, 'title': r.title,
            'is_public': r.is_public, 'category': r.category,
        }
        for r in rows
    }


def invalidate_cache() -> None:
    global _cache
    _cache = None


def get_override(action_key: str) -> dict[str, Any] | None:
    global _cache
    if _cache is None:
        _cache = _load_cache()
    return _cache.get(action_key)


# ── Listing for the admin manager UI ──────────────────────────────────────────

def _all_known_action_keys() -> set[str]:
    from app.core.db_class.db import ActivityLog, LogActionDefinition
    from app import db

    keys = set(ICONS) | set(TITLES) | set(PUBLIC_ACTIONS)
    keys |= {r.action_key for r in LogActionDefinition.query.all()}
    keys |= {r[0] for r in db.session.query(ActivityLog.action).distinct().all()}
    return keys


def _usage_counts() -> dict[str, int]:
    from app.core.db_class.db import ActivityLog
    from app import db
    from sqlalchemy import func
    return dict(
        db.session.query(ActivityLog.action, func.count(ActivityLog.id))
        .group_by(ActivityLog.action).all()
    )


def _describe(action_key: str, override: dict[str, Any] | None, usage: dict[str, int]) -> dict[str, Any]:
    override = override or {}
    return {
        'action_key':     action_key,
        'icon':           override.get('icon') or _default_icon(action_key),
        'title':          override.get('title') or _auto_title(action_key),
        'is_public':      override.get('is_public') if override.get('is_public') is not None
                          else (action_key in PUBLIC_ACTIONS),
        'category':       override.get('category') or _auto_category(action_key),
        'level':          _auto_level(action_key),
        'is_custom':      bool(override),
        'usage_count':    usage.get(action_key, 0),
        'default_icon':   _default_icon(action_key),
        'default_title':  _auto_title(action_key),
        'default_is_public': action_key in PUBLIC_ACTIONS,
    }


def list_all_actions(
    search: str = '',
    category: str = '',
    sort_key: str = 'action_key',
    sort_dir: str = 'asc',
    page: int = 1,
    per_page: int = 20,
) -> dict[str, Any]:
    global _cache
    if _cache is None:
        _cache = _load_cache()
    usage = _usage_counts()

    items = [_describe(key, _cache.get(key), usage) for key in _all_known_action_keys()]

    if search:
        s = search.lower()
        items = [i for i in items if s in i['action_key'].lower() or s in i['title'].lower()]
    if category:
        items = [i for i in items if i['category'] == category]

    reverse = sort_dir == 'desc'
    if sort_key not in ('action_key', 'title', 'category', 'usage_count', 'is_custom'):
        sort_key = 'action_key'
    items.sort(key=lambda i: i[sort_key] if i[sort_key] is not None else '', reverse=reverse)

    total       = len(items)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page        = min(max(page, 1), total_pages)
    start       = (page - 1) * per_page
    page_items  = items[start:start + per_page]

    return {
        'items': page_items, 'total': total,
        'page': page, 'per_page': per_page, 'total_pages': total_pages,
    }


# ── Mutations ──────────────────────────────────────────────────────────────────

def save_override(action_key: str, icon: str | None, title: str | None,
                   is_public: bool | None, user_id: int | None) -> dict[str, Any]:
    from app.core.db_class.db import LogActionDefinition
    from app import db

    row = LogActionDefinition.query.filter_by(action_key=action_key).first()
    if not row:
        row = LogActionDefinition(action_key=action_key, category=_auto_category(action_key))
        db.session.add(row)
    row.icon          = (icon or '').strip() or None
    row.title         = (title or '').strip() or None
    row.is_public     = is_public
    row.updated_by_id = user_id
    db.session.commit()
    invalidate_cache()
    return row.to_json()


def reset_override(action_key: str) -> bool:
    from app.core.db_class.db import LogActionDefinition
    from app import db

    row = LogActionDefinition.query.filter_by(action_key=action_key).first()
    if not row:
        return False
    db.session.delete(row)
    db.session.commit()
    invalidate_cache()
    return True
