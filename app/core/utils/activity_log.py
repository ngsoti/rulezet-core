"""
activity_log.py — Fire-and-forget activity logging helper.

Usage:
    from app.core.utils.activity_log import log_activity

    log_activity("rule.create", f"Created rule '{rule.title}'",
                 target_type="rule", target_id=rule.id, target_uuid=rule.uuid)

`is_public`, `icon`, `title`, `category` and `level` are auto-determined
from the action if not provided. Never raises — failures are silently swallowed.
"""

from __future__ import annotations

import uuid as uuid_mod
from contextlib import suppress
from typing import Any

from app.features.admin.log_action_defaults import (
    ICONS as _ICONS,
    PUBLIC_ACTIONS as _PUBLIC_ACTIONS,
    TITLES as _TITLES,
    KNOWN_CATEGORIES as _KNOWN_CATEGORIES,
    CATEGORY_MAP as _CATEGORY_MAP,
    WARNING_KEYWORDS as _WARNING_KEYWORDS,
    SUCCESS_KEYWORDS as _SUCCESS_KEYWORDS,
)


def _default_icon(action: str) -> str:
    if action in _ICONS:
        return _ICONS[action]
    if action.startswith("admin."):
        return "fa-solid fa-lock"
    if action.startswith("rule."):
        return "fa-solid fa-file-shield"
    if action.startswith("bundle."):
        return "fa-solid fa-box"
    if action.startswith("user."):
        return "fa-solid fa-user"
    if action.startswith("job."):
        return "fa-solid fa-gears"
    if action.startswith("tag."):
        return "fa-solid fa-tag"
    if action.startswith(("comment.", "bundle_comment.")):
        return "fa-solid fa-comment"
    if action.startswith("connector."):
        return "fa-solid fa-plug"
    return "fa-solid fa-circle-dot"


def _auto_category(action: str) -> str:
    prefix = action.split('.')[0] if '.' in action else 'system'
    if prefix not in _KNOWN_CATEGORIES:
        return 'system'
    return _CATEGORY_MAP.get(prefix, prefix)


def _auto_level(action: str) -> str:
    a = action.lower()
    if any(k in a for k in _WARNING_KEYWORDS):
        return 'warning'
    if any(k in a for k in _SUCCESS_KEYWORDS):
        return 'success'
    return 'info'


def _auto_title(action: str) -> str:
    if action in _TITLES:
        return _TITLES[action]
    parts = action.replace('.', ' ').replace('_', ' ').split()
    return ' '.join(p.capitalize() for p in parts)


def log_activity(
    action: str,
    description: str,
    target_type: str | None = None,
    target_id: int | None = None,
    target_uuid: str | None = None,
    extra: dict[str, Any] | None = None,
    is_public: bool | None = None,
    icon: str | None = None,
    title: str | None = None,
    category: str | None = None,
    level: str | None = None,
) -> None:
    with suppress(Exception):
        from app import db
        from app.core.db_class.db import ActivityLog
        from flask import request as freq
        from flask_login import current_user

        user_id = None
        with suppress(Exception):
            if current_user.is_authenticated:
                user_id = current_user.id

        ip = method = url = user_agent = None
        remote_addr = xff = None
        with suppress(Exception):
            remote_addr = freq.remote_addr
            _xff_raw = (freq.headers.get('X-Forwarded-For') or '').strip()
            xff = _xff_raw or None
            # ip_address = real client IP: first XFF entry (client behind proxy) or remote_addr
            ip = (xff.split(',')[0].strip() if xff else remote_addr)
            if ip:
                ip = ip[:45]
            url        = freq.path[:512]
            method     = freq.method
            user_agent = (freq.headers.get('User-Agent') or '')[:256] or None

        # Build extra JSON: IPs (never loopback) + named target key + caller data
        with suppress(Exception):
            base: dict[str, Any] = {}
            # X-Forwarded-For = real client IP chain — always include when present
            if xff:
                base['x_forwarded_for'] = xff[:512]
            # remote_addr = the direct connecting address (proxy/lb) — skip loopback (127.x / ::1)
            if remote_addr and remote_addr != '::1' and not remote_addr.startswith('127.'):
                base['remote_addr'] = remote_addr
            # Named target IDs (rule_id, comment_id, bundle_id…) from target_type
            if target_type and target_id is not None:
                base[f'{target_type}_id'] = target_id
            if target_type and target_uuid:
                base[f'{target_type}_uuid'] = target_uuid
            # Caller-supplied data merged last — wins on key conflicts
            extra = {**base, **(extra or {})} or None

        override = None
        with suppress(Exception):
            from app.features.admin.log_definitions_core import get_override
            override = get_override(action)

        resolved_public    = is_public if is_public is not None else (
            override['is_public'] if override and override.get('is_public') is not None
            else (action in _PUBLIC_ACTIONS))
        resolved_icon      = icon if icon is not None else (
            (override or {}).get('icon') or _default_icon(action))
        resolved_title     = title if title is not None else (
            (override or {}).get('title') or _auto_title(action))
        resolved_category  = category if category is not None else (
            (override or {}).get('category') or _auto_category(action))
        resolved_level     = level if level is not None else _auto_level(action)

        entry = ActivityLog(
            uuid        = str(uuid_mod.uuid4()),
            user_id     = user_id,
            action      = action,
            title       = resolved_title,
            description = description,
            category    = resolved_category,
            level       = resolved_level,
            ip_address  = ip,
            url         = url,
            method      = method,
            user_agent  = user_agent,
            target_type = target_type,
            target_id   = target_id,
            target_uuid = target_uuid,
            extra       = extra,
            is_public   = resolved_public,
            icon        = resolved_icon,
        )
        db.session.add(entry)
        db.session.commit()
