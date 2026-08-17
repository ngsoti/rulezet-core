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
    if action.startswith("chatbot."):
        return "fa-solid fa-robot"
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
    actor_id: int | None = None,
) -> None:
    """
    actor_id: explicit author override for calls made outside the acting
    user's own session — e.g. from a background job thread (no request/session
    context, so `current_user` isn't available: pass the job's `created_by`)
    or from a route that performs an action for a user before that user is
    logged in (e.g. registration: pass the new user's id). Falls back to
    `current_user` when omitted, same as before.
    """
    with suppress(Exception):
        from app import db
        from app.core.db_class.db import ActivityLog
        from flask import request as freq
        from flask_login import current_user

        actor_source = None
        user_id = None
        if actor_id is not None:
            user_id = actor_id
            actor_source = 'explicit'
        else:
            with suppress(Exception):
                if current_user.is_authenticated:
                    user_id = current_user.id
                    actor_source = 'session'

        ip = method = url = user_agent = referrer = endpoint = None
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
            referrer   = (freq.referrer or '')[:512] or None
            endpoint   = freq.endpoint

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
            # Where the action came from — which route fired it, and which
            # page the request was made from (helps trace multi-step flows).
            if endpoint:
                base['endpoint'] = endpoint
            if referrer:
                base['referrer'] = referrer
            # How the author was determined — 'session' (the logged-in caller),
            # 'explicit' (actor_id override, e.g. job owner or new registrant),
            # or omitted entirely when nobody was attributable (a genuine
            # system/automatic action, e.g. a cron-triggered sync).
            if actor_source:
                base['actor_source'] = actor_source
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
