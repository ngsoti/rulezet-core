"""
Bulk field parser — extracts metadata from rule content and updates Rule fields.
Used by the admin bulk parse page and the bulk_parse_fields background job.
"""
import json
import re
from app import db
from app.core.db_class.db import FieldParserConfig, Tag
from app.core.utils.utils import detect_cve

# FieldParserConfig.config_type values — see the model docstring in db.py.
CONFIG_TYPE_FIELD_PARSER  = 'field_parser'
CONFIG_TYPE_PLATFORM_TAGS = 'platform_tags'

# Fields that can be parsed from rule content. Order matters for with_entities queries.
PARSEABLE_FIELD_KEYS = ['license', 'author', 'original_uuid', 'description', 'version', 'title']

FIELD_META = {
    'license':       {'label': 'License',       'icon': 'fa-scale-balanced', 'color': '#0d6efd',
                      'default_keywords': ['license', 'licenses', 'spdx-license-identifier', 'credit']},
    'author':        {'label': 'Author',         'icon': 'fa-user-pen',      'color': '#6f42c1',
                      'default_keywords': ['author', 'authors']},
    'original_uuid': {'label': 'Original UUID',  'icon': 'fa-fingerprint',   'color': '#e67e22',
                      'default_keywords': ['uuid_1', 'id', 'uuid']},
    'description':   {'label': 'Description',    'icon': 'fa-align-left',    'color': '#198754',
                      'default_keywords': ['description', 'desc', 'summary']},
    'version':       {'label': 'Version',        'icon': 'fa-code-branch',   'color': '#dc3545',
                      'default_keywords': ['version', 'rev', 'revision']},
    'title':         {'label': 'Title',          'icon': 'fa-heading',       'color': '#20c997',
                      'default_keywords': ['title', 'name']},
}


def locate_field_match(content: str, field_cfg: dict):
    """
    Extract a field value from rule content using keyword or regex strategy,
    AND report where the match occurred so the admin tester can highlight it.
    field_cfg keys: keywords (list[str]), regex (str).

    Returns (value, start, end, line_index):
      - regex mode: start/end are char offsets of the match into `content`, line_index is None.
      - keyword mode: line_index is the 0-based matching line number, start/end span that whole line.
      - no match / empty content: (None, None, None, None).
    """
    if not content:
        return None, None, None, None

    regex = (field_cfg.get('regex') or '').strip()
    if regex:
        try:
            m = re.search(regex, content, re.IGNORECASE | re.MULTILINE)
        except re.error:
            return None, None, None, None
        if not m:
            return None, None, None, None
        if m.lastindex:
            return m.group(1).strip(), m.start(1), m.end(1), None
        return m.group(0).strip(), m.start(0), m.end(0), None

    keywords = [kw.strip().lower() for kw in (field_cfg.get('keywords') or []) if kw.strip()]
    if not keywords:
        return None, None, None, None

    offset = 0
    for line_idx, raw_line in enumerate(content.splitlines(keepends=True)):
        line     = raw_line.rstrip('\r\n')
        stripped = line.strip()
        # skip indented lines (nested YAML blocks like related: - id: ...)
        if line.startswith((' ', '\t')):
            offset += len(raw_line)
            continue
        for kw in keywords:
            # handles both "key: value" and "key = value" / 'key = "value"'
            pat = re.compile(r'(?i)^' + re.escape(kw) + r'\s*[:=]\s*(.+)')
            m = pat.match(stripped)
            if m:
                val = m.group(1).strip().strip('"\'|').strip()
                if val:
                    return val, offset, offset + len(line), line_idx
        offset += len(raw_line)
    return None, None, None, None


def parse_field_from_content(content: str, field_cfg: dict):
    """
    Extract a field value from rule content using keyword or regex strategy.
    field_cfg keys: keywords (list[str]), regex (str), overwrite (bool).
    Returns the extracted string or None.
    """
    value, _, _, _ = locate_field_match(content, field_cfg)
    return value


def rescan_cve_ids(content: str, existing_cve_raw):
    """
    Re-scan rule content for CVE/vulnerability identifiers and MERGE them into
    the rule's existing list — additive only, never removes or duplicates an
    already-associated identifier.

    Returns (changed: bool, new_cve_json: str | None). new_cve_json is only
    set when changed is True.
    """
    existing = []
    if existing_cve_raw:
        try:
            parsed = json.loads(existing_cve_raw) if isinstance(existing_cve_raw, str) else existing_cve_raw
            if isinstance(parsed, list):
                existing = [v.strip() for v in parsed if isinstance(v, str) and v.strip()]
        except (json.JSONDecodeError, TypeError):
            pass

    _, found_json = detect_cve(content)
    try:
        found = json.loads(found_json) if found_json else []
    except (json.JSONDecodeError, TypeError):
        found = []

    merged = sorted(set(existing) | set(found))
    if merged == sorted(existing):
        return False, None
    return True, json.dumps(merged)


# ── Config CRUD ─────────────────────────────────────────────────────────────
# Shared by both admin parser tools — config_type keeps their saved configs
# from ever mixing in the same list.

def get_all_configs(config_type: str = CONFIG_TYPE_FIELD_PARSER):
    return (FieldParserConfig.query
            .filter_by(config_type=config_type)
            .order_by(FieldParserConfig.created_at.desc())
            .all())


def get_config(config_id: int, config_type: str | None = None):
    cfg = FieldParserConfig.query.get(config_id)
    if cfg and config_type is not None and cfg.config_type != config_type:
        return None
    return cfg


def save_config(name: str, config: dict, user_id: int, config_type: str = CONFIG_TYPE_FIELD_PARSER):
    cfg = FieldParserConfig(name=name, config=config, user_id=user_id, config_type=config_type)
    db.session.add(cfg)
    db.session.commit()
    return cfg


def delete_config(config_id: int, config_type: str | None = None):
    cfg = get_config(config_id, config_type=config_type)
    if cfg:
        db.session.delete(cfg)
        db.session.commit()
        return True
    return False


# ── Platform-tag pattern config (validate-then-trust) ───────────────────────
#
# A "platform tags" config is: {"patterns": [
#     {"label": "Windows", "tag_id": 123, "regex": "\\bwindows\\b|\\bwin32\\b", "enabled": true},
#     ...
# ]}
# tag_id is resolved from the real Tag table (picked via the same tag search
# used everywhere else in the app), never a free-typed tag name — this is what
# makes "the model/admin can't reference a tag that doesn't exist" enforceable:
# validation below re-resolves every tag_id against the DB, every time, and
# refuses to hand back a usable pattern list if even one is missing or a regex
# doesn't compile. Called both when a config is saved (immediate feedback) and
# again right before/while the job runs (defense in depth — a tag can be
# deleted at any time after a config was saved).

def validate_platform_tag_config(config: dict) -> tuple[bool, str, list[dict]]:
    """Validate a platform-tag config against the DB.

    Returns (ok, error_message, resolved_patterns). resolved_patterns is only
    populated when ok is True, and each entry has a live Tag reference
    resolved by id (tag_id, tag_name) plus a pre-compiled-checked regex string.
    Nothing here mutates the DB.
    """
    if not isinstance(config, dict):
        return False, 'Config must be a JSON object.', []

    patterns = config.get('patterns')
    if not isinstance(patterns, list) or not patterns:
        return False, 'Config must contain a non-empty "patterns" list.', []
    if len(patterns) > 200:
        return False, 'Too many patterns (max 200) — split into multiple configs instead.', []

    errors: list[str] = []
    resolved: list[dict] = []
    seen_tag_ids: set[int] = set()

    for i, p in enumerate(patterns):
        label = (p.get('label') or '').strip() if isinstance(p, dict) else ''
        tag_ref = f'pattern #{i + 1}' + (f' ("{label}")' if label else '')

        if not isinstance(p, dict):
            errors.append(f'{tag_ref}: must be an object.')
            continue

        tag_id = p.get('tag_id')
        try:
            tag_id = int(tag_id)
        except (TypeError, ValueError):
            errors.append(f'{tag_ref}: missing or invalid tag_id.')
            continue

        regex = (p.get('regex') or '').strip()
        if not regex:
            errors.append(f'{tag_ref}: regex/keyword pattern is required.')
            continue
        try:
            re.compile(regex, re.IGNORECASE)
        except re.error as e:
            errors.append(f'{tag_ref}: invalid regex — {e}')
            continue

        # The real check: does this tag still exist right now? A free-typed
        # name is never accepted anywhere in this flow — only an id that
        # resolves to a real, current row does.
        tag = Tag.query.get(tag_id)
        if not tag:
            errors.append(f'{tag_ref}: tag id {tag_id} no longer exists (deleted, or never existed).')
            continue

        if tag.id in seen_tag_ids:
            errors.append(f'{tag_ref}: tag "{tag.name}" is already used by another pattern in this config.')
            continue
        seen_tag_ids.add(tag.id)

        resolved.append({
            'label':   label or tag.name,
            'tag_id':  tag.id,
            'tag_name': tag.name,
            'regex':   regex,
            'enabled': bool(p.get('enabled', True)),
        })

    if errors:
        return False, ' | '.join(errors), []
    return True, '', resolved
