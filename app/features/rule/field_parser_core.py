"""
Bulk field parser — extracts metadata from rule content and updates Rule fields.
Used by the admin bulk parse page and the bulk_parse_fields background job.
"""
import json
import re
from app import db
from app.core.db_class.db import FieldParserConfig
from app.core.utils.utils import detect_cve

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


def parse_field_from_content(content: str, field_cfg: dict):
    """
    Extract a field value from rule content using keyword or regex strategy.
    field_cfg keys: keywords (list[str]), regex (str), overwrite (bool).
    Returns the extracted string or None.
    """
    if not content:
        return None

    regex = (field_cfg.get('regex') or '').strip()
    if regex:
        try:
            m = re.search(regex, content, re.IGNORECASE | re.MULTILINE)
            if m:
                return (m.group(1) if m.lastindex else m.group(0)).strip()
        except re.error:
            pass
        return None

    keywords = [kw.strip().lower() for kw in (field_cfg.get('keywords') or []) if kw.strip()]
    if not keywords:
        return None

    for line in content.splitlines():
        stripped = line.strip()
        # skip indented lines (nested YAML blocks like related: - id: ...)
        if line.startswith((' ', '\t')):
            continue
        for kw in keywords:
            # handles both "key: value" and "key = value" / 'key = "value"'
            pat = re.compile(r'(?i)^' + re.escape(kw) + r'\s*[:=]\s*(.+)')
            m = pat.match(stripped)
            if m:
                val = m.group(1).strip().strip('"\'|').strip()
                if val:
                    return val
    return None


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

def get_all_configs():
    return FieldParserConfig.query.order_by(FieldParserConfig.created_at.desc()).all()


def get_config(config_id: int):
    return FieldParserConfig.query.get(config_id)


def save_config(name: str, config: dict, user_id: int):
    cfg = FieldParserConfig(name=name, config=config, user_id=user_id)
    db.session.add(cfg)
    db.session.commit()
    return cfg


def delete_config(config_id: int):
    cfg = FieldParserConfig.query.get(config_id)
    if cfg:
        db.session.delete(cfg)
        db.session.commit()
        return True
    return False
