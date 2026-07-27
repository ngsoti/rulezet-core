"""
connector_core.py — Business logic for the Connector feature.

All DB interactions stay here. Blueprints and API namespaces call these
functions and never touch the session directly.
"""

import datetime
import re
import uuid as uuid_mod
import logging

import requests as http_requests
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger(__name__)

import json as _json

from app import db
from app.core.db_class.db import (
    Bundle, BundleRuleAssociation, BundleTagAssociation, Connector, Rule, User,
    RuleTagAssociation, Tag, ActivityLog, RuleUpdateHistory,
    OFFICIAL_LOGO_AVATAR_SENTINEL,
)
from sqlalchemy import func
from app.core.utils.activity_log import log_activity
from app.features.jobs.jobs_core import create_job


# ─── Shadow user ──────────────────────────────────────────────────────────────

_OLD_SHADOW_USERNAME_RE = re.compile(r'^connector_[0-9a-f]{8}$')


def _slugify_username(name: str) -> str:
    """'Rulezet Official' -> 'rulezet_official' — used instead of a raw uuid
    fragment so a connector's shadow user has a readable username rather
    than 'connector_3f9a21bc'."""
    slug = re.sub(r'[^a-z0-9]+', '_', (name or '').lower()).strip('_')
    return slug or 'connector'


def _unique_username(base: str, exclude_user_id: int = None) -> str:
    candidate = base
    n = 1
    while True:
        q = User.query.filter_by(username=candidate)
        if exclude_user_id:
            q = q.filter(User.id != exclude_user_id)
        if not q.first():
            return candidate
        n += 1
        candidate = f"{base}_{n}"


def _get_or_create_shadow_user(connector: Connector) -> User:
    """Return (and lazily create) the ghost user that owns imported content."""
    if connector.shadow_user_id:
        user = User.query.get(connector.shadow_user_id)
        if user:
            return user

    shadow_email = f"shadow_{connector.uuid[:8]}@connector.local"
    existing = User.query.filter_by(email=shadow_email).first()
    if existing:
        connector.shadow_user_id = existing.id
        db.session.commit()
        return existing

    shadow = User(
        first_name=connector.name,
        last_name=f"[{connector.connector_type}]",
        email=shadow_email,
        username=_unique_username(_slugify_username(connector.name)),
        is_verified=False,
        admin=False,
    )
    shadow.password = uuid_mod.uuid4().hex   # random password — cannot login
    try:
        db.session.add(shadow)
        db.session.flush()
    except IntegrityError:
        # Another concurrent call already created this shadow user
        db.session.rollback()
        existing = User.query.filter_by(email=shadow_email).first()
        if existing:
            connector.shadow_user_id = existing.id
            db.session.commit()
            return existing
        raise

    connector.shadow_user_id = shadow.id
    db.session.commit()
    return shadow


def _seed_official_shadow_avatar(shadow: User) -> None:
    """Point the official connector's shadow user at the app logo under
    static/image/ — not a copy under static/uploads/avatars/ like a normal
    user avatar. get_avatar_url() special-cases OFFICIAL_LOGO_AVATAR_SENTINEL
    to resolve straight to /static/image/pp_Rulezet.png."""
    if shadow.profile_picture != OFFICIAL_LOGO_AVATAR_SENTINEL:
        shadow.profile_picture = OFFICIAL_LOGO_AVATAR_SENTINEL


# ─── CRUD ─────────────────────────────────────────────────────────────────────

def get_connectors(owner_id: int) -> list:
    """Return user's own connectors + all system connectors."""
    from sqlalchemy import or_
    return (Connector.query
            .filter(or_(Connector.owner_id == owner_id, Connector.is_system == True))
            .order_by(Connector.is_system.desc(), Connector.created_at.desc())
            .all())


def get_connector_by_uuid(connector_uuid: str, owner_id: int = None) -> Connector | None:
    q = Connector.query.filter_by(uuid=connector_uuid)
    if owner_id is not None:
        q = q.filter_by(owner_id=owner_id)
    return q.first()


def create_connector(owner_id: int, name: str, instance_url: str,
                     connector_type: str = 'rulezet',
                     api_key_outbound: str = None,
                     description: str = None,
                     icon: str = None,
                     sync_rules: bool = True,
                     sync_bundles: bool = False,
                     owner_mode: str = 'shadow') -> Connector | None:
    try:
        url = instance_url.rstrip('/')
        connector = Connector(
            uuid=str(uuid_mod.uuid4()),
            name=name.strip(),
            description=description,
            icon=icon,
            connector_type=connector_type,
            instance_url=url,
            api_key_outbound=api_key_outbound,
            owner_id=owner_id,
            sync_rules=sync_rules,
            sync_bundles=sync_bundles,
            owner_mode=owner_mode,
        )
        db.session.add(connector)
        db.session.flush()
        _get_or_create_shadow_user(connector)   # eagerly create shadow user
        db.session.commit()

        log_activity('connector.create',
                     f"Created connector '{name}' → {url}",
                     target_type='connector', target_id=connector.id,
                     target_uuid=connector.uuid)
        return connector
    except Exception as e:
        db.session.rollback()
        print(f"[connector_core] create_connector error: {e}")
        return None


def update_connector(connector: Connector, data: dict) -> bool:
    if connector.is_system:
        return False
    try:
        allowed = ('name', 'description', 'icon', 'instance_url', 'api_key_outbound',
                   'sync_rules', 'sync_bundles', 'is_active', 'owner_mode')
        for key in allowed:
            if key in data:
                val = data[key]
                if key == 'instance_url' and val:
                    val = val.rstrip('/')
                setattr(connector, key, val)
        connector.updated_at = datetime.datetime.now(datetime.timezone.utc)
        db.session.commit()
        log_activity('connector.update', f"Updated connector '{connector.name}'",
                     target_type='connector', target_id=connector.id,
                     target_uuid=connector.uuid)
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[connector_core] update_connector error: {e}")
        return False


def delete_connector(connector: Connector) -> bool:
    if connector.is_system:
        return False
    try:
        name = connector.name
        cid  = connector.id
        cuuid = connector.uuid
        # Nullify FK on rules/bundles so we don't lose data
        Rule.query.filter_by(connector_id=cid).update({'connector_id': None}, synchronize_session=False)
        Bundle.query.filter_by(connector_id=cid).update({'connector_id': None}, synchronize_session=False)
        db.session.delete(connector)
        db.session.commit()
        log_activity('connector.delete', f"Deleted connector '{name}'",
                     extra={'connector_uuid': cuuid})
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[connector_core] delete_connector error: {e}")
        return False


# ─── Connection test ──────────────────────────────────────────────────────────

def test_connector(connector: Connector) -> tuple[bool, str, dict]:
    """
    Ping the remote /api/sync/manifest then /api/sync/stats.
    Returns (success: bool, message: str, stats: dict).
    stats contains 'rules' and 'bundles' counts from the remote (or {}).
    """
    base    = connector.instance_url
    headers = {}
    if connector.api_key_outbound:
        headers['X-API-KEY'] = connector.api_key_outbound
    try:
        resp = http_requests.get(f"{base}/api/sync/manifest", headers=headers, timeout=8)
        if resp.status_code == 404:
            msg = ("Sync API not found (HTTP 404). The remote instance may be running an older version "
                   "of Rulezet that does not support federation sync.")
            connector.last_error = msg
            db.session.commit()
            return False, msg, {}
        if resp.status_code != 200:
            msg = f"Remote returned HTTP {resp.status_code}."
            connector.last_error = msg
            db.session.commit()
            return False, msg, {}

        remote_name = resp.json().get('instance', {}).get('name', 'unknown')

        # Fetch public stats (best-effort — non-fatal if absent)
        stats: dict = {}
        try:
            sr = http_requests.get(f"{base}/api/sync/stats", headers=headers, timeout=5)
            if sr.status_code == 200:
                sd = sr.json()
                stats = {'rules': sd.get('rules'), 'bundles': sd.get('bundles')}
        except Exception:
            pass

        connector.is_verified = True
        connector.last_error  = None
        if stats.get('rules') is not None:
            connector.remote_rules_count   = stats['rules']
        if stats.get('bundles') is not None:
            connector.remote_bundles_count = stats['bundles']
        db.session.commit()

        stats_str = ''
        if stats.get('rules') is not None:
            stats_str = f" — {stats['rules']:,} rules, {stats['bundles']:,} bundles"

        log_activity('connector.test_ok',
                     f"Connection test OK for '{connector.name}' → {remote_name}{stats_str}",
                     target_type='connector', target_id=connector.id,
                     target_uuid=connector.uuid)
        return True, f"Connected to \"{remote_name}\"{stats_str}.", stats

    except Exception as e:
        msg = f"Connection error: {e}"
        connector.last_error = msg
        db.session.commit()
        return False, msg, {}


# ─── Pull (trigger background job) ───────────────────────────────────────────

def get_connector_history(connector: Connector) -> list:
    """Return the last 30 activity log entries for this connector."""
    entries = (ActivityLog.query
               .filter(
                   ActivityLog.target_type == 'connector',
                   ActivityLog.target_id == connector.id,
               )
               .order_by(ActivityLog.created_at.desc())
               .limit(30)
               .all())
    return [
        {
            'action':      e.action,
            'description': e.description,
            'timestamp':   e.created_at.strftime('%Y-%m-%d %H:%M:%S') if e.created_at else None,
            'extra':       e.extra or {},
        }
        for e in entries
    ]


def seed_official_connector() -> None:
    """Create the read-only official Rulezet connector if it doesn't exist yet,
    and make sure its shadow user (the ghost owner attributed to every rule
    pulled from rulezet.org) has a readable username and the Rulezet logo as
    its avatar — runs on every boot so existing installs self-heal too, not
    just brand-new ones."""
    try:
        c = Connector.query.filter_by(is_system=True).first()
        if not c:
            admin = User.query.filter_by(admin=True).first()
            if not admin:
                return
            c = Connector(
                uuid=str(uuid_mod.uuid4()),
                name='Rulezet Official',
                description='The official Rulezet community — rulezet.org.',
                icon='fa-solid fa-shield-halved',
                connector_type='rulezet',
                instance_url='https://rulezet.org',
                owner_id=admin.id,
                sync_rules=True,
                sync_bundles=True,
                is_system=True,
                owner_mode='shadow',
            )
            db.session.add(c)
            db.session.commit()

        shadow = _get_or_create_shadow_user(c)
        if _OLD_SHADOW_USERNAME_RE.match(shadow.username or ''):
            shadow.username = _unique_username(_slugify_username(c.name), exclude_user_id=shadow.id)
        _seed_official_shadow_avatar(shadow)
        db.session.commit()
    except Exception:
        db.session.rollback()


def trigger_pull(connector: Connector, triggered_by: int,
                 sync_rules: bool = None, sync_bundles: bool = None,
                 filters: dict = None) -> object | None:
    """Enqueue a connector_pull background job and return the job object.

    sync_rules / sync_bundles override the connector's own flags for this pull only.
    filters — dict from ConnectorPullFilter (date, formats, tags, cves, …).
    """
    if not connector.is_active:
        return None
    payload: dict = {'connector_id': connector.id}
    if sync_rules   is not None: payload['sync_rules']   = sync_rules
    if sync_bundles is not None: payload['sync_bundles'] = sync_bundles
    if filters:                  payload['filters']      = filters

    what = ' + '.join(filter(None, [
        'rules'   if (sync_rules   if sync_rules   is not None else connector.sync_rules)   else '',
        'bundles' if (sync_bundles if sync_bundles is not None else connector.sync_bundles) else '',
    ]))
    job = create_job(
        job_type='connector_pull',
        payload=payload,
        label=f"Pull from '{connector.name}' ({what})",
        created_by=triggered_by,
    )
    log_activity('connector.pull_triggered',
                 f"Pull queued for connector '{connector.name}'",
                 target_type='connector', target_id=connector.id,
                 target_uuid=connector.uuid,
                 extra={'job_uuid': job.uuid if job else None})
    return job


# ─── Sync helpers (called from job handler) ───────────────────────────────────

def _upsert_rule(connector: Connector, shadow_user_id: int, remote: dict,
                 triggered_by_id: int = None,
                 missing_tags: set = None,
                 local_match=None,
                 tag_cache: dict = None,
                 assoc_set: set = None) -> str:
    """UUID-based upsert: match → update in place with history; no match → create.

    local_match — pre-looked-up Rule object (avoids per-rule DB query when caller
                  does a batch UUID lookup for the whole page).
    tag_cache   — {name.lower(): Tag} dict built once per pull for O(1) tag lookups.
    assoc_set   — {(rule_id, tag_id)} set for O(1) duplicate-association checks;
                  updated in place as new associations are added.

    Returns: 'created' | 'updated' | 'skipped' | 'invalid'
    """
    remote_uuid = remote.get('uuid')
    if not remote_uuid:
        return 'invalid'

    owner_id = triggered_by_id if triggered_by_id else shadow_user_id
    now      = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    # Use pre-looked-up match when available (batch path), otherwise fall back to DB query.
    if local_match is None:
        local_match = Rule.query.filter(
            or_(Rule.remote_rule_uuid == remote_uuid, Rule.uuid == remote_uuid),
        ).order_by(Rule.is_deleted.asc()).first()

    if local_match:
        from app.features.rule.rule_core import rule_metadata_snapshot
        old_snapshot = rule_metadata_snapshot(local_match)

        restored = False
        if local_match.is_deleted:
            local_match.is_deleted        = False
            local_match.deleted_at        = None
            local_match.deleted_by_id     = None
            local_match.delete_batch_uuid = None
            restored = True

        new_content     = remote.get('to_string', '')
        content_changed = (local_match.to_string or '') != new_content

        content_history = None
        if content_changed:
            content_history = RuleUpdateHistory(
                rule_id=local_match.id,
                rule_title=local_match.title,
                success=True,
                message=f"Updated by pull from '{connector.name}' ({connector.instance_url})",
                old_content=local_match.to_string,
                new_content=new_content,
                analyzed_by_user_id=owner_id,
                analyzed_at=now,
                manuel_submit=True,
                change_type="content",
            )
            db.session.add(content_history)
            local_match.to_string = new_content

        meta_changed = False
        for field in ('format', 'title', 'description', 'author', 'version', 'license', 'source'):
            value = remote.get(field)
            if value is None:
                continue
            if field == 'version':
                value = str(value)
            if getattr(local_match, field) != value:
                setattr(local_match, field, value)
                meta_changed = True

        missed = _sync_tags(local_match, remote.get('tags', []), owner_id,
                            tag_cache=tag_cache, assoc_set=assoc_set)
        if missing_tags is not None:
            missing_tags.update(missed)
        _sync_cve_ids(local_match, remote.get('cve_ids', []))

        new_snapshot     = rule_metadata_snapshot(local_match)
        metadata_changed = new_snapshot != old_snapshot

        if not content_changed and not metadata_changed and not restored:
            return 'skipped'

        if content_history is not None:
            content_history.old_snapshot = old_snapshot
            content_history.new_snapshot = new_snapshot
            content_history.change_type  = "mixed" if metadata_changed else "content"
        elif metadata_changed:
            db.session.add(RuleUpdateHistory(
                rule_id=local_match.id,
                rule_title=local_match.title,
                success=True,
                message=f"Metadata updated by pull from '{connector.name}' ({connector.instance_url})",
                old_snapshot=old_snapshot,
                new_snapshot=new_snapshot,
                analyzed_by_user_id=owner_id,
                analyzed_at=now,
                # Not a content submission — was_last_history_manuel() gates
                # GitHub auto-sync on this flag, and a metadata-only sync
                # shouldn't block future content syncs for the rule.
                manuel_submit=False,
                change_type="metadata",
            ))

        local_match.connector_id      = connector.id
        local_match.sync_instance_url = connector.instance_url
        local_match.last_modif        = now
        db.session.flush()

        _import_rule_history(local_match, remote.get('update_history', []), owner_id)
        return 'updated'

    # ── No match → create the rule from remote data ───────────────────────────
    rule = Rule(
        uuid=remote_uuid,           # preserve origin UUID for cross-instance lookup
        remote_rule_uuid=remote_uuid,
        connector_id=connector.id,
        user_id=owner_id,
        format=remote.get('format', 'unknown'),
        title=remote.get('title', ''),
        description=remote.get('description'),
        to_string=remote.get('to_string', ''),
        author=remote.get('author') or connector.name,
        source=remote.get('source'),
        sync_instance_url=connector.instance_url,
        version=remote.get('version'),
        license=remote.get('license'),
        vote_up=0,
        vote_down=0,
        creation_date=now,
        last_modif=now,
        is_deleted=False,
    )
    db.session.add(rule)
    db.session.flush()  # needed to obtain rule.id for tag associations
    missed = _sync_tags(rule, remote.get('tags', []), owner_id,
                        tag_cache=tag_cache, assoc_set=assoc_set)
    if missing_tags is not None:
        missing_tags.update(missed)
    _sync_cve_ids(rule, remote.get('cve_ids', []))
    _import_rule_history(rule, remote.get('update_history', []), owner_id)
    return 'created'


def _prepare_new_rule(connector: Connector, owner_id: int, remote: dict) -> Rule:
    """Create a Rule ORM object from remote data and add it to the session — do NOT flush.

    The caller must call db.session.flush() after batching all new rules, then call
    _sync_tags / _sync_cve_ids / _import_rule_history_new to finish each rule.
    This allows a whole page of new rules to be inserted in a single DB round-trip.
    """
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    remote_uuid = remote.get('uuid')
    rule = Rule(
        uuid=remote_uuid,           # preserve origin UUID for cross-instance lookup
        remote_rule_uuid=remote_uuid,
        connector_id=connector.id,
        user_id=owner_id,
        format=remote.get('format', 'unknown'),
        title=remote.get('title', ''),
        description=remote.get('description'),
        to_string=remote.get('to_string', ''),
        author=remote.get('author') or connector.name,
        source=remote.get('source'),
        sync_instance_url=connector.instance_url,
        version=remote.get('version'),
        license=remote.get('license'),
        vote_up=0,
        vote_down=0,
        creation_date=now,
        last_modif=now,
        is_deleted=False,
    )
    db.session.add(rule)
    return rule


def _import_rule_history_new(rule: Rule, history: list, fallback_user_id: int) -> None:
    """Same as _import_rule_history but skips the existing-history DB query.
    Safe to call only for brand-new rules (just flushed, guaranteed empty history).
    """
    if not history:
        return
    seen: set = set()
    for h in history:
        try:
            if h.get('analyzed_at'):
                raw = datetime.datetime.fromisoformat(
                    h['analyzed_at'].replace('Z', '+00:00')
                ).replace(tzinfo=None)
            else:
                raw = datetime.datetime.utcnow()
            key = raw.isoformat()
            if key in seen:
                continue
            seen.add(key)
            db.session.add(RuleUpdateHistory(
                rule_id=rule.id,
                rule_title=rule.title,
                success=h.get('success', True),
                message=h.get('message'),
                old_content=h.get('old_content'),
                new_content=h.get('new_content'),
                analyzed_by_user_id=fallback_user_id,
                analyzed_at=raw,
                manuel_submit=h.get('manuel_submit', False),
            ))
        except Exception as exc:
            logger.warning("_import_rule_history_new: skipped entry for rule %s: %s", rule.id, exc)


def _import_rule_history(rule: Rule, history: list, fallback_user_id: int) -> None:
    """Attach RuleUpdateHistory entries to a rule, deduplicating by analyzed_at
    (both within the batch and against entries already stored for the rule)."""
    if not history:
        return
    seen = {
        h.analyzed_at.isoformat()
        for h in rule.rule_update_history.all()
        if h.analyzed_at
    }
    for h in history:
        try:
            if h.get('analyzed_at'):
                raw = datetime.datetime.fromisoformat(
                    h['analyzed_at'].replace('Z', '+00:00')
                ).replace(tzinfo=None)
            else:
                raw = datetime.datetime.utcnow()
            key = raw.isoformat()
            if key in seen:
                continue
            seen.add(key)
            db.session.add(RuleUpdateHistory(
                rule_id=rule.id,
                rule_title=rule.title,
                success=h.get('success', True),
                message=h.get('message'),
                old_content=h.get('old_content'),
                new_content=h.get('new_content'),
                analyzed_by_user_id=fallback_user_id,
                analyzed_at=raw,
                manuel_submit=h.get('manuel_submit', False),
            ))
        except Exception as exc:
            logger.warning("_import_rule_history: skipped entry for rule %s: %s", rule.id, exc)


def build_tag_cache() -> dict:
    """Load every Tag into a name.lower() → Tag dict for O(1) lookups during a pull.
    Call once at the start of a pull job and pass it down to _sync_tags / _ensure_tag."""
    return {t.name.lower(): t for t in Tag.query.all()}


def _find_tag(name: str, tag_cache: dict = None):
    """Exact case-insensitive tag lookup. Uses in-memory cache when provided."""
    if tag_cache is not None:
        return tag_cache.get(name.lower())
    return Tag.query.filter(func.lower(Tag.name) == name.lower()).first()


def _auto_install_taxonomy(namespace: str) -> bool:
    """Ensure a MISP taxonomy namespace is installed from the local submodule.
    Returns True if the namespace is now usable."""
    try:
        from app.features.tags.tags_core import (
            add_tags_from_misp_taxonomy,
            update_tags_from_misp_taxonomy,
            get_all_taxonomy_uuids_from_disk,
            get_all_taxonomies_in_db,
        )
        from app.features.account.account_core import get_admin_user

        admin = get_admin_user()
        if not admin:
            return False

        ns_to_uid = {ns: uid for uid, ns in get_all_taxonomy_uuids_from_disk()}
        uid = ns_to_uid.get(namespace)
        if not uid:
            logger.debug("_auto_install_taxonomy: '%s' not found in submodule", namespace)
            return False

        if namespace not in get_all_taxonomies_in_db():
            ok, msg = add_tags_from_misp_taxonomy(uid, admin)
            logger.info("_auto_install_taxonomy: installed '%s' — %s", namespace, msg)
        else:
            ok, msg = update_tags_from_misp_taxonomy(uid, admin)
            logger.info("_auto_install_taxonomy: updated '%s' — %s", namespace, msg)

        return bool(ok)
    except Exception as exc:
        logger.warning("_auto_install_taxonomy: failed for '%s': %s", namespace, exc)
        return False


def _auto_install_galaxy(gtype: str) -> bool:
    """Ensure a galaxy type is fully installed from the local submodule.

    - If the galaxy is not in DB yet: imports all clusters.
    - If already in DB: runs an update pass to add any new clusters that exist
      on disk but are missing from the DB (handles stale/outdated galaxy installs).

    Uses the instance admin as creator. Returns True if the galaxy is now usable.
    """
    try:
        from app.features.tags.tags_core import (
            add_tags_from_misp_galaxy,
            update_tags_from_misp_galaxy,
            get_all_galaxy_uuids_from_disk,
            get_all_galaxies_in_db,
        )
        from app.features.account.account_core import get_admin_user

        admin = get_admin_user()
        if not admin:
            return False

        gtype_to_uid = {gt: uid for uid, gt in get_all_galaxy_uuids_from_disk()}
        uid = gtype_to_uid.get(gtype)
        if not uid:
            logger.warning("_auto_install_galaxy: '%s' not found in submodule", gtype)
            return False

        if gtype not in get_all_galaxies_in_db():
            # Fresh install
            ok, msg = add_tags_from_misp_galaxy(uid, admin)
            logger.info("_auto_install_galaxy: installed '%s' — %s", gtype, msg)
        else:
            # Already present — add any new clusters from the submodule
            ok, msg = update_tags_from_misp_galaxy(uid, admin)
            logger.info("_auto_install_galaxy: updated '%s' — %s", gtype, msg)

        return bool(ok)
    except Exception as exc:
        logger.warning("_auto_install_galaxy: failed for '%s': %s", gtype, exc)
        return False


def _create_stub_galaxy_tag(name: str, user_id: int, tag_cache: dict = None) -> "Tag | None":
    """Create a minimal Tag for a galaxy cluster not present in the local submodule.

    Uses a savepoint so a duplicate-name error only rolls back this one insert,
    not the entire pull transaction.
    """
    try:
        gtype = name[len("misp-galaxy:"):].split("=")[0].strip().rstrip('"')
        with db.session.begin_nested():
            tag = Tag(
                uuid=str(uuid_mod.uuid4()),
                name=name,
                source="Galaxy",
                is_active=True,
                is_approved_by_admin=True,
                galaxy_meta={"type": gtype, "stub": True},
                created_by=user_id,
                created_at=datetime.datetime.now(datetime.timezone.utc),
                updated_at=datetime.datetime.now(datetime.timezone.utc),
            )
            db.session.add(tag)
        logger.info("_create_stub_galaxy_tag: created stub '%s'", name)
        if tag_cache is not None:
            tag_cache[name.lower()] = tag
        return tag
    except Exception:
        # Savepoint rolled back — tag was already created in this transaction
        tag = _find_tag(name, tag_cache)
        return tag


def _create_stub_tag(name: str, user_id: int, tag_cache: dict = None) -> "Tag | None":
    """Create a minimal Tag for any name not found locally.

    Uses a savepoint so a duplicate-name error only rolls back this insert.
    """
    try:
        with db.session.begin_nested():
            tag = Tag(
                uuid=str(uuid_mod.uuid4()),
                name=name,
                source="Connector",
                is_active=True,
                is_approved_by_admin=True,
                created_by=user_id,
                created_at=datetime.datetime.now(datetime.timezone.utc),
                updated_at=datetime.datetime.now(datetime.timezone.utc),
            )
            db.session.add(tag)
        logger.info("_create_stub_tag: created stub '%s'", name)
        if tag_cache is not None:
            tag_cache[name.lower()] = tag
        return tag
    except Exception:
        tag = _find_tag(name, tag_cache)
        return tag


def _ensure_tag(name: str, user_id: int, auto_installed: set,
                tag_cache: dict = None) -> "Tag | None":
    """Return a local Tag for *name*, installing/creating it if needed.

    Priority:
    1. Found in cache/DB → return it.
    2. misp-galaxy: tag → auto-install galaxy, then stub if still missing.
    3. namespace:value tag → auto-install MISP taxonomy, then stub if still missing.
    4. Unknown format → create stub tag directly.
    """
    tag = _find_tag(name, tag_cache)
    if tag is not None:
        return tag

    if name.startswith("misp-galaxy:") and "=" in name:
        gtype = name[len("misp-galaxy:"):].split("=")[0].strip().rstrip('"')
        if gtype not in auto_installed:
            _auto_install_galaxy(gtype)
            auto_installed.add(gtype)
            if tag_cache is not None:
                new_tags = Tag.query.filter(
                    func.lower(Tag.name).like(f"misp-galaxy:{gtype.lower()}%")
                ).all()
                for t in new_tags:
                    tag_cache[t.name.lower()] = t
        tag = _find_tag(name, tag_cache)
        if tag is None:
            tag = _create_stub_galaxy_tag(name, user_id, tag_cache)

    elif ":" in name:
        # Regular MISP taxonomy tag (e.g. tlp:clear, pap:white)
        namespace = name.split(":")[0].lower()
        if namespace not in auto_installed:
            _auto_install_taxonomy(namespace)
            auto_installed.add(namespace)
            if tag_cache is not None:
                new_tags = Tag.query.filter(
                    func.lower(Tag.name).like(f"{namespace}:%")
                ).all()
                for t in new_tags:
                    tag_cache[t.name.lower()] = t
        tag = _find_tag(name, tag_cache)
        if tag is None:
            tag = _create_stub_tag(name, user_id, tag_cache)

    else:
        tag = _create_stub_tag(name, user_id, tag_cache)

    return tag


def _sync_tags(rule: Rule, tag_names: list, user_id: int,
               tag_cache: dict = None, assoc_set: set = None) -> set:
    """Attach tags to a rule, auto-installing/creating galaxy tags as needed.

    tag_cache  — optional {name.lower(): Tag} dict built once per pull for O(1) lookups.
    assoc_set  — optional {(rule_id, tag_id)} set for O(1) duplicate checks; updated in place.

    Returns a set of non-galaxy tag names that could not be found locally.
    """
    missing: set = set()
    auto_installed: set = set()

    for name in tag_names:
        tag = _ensure_tag(name, user_id, auto_installed, tag_cache)

        if tag is None:
            missing.add(name)
            continue

        if not tag.is_active:
            tag.is_active = True

        key = (rule.id, tag.id)
        if assoc_set is not None:
            if key in assoc_set:
                continue
            assoc_set.add(key)
        else:
            if RuleTagAssociation.query.filter_by(rule_id=rule.id, tag_id=tag.id).first():
                continue

        db.session.add(RuleTagAssociation(
            uuid=str(uuid_mod.uuid4()),
            rule_id=rule.id,
            tag_id=tag.id,
            user_id=user_id,
            added_at=datetime.datetime.now(datetime.timezone.utc),
        ))
    return missing


def _sync_bundle_tags(bundle: Bundle, tag_names: list, user_id: int,
                      tag_cache: dict = None) -> set:
    """Same as _sync_tags but for bundles via BundleTagAssociation."""
    missing: set = set()
    auto_installed: set = set()

    for name in tag_names:
        tag = _ensure_tag(name, user_id, auto_installed, tag_cache)

        if tag is None:
            missing.add(name)
            continue

        if not tag.is_active:
            tag.is_active = True

        already = BundleTagAssociation.query.filter_by(bundle_id=bundle.id, tag_id=tag.id).first()
        if not already:
            db.session.add(BundleTagAssociation(
                uuid=str(uuid_mod.uuid4()),
                bundle_id=bundle.id,
                tag_id=tag.id,
                user_id=user_id,
                added_at=datetime.datetime.now(datetime.timezone.utc),
            ))
    return missing


def _sync_cve_ids(obj, remote_cve_ids: list, field: str = 'cve_id') -> None:
    """Merge remote CVE ids into the local object's CVE field (additive).

    Rules use field='cve_id', Bundles use field='vulnerability_identifiers'.
    """
    if not remote_cve_ids:
        return
    raw = getattr(obj, field, None)
    try:
        existing = _json.loads(raw) if raw else []
        if not isinstance(existing, list):
            existing = [existing] if existing else []
    except (TypeError, ValueError):
        existing = [raw] if raw else []

    merged = list(existing)
    for cid in remote_cve_ids:
        if cid and cid not in merged:
            merged.append(cid)

    if merged != existing:
        setattr(obj, field, _json.dumps(merged))


def _sync_attacks(rule, technique_ids: list, user_id: int,
                  atk_assoc_set: set = None) -> list:
    """Attach ATT&CK technique associations to a rule.

    Returns a list of technique_ids that don't exist locally (unknown techniques).
    If the local ATT&CK table is completely empty, returns the sentinel ['__empty__']
    so the caller knows to trigger an ATT&CK data install.
    """
    if not technique_ids:
        return []

    from app.core.db_class.db import AttackTechnique, RuleAttackAssociation
    import datetime as _dt

    # Check if ATT&CK data exists at all
    if not AttackTechnique.query.first():
        return ['__empty__']

    unknown = []
    for tid in technique_ids:
        tid = (tid or '').strip().upper()
        if not tid:
            continue
        technique = AttackTechnique.query.filter_by(technique_id=tid).first()
        if not technique:
            unknown.append(tid)
            continue
        key = (rule.id, tid)
        if atk_assoc_set is not None:
            if key in atk_assoc_set:
                continue
            atk_assoc_set.add(key)
        else:
            if RuleAttackAssociation.query.filter_by(rule_id=rule.id, technique_id=tid).first():
                continue
        db.session.add(RuleAttackAssociation(
            uuid=str(uuid_mod.uuid4()),
            rule_id=rule.id,
            technique_id=tid,
            user_id=user_id,
            source='connector',
            added_at=_dt.datetime.now(_dt.timezone.utc),
        ))
    return unknown


def _extract_tag_family(name: str) -> str | None:
    """Extract the tag family/namespace from a tag name.

    Examples:
        'tlp:clear'                      -> 'tlp'
        'pap:white'                      -> 'pap'
        'misp-galaxy:threat-actor="X"'  -> 'misp-galaxy:threat-actor'
    """
    if not name or ":" not in name:
        return None
    if name.startswith("misp-galaxy:"):
        suffix = name[len("misp-galaxy:"):]
        return "misp-galaxy:" + suffix.split("=")[0].rstrip('"').strip()
    return name.split(":")[0]


def import_tag_families(families: list, user) -> list:
    """Import tag families from MISP taxonomies/galaxies submodules.

    Returns a list of dicts: [{family, ok, msg}, ...].
    Families that start with 'misp-galaxy:' are imported from galaxies,
    others from taxonomies.
    """
    from app.features.tags.tags_core import (
        add_tags_from_misp_taxonomy,
        add_tags_from_misp_galaxy,
        get_all_taxonomy_uuids_from_disk,
        get_all_galaxy_uuids_from_disk,
    )
    ns_to_uid    = {ns: uid for uid, ns in get_all_taxonomy_uuids_from_disk()}
    gtype_to_uid = {gtype: uid for uid, gtype in get_all_galaxy_uuids_from_disk()}

    results = []
    for family in families:
        family = family.strip()
        if not family:
            continue
        if family.startswith("misp-galaxy:"):
            gtype = family[len("misp-galaxy:"):]
            uid   = gtype_to_uid.get(gtype)
            if uid:
                ok, msg = add_tags_from_misp_galaxy(uid, user)
            else:
                ok, msg = False, f"Galaxy type '{gtype}' not found on disk."
        else:
            uid = ns_to_uid.get(family)
            if uid:
                ok, msg = add_tags_from_misp_taxonomy(uid, user)
            else:
                ok, msg = False, f"Taxonomy '{family}' not found on disk."
        results.append({'family': family, 'ok': bool(ok), 'msg': msg})
    return results


def _sync_bundle_rules(bundle: Bundle, rule_uuids: list) -> int:
    """Attach local rules (matched by uuid) to the bundle.
    Additive only — never removes rules a local user added. Returns the
    number of new associations created."""
    added = 0
    for r_uuid in rule_uuids or []:
        rule = Rule.query.filter(
            Rule.is_deleted == False,
            or_(Rule.remote_rule_uuid == r_uuid, Rule.uuid == r_uuid),
        ).first()
        if rule is None:
            continue
        already = BundleRuleAssociation.query.filter_by(
            bundle_id=bundle.id, rule_id=rule.id,
        ).first()
        if already is None:
            db.session.add(BundleRuleAssociation(bundle_id=bundle.id, rule_id=rule.id))
            added += 1
    return added


def _upsert_bundle(connector: Connector, shadow_user_id: int, remote: dict,
                   triggered_by_id: int = None, tag_cache: dict = None) -> str:
    """Create or update a Bundle from a remote payload dict, then attach the
    local rules listed in remote['rules'] (rules are pulled before bundles,
    so they already exist locally when sync_rules is enabled).
    Returns 'created', 'updated', 'skipped', or 'invalid'.
    """
    remote_uuid = remote.get('uuid')
    if not remote_uuid:
        return 'invalid'

    owner_id = triggered_by_id if triggered_by_id else shadow_user_id

    existing = Bundle.query.filter_by(
        connector_id=connector.id,
        remote_bundle_uuid=remote_uuid,
    ).first()

    now = datetime.datetime.now(datetime.timezone.utc)

    if existing:
        added = _sync_bundle_rules(existing, remote.get('rules', []))
        _sync_bundle_tags(existing, remote.get('tags', []), owner_id, tag_cache=tag_cache)
        _sync_cve_ids(existing, remote.get('vulnerability_identifiers', []), field='vulnerability_identifiers')
        remote_ts = remote.get('updated_at')
        changed = False
        if remote_ts and existing.updated_at:
            try:
                remote_dt = datetime.datetime.fromisoformat(remote_ts.replace('Z', '+00:00')).replace(tzinfo=None)
                if remote_dt > existing.updated_at:
                    existing.name        = remote.get('name', existing.name)
                    existing.description = remote.get('description', existing.description)
                    existing.user_id     = owner_id
                    existing.updated_at  = now
                    changed = True
            except ValueError:
                pass
        return 'updated' if (added or changed) else 'skipped'

    bundle = Bundle(
        uuid=str(uuid_mod.uuid4()),
        remote_bundle_uuid=remote_uuid,
        connector_id=connector.id,
        user_id=owner_id,
        name=remote.get('name', ''),
        description=remote.get('description'),
        created_by='connector',
        access=True,
        vote_up=0,
        vote_down=0,
        created_at=now,
        updated_at=now,
    )
    db.session.add(bundle)
    db.session.flush()
    _sync_bundle_rules(bundle, remote.get('rules', []))
    _sync_bundle_tags(bundle, remote.get('tags', []), owner_id, tag_cache=tag_cache)
    _sync_cve_ids(bundle, remote.get('vulnerability_identifiers', []), field='vulnerability_identifiers')
    return 'created'
