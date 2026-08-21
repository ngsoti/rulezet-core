"""
job_handlers.py
Concrete job handlers for bulk tag operations.

Each handler writes structured log lines via log_job() so the UI can
display a real-time activity feed with timestamps and event types.

Resume support:
    '_resume_offset' is saved in job.payload after every batch.
    On restart/resume the handler reads it and skips already-processed rows.

Pause / Cancel support:
    _should_pause() and _is_cancelled() are checked between every batch.
"""

import datetime
import html as _html
import json
import os
import re
import subprocess
import sys
import uuid as uuid_mod
from pathlib import Path

from app.features.jobs.job_worker import register_handler
from app import db
from app.core.db_class.db import Rule, Tag, RuleTagAssociation, BackgroundJob, BackgroundJobLog, ActivityLog, RequestOwnerRule, User, GithubProposal
from app.features.rule.rule_core import _wipe_rule_children, create_rule_history, add_contributor
from app.core.utils.activity_log import log_activity

BATCH_SIZE = 2000   # bulk_insert_mappings handles large batches efficiently

LOG_EVERY  = 10     # write a progress log line every N batches


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def log_job(job, message, level='info', event=None):
    """Write one log line for the job. Commits immediately so the UI sees it."""
    try:
        entry = BackgroundJobLog(
            job_id=job.id,
            level=level,
            event=event,
            message=message,
            created_at=_now(),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[log_job] failed to write log: {e}")


def _reload(job):
    try:
        db.session.expire(job)
        db.session.refresh(job)
    except Exception:
        pass


def _is_cancelled(job):
    _reload(job)
    return job.status == 'cancelled'


def _should_pause(job):
    _reload(job)
    return job.status == 'paused'


def _save_offset(job, offset):
    payload = dict(job.payload or {})
    payload['_resume_offset'] = offset
    job.payload = payload


def _refresh_quality_scores(rule_ids):
    """Recompute quality_score for rules whose tags/ATT&CK associations just
    changed in bulk — these bulk handlers write via bulk_insert_mappings/
    delete() (no ORM Rule objects touched), so nothing else would trigger the
    per-write recompute hooks that live on the interactive routes."""
    rule_ids = [rid for rid in rule_ids if rid]
    if not rule_ids:
        return
    try:
        from app.features.rule.rule_quality.quality_score_core import build_batch_context, recompute_rule_quality_score
        batch_context = build_batch_context(rule_ids)
        for rule in Rule.query.filter(Rule.id.in_(rule_ids)).all():
            recompute_rule_quality_score(rule, commit=False, batch_context=batch_context)
        db.session.commit()
    except Exception:
        db.session.rollback()


def _append_transferred_ids(job, ids):
    """Accumulate transferred rule ids in job.payload so they survive a
    pause/resume cycle (each resume calls the handler fresh, so an in-memory
    list alone would lose everything gathered before the pause)."""
    payload = dict(job.payload or {})
    payload['_transferred_ids'] = payload.get('_transferred_ids', []) + list(ids)
    job.payload = payload


def _build_rule_query(payload):
    """
    Build a Rule query from the filter payload.
    Mirrors get_rules_page_filter params exactly so the job processes
    the same rules the user previewed in the UI.
    """
    from sqlalchemy import or_, func

    query = Rule.query

    # pick mode — only these specific rule IDs, skip all other filters
    if payload.get('rule_ids'):
        query = query.filter(Rule.id.in_(payload['rule_ids']))
        return query

    # excluded_ids — used in 'all' mode when user deselected some rows
    excluded = payload.get('excluded_ids', [])
    if excluded:
        query = query.filter(Rule.id.notin_(excluded))

    # search
    search = payload.get('search')
    if search:
        search        = search.strip()
        search_field  = payload.get('search_field', 'all')
        exact_match   = payload.get('exact_match', False)

        if exact_match:
            if search_field == 'title':
                query = query.filter(Rule.title == search)
            elif search_field == 'content':
                query = query.filter(Rule.to_string.like(f"%{search}%"))
            else:
                query = query.filter(or_(Rule.title == search,
                                         Rule.to_string.like(f"%{search}%")))
        else:
            s = f"%{search.lower()}%"
            if search_field == 'title':
                query = query.filter(Rule.title.ilike(s))
            elif search_field == 'content':
                query = query.filter(Rule.to_string.ilike(s))
            else:
                query = query.filter(or_(
                    Rule.title.ilike(s),
                    Rule.description.ilike(s),
                    Rule.format.ilike(s),
                    Rule.author.ilike(s),
                    Rule.to_string.ilike(s),
                    Rule.uuid.ilike(s),
                ))

    # format / rule_type
    fmt = payload.get('rule_type') or payload.get('format')
    if fmt:
        query = query.filter(Rule.format.ilike(f"%{fmt}%"))

    # author (single, free-text `Rule.author` field)
    if payload.get('author'):
        query = query.filter(Rule.author.ilike(f"%{payload['author'].lower()}%"))

    # authors (plural, comma-separated — same free-text `Rule.author` field,
    # sent by ruleList.js's "select all matching" when person_mode='author')
    if payload.get('authors'):
        author_list = [a.strip() for a in payload['authors'].split(',') if a.strip()]
        if author_list:
            query = query.filter(or_(*[Rule.author.ilike(f"%{a}%") for a in author_list]))

    # editors (comma-separated) — the rule's owning User account (username or
    # first+last name), not the free-text `author` field. Mirrors filter_rules'
    # editor_names handling exactly so "select all matching" scopes the same
    # way the on-screen list did.
    if payload.get('editors'):
        editor_list = [e.strip() for e in payload['editors'].split(',') if e.strip()]
        if editor_list:
            editor_col = func.coalesce(User.username, func.concat(User.first_name, ' ', User.last_name))
            query = (query
                     .join(User, User.id == Rule.user_id)
                     .filter(or_(*[editor_col.ilike(f"%{e}%") for e in editor_list])))

    # user_id
    if payload.get('user_id'):
        query = query.filter(Rule.user_id == int(payload['user_id']))

    # sources (comma-separated string)
    if payload.get('sources'):
        src_list = [s.strip() for s in payload['sources'].split(',') if s.strip()]
        if src_list:
            query = query.filter(or_(*[Rule.source.ilike(f"%{s}%") for s in src_list]))

    # licenses (comma-separated string)
    if payload.get('licenses'):
        lic_list = [l.strip() for l in payload['licenses'].split(',') if l.strip()]
        if lic_list:
            query = query.filter(or_(*[Rule.license.ilike(f"%{l}%") for l in lic_list]))

    # vulnerabilities / CVEs (comma-separated string)
    if payload.get('vulnerabilities'):
        vuln_list = [v.strip() for v in payload['vulnerabilities'].split(',') if v.strip()]
        if vuln_list:
            query = query.filter(or_(*[Rule.cve_id.ilike(f'%"{v}"%') for v in vuln_list]))

    # filter rules that already have certain tags (comma-separated tag names)
    if payload.get('tags'):
        tag_names = [t.strip().lower() for t in payload['tags'].split(',') if t.strip()]
        if tag_names:
            found    = Tag.query.filter(func.lower(Tag.name).in_(tag_names)).all()
            tag_ids  = [t.id for t in found]
            if tag_ids:
                query = query.join(RuleTagAssociation, Rule.id == RuleTagAssociation.rule_id)\
                             .filter(RuleTagAssociation.tag_id.in_(tag_ids))\
                             .distinct()

    # sort
    sort_by = payload.get('sort_by', 'newest')
    if sort_by == 'oldest':
        query = query.order_by(Rule.creation_date.asc())
    elif sort_by == 'most_likes':
        query = query.order_by(Rule.vote_up.desc())
    elif sort_by == 'least_likes':
        query = query.order_by(Rule.vote_down.desc())
    else:
        query = query.order_by(Rule.creation_date.desc())

    return query


# ─── bulk_add_tag_to_rules ────────────────────────────────────────────────────

@register_handler('bulk_add_tag_to_rules')
def handle_bulk_add_tag_to_rules(job, app):
    payload = job.payload or {}
    tag_ids = payload.get('tag_ids', [])
    filters = payload.get('filters', {})
    user_id = payload.get('user_id')
    offset  = payload.get('_resume_offset', 0)

    if not tag_ids:
        raise ValueError("No tag_ids provided.")

    tags = Tag.query.filter(Tag.id.in_(tag_ids)).all()
    if not tags:
        raise ValueError("None of the provided tags were found.")

    tag_names = ', '.join(t.name for t in tags)
    rule_query = _build_rule_query(filters)

    # ── First run: compute total and log start ────────────────────────────────
    if job.total == 0:
        job.total = rule_query.count()
        db.session.commit()

        filter_desc = []
        if filters.get('search'):   filter_desc.append(f"search={filters['search']}")
        if filters.get('format'):   filter_desc.append(f"format={filters['format']}")
        if filters.get('rule_type'): filter_desc.append(f"format={filters['rule_type']}")
        if filters.get('author'):   filter_desc.append(f"author={filters['author']}")
        if filters.get('sources'):  filter_desc.append(f"source={filters['sources']}")
        if filters.get('rule_ids'): filter_desc.append(f"{len(filters['rule_ids'])} rule(s) manually selected")
        filter_str = ' · '.join(filter_desc) if filter_desc else 'all rules'

        log_job(job,
            f"Job started — {job.total} rule(s) targeted · tags: {tag_names} · filters: {filter_str}",
            level='info', event='started')

    # ── Resume: log that we are picking up where we left off ──────────────────
    elif offset > 0:
        log_job(job,
            f"Resuming from offset {offset} ({offset}/{job.total} already processed, "
            f"{job.progress_pct}% done)",
            level='info', event='resumed')

    if job.total == 0:
        log_job(job, "No rules matched the filters — nothing to do.", level='warning', event='done')
        return

    # ── Pre-load existing associations in one query ───────────────────────────
    existing = set(
        db.session.query(
            RuleTagAssociation.rule_id,
            RuleTagAssociation.tag_id,
        ).filter(
            RuleTagAssociation.tag_id.in_(tag_ids)
        ).all()
    )
    log_job(job,
        f"Loaded {len(existing)} existing association(s) to skip — starting bulk insert.",
        level='info', event='preload')

    batch_num   = 0
    total_added = 0
    added_at    = _now()

    while True:
        # ── Check cancel / pause ──────────────────────────────────────────────
        if _is_cancelled(job):
            log_job(job,
                f"Job cancelled at offset {offset} ({job.progress_pct}% done — "
                f"{total_added} association(s) added so far).",
                level='warning', event='cancelled')
            return

        if _should_pause(job):
            _save_offset(job, offset)
            db.session.commit()
            log_job(job,
                f"Job paused at offset {offset} ({job.progress_pct}% done — "
                f"{total_added} association(s) added so far). "
                f"Click Resume to continue.",
                level='info', event='paused')
            return

        # ── Fetch next batch of rule IDs (+ title/content/owner for history
        #    entries and contributor crediting) ──
        batch_rows = rule_query.with_entities(Rule.id, Rule.title, Rule.to_string, Rule.user_id) \
                                .offset(offset).limit(BATCH_SIZE).all()
        batch_ids = [r[0] for r in batch_rows]
        if not batch_ids:
            break

        # ── Build insert list — skip already-existing pairs ───────────────────
        to_insert = [
            {
                "uuid":     str(uuid_mod.uuid4()),
                "rule_id":  rule_id,
                "tag_id":   tag_id,
                "user_id":  user_id,
                "added_at": added_at,
            }
            for rule_id in batch_ids
            for tag_id  in tag_ids
            if (rule_id, tag_id) not in existing
        ]

        if to_insert:
            db.session.bulk_insert_mappings(RuleTagAssociation, to_insert)
            for row in to_insert:
                existing.add((row["rule_id"], row["tag_id"]))
            total_added += len(to_insert)

            # A bulk tag operation is otherwise invisible in a rule's own
            # history — the UI-driven quick_meta path records this, and a
            # caller shouldn't get weaker auditing just for using the bulk
            # job. One entry per rule that actually gained a tag here.
            #
            # old/new snapshot only needs the "tags" key: diff_rule_snapshots
            # renders it as a set difference (added = new - old), so an empty
            # old list + the names actually added to THIS rule is enough to
            # show "Tags added: x, y" correctly — no need to fetch every tag
            # already on the rule just to reproduce a value the diff discards.
            tag_name_by_id = {t.id: t.name for t in tags}
            added_names_by_rule = {}
            for row in to_insert:
                added_names_by_rule.setdefault(row["rule_id"], []).append(tag_name_by_id[row["tag_id"]])

            for rule_id, rule_title, rule_content, rule_owner_id in batch_rows:
                added_names = added_names_by_rule.get(rule_id)
                if not added_names:
                    continue
                create_rule_history({
                    "id": rule_id,
                    "title": rule_title,
                    "success": True,
                    "manual_submit": False,
                    "message": f"Bulk-tagged with: {tag_names}",
                    "new_content": rule_content,
                    "old_content": rule_content,
                    "old_snapshot": {"tags": []},
                    "new_snapshot": {"tags": sorted(added_names)},
                    "change_type": "metadata",
                    "analyzed_by_user_id": user_id,
                })
                # Credit whoever ran the bulk tag as a contributor — same
                # treatment a manual/quick_meta tag edit already gets — but
                # only when they don't already own the rule (no self-credit).
                if user_id and user_id != rule_owner_id:
                    add_contributor(user_id, rule_id)

            _refresh_quality_scores(added_names_by_rule.keys())

        offset    += len(batch_ids)
        batch_num += 1
        job.done   = offset
        _save_offset(job, offset)
        db.session.commit()

        # ── Periodic progress log ─────────────────────────────────────────────
        if batch_num % LOG_EVERY == 0:
            log_job(job,
                f"Progress: {job.done}/{job.total} rules ({job.progress_pct}%) — "
                f"{total_added} association(s) added so far.",
                level='info', event='progress')

    # ── Done ──────────────────────────────────────────────────────────────────
    log_job(job,
        f"Completed — {job.total} rule(s) processed, "
        f"{total_added} new association(s) created, "
        f"{len(existing) - total_added} skipped (already existed).",
        level='success', event='done')


# ─── bulk_remove_tag_from_rules ───────────────────────────────────────────────

@register_handler('bulk_remove_tag_from_rules')
def handle_bulk_remove_tag_from_rules(job, app):
    payload = job.payload or {}
    tag_ids = payload.get('tag_ids', [])
    filters = payload.get('filters', {})
    offset  = payload.get('_resume_offset', 0)

    tags = Tag.query.filter(Tag.id.in_(tag_ids)).all()
    tag_names = ', '.join(t.name for t in tags) if tags else str(tag_ids)

    rule_query = _build_rule_query(filters)

    if job.total == 0:
        job.total = rule_query.count()
        db.session.commit()

        filter_desc = []
        if filters.get('search'):   filter_desc.append(f"search={filters['search']}")
        if filters.get('format'):   filter_desc.append(f"format={filters['format']}")
        if filters.get('rule_type'): filter_desc.append(f"format={filters['rule_type']}")
        if filters.get('author'):   filter_desc.append(f"author={filters['author']}")
        if filters.get('sources'):  filter_desc.append(f"source={filters['sources']}")
        if filters.get('rule_ids'): filter_desc.append(f"{len(filters['rule_ids'])} rule(s) manually selected")
        filter_str = ' · '.join(filter_desc) if filter_desc else 'all rules'

        log_job(job,
            f"Job started — {job.total} rule(s) targeted · tags to remove: {tag_names} · filters: {filter_str}",
            level='info', event='started')

    elif offset > 0:
        log_job(job,
            f"Resuming from offset {offset} ({job.progress_pct}% done).",
            level='info', event='resumed')

    if job.total == 0:
        log_job(job, "No rules matched the filters — nothing to do.", level='warning', event='done')
        return

    all_rule_ids = [r[0] for r in rule_query.with_entities(Rule.id).all()]

    batch_num     = 0
    total_removed = 0

    while offset < len(all_rule_ids):
        if _is_cancelled(job):
            log_job(job,
                f"Job cancelled at offset {offset} ({job.progress_pct}% done — "
                f"{total_removed} association(s) removed so far).",
                level='warning', event='cancelled')
            return

        if _should_pause(job):
            _save_offset(job, offset)
            db.session.commit()
            log_job(job,
                f"Job paused at offset {offset} ({job.progress_pct}% done — "
                f"{total_removed} association(s) removed so far). "
                f"Click Resume to continue.",
                level='info', event='paused')
            return

        chunk = all_rule_ids[offset:offset + BATCH_SIZE]

        deleted = RuleTagAssociation.query.filter(
            RuleTagAssociation.rule_id.in_(chunk),
            RuleTagAssociation.tag_id.in_(tag_ids),
        ).delete(synchronize_session=False)

        if deleted:
            _refresh_quality_scores(chunk)

        offset        += len(chunk)
        batch_num     += 1
        total_removed += deleted
        job.done       = offset
        _save_offset(job, offset)
        db.session.commit()

        if batch_num % LOG_EVERY == 0:
            log_job(job,
                f"Progress: {job.done}/{job.total} rules ({job.progress_pct}%) — "
                f"{total_removed} association(s) removed so far.",
                level='info', event='progress')

    log_job(job,
        f"Completed — {job.total} rule(s) processed, "
        f"{total_removed} association(s) removed.",
        level='success', event='done')


# ─── compute_rule_quality_score ────────────────────────────────────────────────

@register_handler('compute_rule_quality_score')
def handle_compute_rule_quality_score(job, app):
    """Bulk (re)analyze rules for the quality-score dashboard — 'analyze all'
    or 'analyze selection' from the admin panel. Same shape as
    bulk_add_tag_to_rules: _build_rule_query() handles both 'rule_ids'
    (RuleList select-mode picks) and the full filter set (RuleList
    'select all matching filters')."""
    from app.features.rule.rule_quality.quality_score_core import build_batch_context, recompute_rule_quality_score

    payload = job.payload or {}
    filters = payload.get('filters', {})
    offset  = payload.get('_resume_offset', 0)

    rule_query = _build_rule_query(filters)

    if job.total == 0:
        job.total = rule_query.count()
        db.session.commit()

        filter_desc = []
        if filters.get('search'):    filter_desc.append(f"search={filters['search']}")
        if filters.get('format'):    filter_desc.append(f"format={filters['format']}")
        if filters.get('rule_type'): filter_desc.append(f"format={filters['rule_type']}")
        if filters.get('author'):    filter_desc.append(f"author={filters['author']}")
        if filters.get('sources'):   filter_desc.append(f"source={filters['sources']}")
        if filters.get('rule_ids'):  filter_desc.append(f"{len(filters['rule_ids'])} rule(s) manually selected")
        filter_str = ' · '.join(filter_desc) if filter_desc else 'all rules'

        log_job(job,
            f"Job started — {job.total} rule(s) targeted · filters: {filter_str}",
            level='info', event='started')
    elif offset > 0:
        log_job(job,
            f"Resuming from offset {offset} ({offset}/{job.total} already processed, "
            f"{job.progress_pct}% done)",
            level='info', event='resumed')

    if job.total == 0:
        log_job(job, "No rules matched the filters — nothing to do.", level='warning', event='done')
        return

    batch_num = 0
    analyzed  = 0

    while True:
        if _is_cancelled(job):
            log_job(job,
                f"Job cancelled at offset {offset} ({job.progress_pct}% done — {analyzed} rule(s) analyzed so far).",
                level='warning', event='cancelled')
            return

        if _should_pause(job):
            _save_offset(job, offset)
            db.session.commit()
            log_job(job,
                f"Job paused at offset {offset} ({job.progress_pct}% done — {analyzed} rule(s) analyzed so far). "
                f"Click Resume to continue.",
                level='info', event='paused')
            return

        batch = rule_query.offset(offset).limit(BATCH_SIZE).all()
        if not batch:
            break

        # One query per signal for the whole batch instead of ~5 per rule —
        # this is what made a full "analyze all" run take hours instead of
        # minutes at 300k+ rules.
        batch_context = build_batch_context([r.id for r in batch])
        for rule in batch:
            try:
                recompute_rule_quality_score(rule, commit=False, batch_context=batch_context)
                analyzed += 1
            except Exception as e:
                log_job(job, f"Failed to score rule #{rule.id} ({rule.title}): {e}",
                         level='error', event='rule_error')
        db.session.commit()

        offset    += len(batch)
        batch_num += 1
        job.done   = offset
        _save_offset(job, offset)
        db.session.commit()

        if batch_num % LOG_EVERY == 0:
            log_job(job,
                f"Progress: {job.done}/{job.total} rules ({job.progress_pct}%) — {analyzed} analyzed so far.",
                level='info', event='progress')

    log_job(job,
        f"Completed — {analyzed}/{job.total} rule(s) analyzed.",
        level='success', event='done')


# ─── delete_github_rules ──────────────────────────────────────────────────────

@register_handler('delete_github_rules')
def handle_delete_github_rules(job, app):
    """
    Soft-delete all rules from the given GitHub source URLs.
    Rules are moved to the trash (is_deleted=True) and can be restored by an admin.

    Payload:
        urls : list[str] — GitHub source URLs
    """
    import uuid as _uuid
    import datetime

    payload = job.payload or {}
    urls    = payload.get('urls', [])
    if not urls:
        raise ValueError("No URLs provided.")

    # Count active rules for these sources
    initial = Rule.query.filter(Rule.source.in_(urls), Rule.is_deleted == False).count()
    if job.total == 0:
        job.total = initial
        db.session.commit()
        log_job(job, f"Job started — {initial} rule(s) to move to trash from: {', '.join(urls)}",
                level='info', event='started')

    if initial == 0:
        log_job(job, "No active rules found — nothing to delete.", level='warning', event='done')
        return

    batch_uuid = payload.get('batch_uuid') or str(_uuid.uuid4())
    now        = datetime.datetime.now(tz=datetime.timezone.utc)
    created_by = job.created_by

    # Soft-delete in one bulk update
    updated = Rule.query.filter(Rule.source.in_(urls), Rule.is_deleted == False).update(
        {"is_deleted": True, "deleted_at": now, "deleted_by_id": created_by, "delete_batch_uuid": batch_uuid},
        synchronize_session=False,
    )
    db.session.commit()

    job.done = updated
    db.session.commit()

    log_job(job, f"Completed — {updated} rule(s) moved to trash (batch: {batch_uuid[:8]}).",
            level='success', event='done')


# ─── delete_activity_logs ─────────────────────────────────────────────────────

LOG_DELETE_BATCH = 1000


@register_handler('delete_activity_logs')
def handle_delete_activity_logs(job, app):
    """Delete activity log entries in batches.

    Payload keys:
      log_ids      list[int]  — specific IDs to delete (ignored if delete_all=True)
      delete_all   bool       — delete everything (filtered by action_filter if set)
      action_filter str       — optional action prefix to filter when delete_all=True
    """
    payload      = job.payload or {}
    log_ids      = payload.get('log_ids', [])
    delete_all   = payload.get('delete_all', False)
    action_filter = payload.get('action_filter', '')

    log_job(job, "Starting activity log deletion…", level='info', event='started')

    if delete_all:
        q = ActivityLog.query
        if action_filter:
            q = q.filter(ActivityLog.action.ilike(f'{action_filter}%'))
        total = q.count()
    else:
        log_ids = [int(i) for i in log_ids if str(i).isdigit()]
        total = len(log_ids)

    job.total = total
    job.done  = 0
    db.session.commit()

    if total == 0:
        log_job(job, "Nothing to delete.", level='info', event='done')
        return

    deleted = 0

    if delete_all:
        q = ActivityLog.query
        if action_filter:
            q = q.filter(ActivityLog.action.ilike(f'{action_filter}%'))

        offset = payload.get('_resume_offset', 0)

        while True:
            if _is_cancelled(job):
                log_job(job, f"Cancelled — {deleted} deleted so far.", level='warning', event='cancelled')
                return
            if _should_pause(job):
                _save_offset(job, offset)
                db.session.commit()
                log_job(job, f"Paused — {deleted} deleted so far.", level='warning', event='paused')
                while _should_pause(job):
                    import time; time.sleep(1)
                log_job(job, "Resumed.", level='info', event='resumed')

            batch_ids = [r.id for r in ActivityLog.query
                         .filter(ActivityLog.action.ilike(f'{action_filter}%') if action_filter else db.true())
                         .order_by(ActivityLog.id)
                         .offset(offset)
                         .limit(LOG_DELETE_BATCH)
                         .with_entities(ActivityLog.id)
                         .all()]
            if not batch_ids:
                break

            ActivityLog.query.filter(ActivityLog.id.in_(batch_ids)).delete(synchronize_session=False)
            db.session.commit()
            deleted += len(batch_ids)
            job.done = deleted
            db.session.commit()
            log_job(job, f"Deleted {deleted}/{total} log(s).", level='info', event='progress')
    else:
        for i in range(0, len(log_ids), LOG_DELETE_BATCH):
            if _is_cancelled(job):
                log_job(job, f"Cancelled — {deleted} deleted.", level='warning', event='cancelled')
                return

            batch = log_ids[i:i + LOG_DELETE_BATCH]
            ActivityLog.query.filter(ActivityLog.id.in_(batch)).delete(synchronize_session=False)
            db.session.commit()
            deleted += len(batch)
            job.done = deleted
            db.session.commit()

    log_job(job, f"Done — {deleted} activity log(s) deleted.", level='success', event='done')


# ─── update_misp_data ─────────────────────────────────────────────────────────

ROOT_DIR = Path(__file__).resolve().parents[3]   # rulezet-core/
TAX_PATH = ROOT_DIR / "app" / "modules" / "misp-taxonomies"
GAL_PATH = ROOT_DIR / "app" / "modules" / "misp-galaxy"


def _git_submodule_update(submodule_path: Path) -> tuple[bool, str]:
    """Update a git submodule to its latest upstream commit.

    Submodules are always in detached-HEAD state, so `git pull` inside them
    fails. The correct command is `git submodule update --remote` run from
    the project root, passing the relative submodule path.
    """
    try:
        rel = submodule_path.relative_to(ROOT_DIR)
        r = subprocess.run(
            ["git", "submodule", "update", "--remote", "--merge", str(rel)],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = (r.stdout + r.stderr).strip()
        return r.returncode == 0, output or "Already up to date."
    except Exception as e:
        return False, str(e)


@register_handler('update_misp_data')
def handle_update_misp_data(job, app):
    """3-step MISP data update:
      Step 1 — git pull both submodules
      Step 2 — update ALREADY-IMPORTED taxonomies only (add new tags, skip existing)
      Step 3 — update ALREADY-IMPORTED galaxies only (add new clusters, skip existing)
    """
    from app.core.db_class.db import User
    from app.features.tags import tags_core

    user = User.query.get(job.created_by)
    if not user:
        log_job(job, "User not found — aborting.", level='error', event='error')
        return

    # ── Step 1: git pull ──────────────────────────────────────────────────────
    log_job(job, "Step 1 — Pulling latest MISP data from GitHub…",
            level='info', event='step1_start')
    job.total = 3
    job.done  = 0
    db.session.commit()

    tax_ok, tax_out = _git_submodule_update(TAX_PATH)
    log_job(job,
            f"misp-taxonomies: {tax_out}",
            level='success' if tax_ok else 'warning',
            event='step1_tax_pull')

    gal_ok, gal_out = _git_submodule_update(GAL_PATH)
    log_job(job,
            f"misp-galaxy: {gal_out}",
            level='success' if gal_ok else 'warning',
            event='step1_gal_pull')

    job.done = 1
    db.session.commit()
    log_job(job, "Step 1 done.", level='success', event='step1_done')

    # ── Step 2: update already-imported taxonomies only ───────────────────────
    tax_list = tags_core.get_imported_taxonomy_uuids_from_disk()
    log_job(job,
            f"Step 2 — Updating {len(tax_list)} imported taxonomy(ies)…",
            level='info', event='step2_start')

    updated_t = 0
    uptodate_t = 0
    error_t = 0

    for uid, ns in tax_list:
        if _is_cancelled(job):
            log_job(job, "Cancelled during taxonomy update.", level='warning', event='cancelled')
            return

        ok, msg = tags_core.update_tags_from_misp_taxonomy(uid, user)
        if ok is True and "up to date" in msg:
            uptodate_t += 1
        elif ok is True:
            updated_t += 1
            log_job(job, f"[taxonomy] {msg}", level='success', event='step2_progress')
        else:
            error_t += 1
            log_job(job, f"[taxonomy] {msg}", level='warning', event='step2_progress')

    job.done = 2
    db.session.commit()
    log_job(job,
            f"Step 2 done — {updated_t} updated, {uptodate_t} already up to date, {error_t} errors.",
            level='success', event='step2_done')

    # ── Step 3: update already-imported galaxies only ────────────────────────
    gal_list = tags_core.get_imported_galaxy_uuids_from_disk()
    log_job(job,
            f"Step 3 — Updating {len(gal_list)} imported galaxy(ies)…",
            level='info', event='step3_start')

    updated_g  = 0
    uptodate_g = 0
    error_g    = 0

    for uid, gtype in gal_list:
        if _is_cancelled(job):
            log_job(job, "Cancelled during galaxy update.", level='warning', event='cancelled')
            return

        ok, msg = tags_core.update_tags_from_misp_galaxy(uid, user)
        if ok is True and "up to date" in msg:
            uptodate_g += 1
        elif ok is True:
            updated_g += 1
            log_job(job, f"[galaxy] {msg}", level='success', event='step3_progress')
        else:
            error_g += 1
            log_job(job, f"[galaxy] {msg}", level='warning', event='step3_progress')

    job.done = 3
    db.session.commit()
    log_job(job,
            f"Step 3 done — {updated_g} updated, {uptodate_g} already up to date, {error_g} errors.",
            level='success', event='step3_done')

    log_job(job, "All done. Your imported MISP data is up to date.", level='success', event='done')


# ─── MISP: import ALL taxonomies / galaxies (new + already-imported) ────────

@register_handler('import_all_taxonomies')
def handle_import_all_taxonomies(job, app):
    """Import every taxonomy found on disk — brand new ones included.
    add_tags_from_misp_taxonomy() already skips a namespace that's already
    imported, so this is safe to re-run."""
    from app.core.db_class.db import User
    from app.features.tags import tags_core

    user = User.query.get(job.created_by)
    if not user:
        log_job(job, "User not found — aborting.", level='error', event='error')
        return

    tax_list = tags_core.get_all_taxonomy_uuids_from_disk()
    job.total = len(tax_list)
    job.done  = 0
    db.session.commit()
    log_job(job, f"Found {len(tax_list)} taxonomy(ies) on disk — importing…",
            level='info', event='start')

    imported, skipped, error = 0, 0, 0
    for i, (uid, ns) in enumerate(tax_list, start=1):
        if _is_cancelled(job):
            log_job(job, "Cancelled.", level='warning', event='cancelled')
            return
        while _should_pause(job):
            import time; time.sleep(2)

        ok, msg = tags_core.add_tags_from_misp_taxonomy(uid, user)
        if ok is True and "already imported" in msg:
            skipped += 1
        elif ok is True:
            imported += 1
            log_job(job, f"[{ns}] {msg}", level='success', event='progress')
        else:
            error += 1
            log_job(job, f"[{ns}] {msg}", level='warning', event='progress')

        job.done = i
        db.session.commit()

    log_job(job,
            f"Done — {imported} taxonomy(ies) imported, {skipped} already present, {error} errors.",
            level='success', event='done')


@register_handler('import_all_galaxies')
def handle_import_all_galaxies(job, app):
    """Import every galaxy found on disk — brand new ones included.
    add_tags_from_misp_galaxy() already skips a type that's already
    imported, so this is safe to re-run."""
    from app.core.db_class.db import User
    from app.features.tags import tags_core

    user = User.query.get(job.created_by)
    if not user:
        log_job(job, "User not found — aborting.", level='error', event='error')
        return

    gal_list = tags_core.get_all_galaxy_uuids_from_disk()
    job.total = len(gal_list)
    job.done  = 0
    db.session.commit()
    log_job(job, f"Found {len(gal_list)} galaxy(ies) on disk — importing…",
            level='info', event='start')

    imported, skipped, error = 0, 0, 0
    for i, (uid, gtype) in enumerate(gal_list, start=1):
        if _is_cancelled(job):
            log_job(job, "Cancelled.", level='warning', event='cancelled')
            return
        while _should_pause(job):
            import time; time.sleep(2)

        ok, msg = tags_core.add_tags_from_misp_galaxy(uid, user)
        if ok is True and "already imported" in msg:
            skipped += 1
        elif ok is True:
            imported += 1
            log_job(job, f"[{gtype}] {msg}", level='success', event='progress')
        else:
            error += 1
            log_job(job, f"[{gtype}] {msg}", level='warning', event='progress')

        job.done = i
        db.session.commit()

    log_job(job,
            f"Done — {imported} galaxy(ies) imported, {skipped} already present, {error} errors.",
            level='success', event='done')

# ─── trash_restore_bulk ───────────────────────────────────────────────────────

TRASH_BATCH = 200


@register_handler('trash_restore_bulk')
def handle_trash_restore_bulk(job, app):
    """
    Restore soft-deleted rules in batches.

    Payload:
        ids          : list[int]  — specific rule IDs to restore (optional)
        restore_all  : bool       — restore every rule in the trash
        batch_uuid   : str        — restore all rules sharing this batch UUID
    """
    import datetime as _dt
    payload    = job.payload or {}
    restore_all = payload.get('restore_all', False)
    batch_uuid  = payload.get('batch_uuid')
    ids         = payload.get('ids', [])

    # Build the target query
    query = Rule.query.filter(Rule.is_deleted == True)
    if restore_all:
        pass  # all deleted rules
    elif batch_uuid:
        query = query.filter(Rule.delete_batch_uuid == batch_uuid)
    elif ids:
        query = query.filter(Rule.id.in_(ids))
    else:
        log_job(job, "No target specified.", level='warning', event='done')
        return

    total = query.count()
    if job.total == 0:
        job.total = total
        db.session.commit()
        log_job(job, f"Job started — {total} rule(s) to restore.", level='info', event='started')

    if total == 0:
        log_job(job, "No deleted rules found.", level='warning', event='done')
        return

    offset = payload.get('_resume_offset', 0)
    restored = 0
    all_ids  = [r[0] for r in query.with_entities(Rule.id).all()]

    for i in range(offset, len(all_ids), TRASH_BATCH):
        if _is_cancelled(job):
            log_job(job, "Cancelled.", level='warning', event='cancelled')
            return
        while _should_pause(job):
            import time; time.sleep(2)
        chunk = all_ids[i:i + TRASH_BATCH]
        now   = _dt.datetime.now(tz=_dt.timezone.utc)
        Rule.query.filter(Rule.id.in_(chunk), Rule.is_deleted == True).update(
            {"is_deleted": False, "deleted_at": None, "deleted_by_id": None, "delete_batch_uuid": None},
            synchronize_session=False,
        )
        db.session.commit()
        restored  += len(chunk)
        job.done   = restored
        _save_offset(job, i + TRASH_BATCH)
        db.session.commit()
        log_job(job, f"{restored}/{total} rule(s) restored.", level='info', event='progress')

    log_job(job, f"Done — {restored} rule(s) restored.", level='success', event='done')


# ─── trash_permanent_delete_bulk ──────────────────────────────────────────────

@register_handler('trash_permanent_delete_bulk')
def handle_trash_permanent_delete_bulk(job, app):
    """
    Permanently delete soft-deleted rules in batches (irreversible).

    Payload:
        ids          : list[int]  — specific rule IDs
        delete_all   : bool       — delete every rule in the trash
        batch_uuid   : str        — delete all rules sharing this batch UUID
    """
    payload    = job.payload or {}
    delete_all = payload.get('delete_all', False)
    batch_uuid = payload.get('batch_uuid')
    ids        = payload.get('ids', [])

    query = Rule.query.filter(Rule.is_deleted == True)
    if delete_all:
        pass
    elif batch_uuid:
        query = query.filter(Rule.delete_batch_uuid == batch_uuid)
    elif ids:
        query = query.filter(Rule.id.in_(ids))
    else:
        log_job(job, "No target specified.", level='warning', event='done')
        return

    total = query.count()
    if job.total == 0:
        job.total = total
        db.session.commit()
        log_job(job, f"Job started — {total} rule(s) to permanently delete.", level='info', event='started')

    if total == 0:
        log_job(job, "No rules found.", level='warning', event='done')
        return

    offset  = payload.get('_resume_offset', 0)
    deleted = 0
    all_ids = [r[0] for r in query.with_entities(Rule.id).all()]

    for i in range(offset, len(all_ids), TRASH_BATCH):
        if _is_cancelled(job):
            log_job(job, "Cancelled.", level='warning', event='cancelled')
            return
        while _should_pause(job):
            import time; time.sleep(2)
        chunk = all_ids[i:i + TRASH_BATCH]
        _wipe_rule_children(chunk)
        Rule.query.filter(Rule.id.in_(chunk), Rule.is_deleted == True).delete(synchronize_session=False)
        db.session.commit()
        deleted  += len(chunk)
        job.done  = deleted
        _save_offset(job, i + TRASH_BATCH)
        db.session.commit()
        log_job(job, f"{deleted}/{total} rule(s) permanently deleted.", level='info', event='progress')

    log_job(job, f"Done — {deleted} rule(s) permanently deleted.", level='success', event='done')


# ─── Connector pull ───────────────────────────────────────────────────────────

@register_handler('connector_pull')
def handle_connector_pull(job, app):
    """
    Pull rules (and optionally bundles) from a remote Rulezet instance.

    Payload:
        connector_id : int — local Connector.id to pull from
    """
    import datetime
    import requests as http_requests
    from concurrent.futures import ThreadPoolExecutor
    from app.core.db_class.db import Connector, Rule, RuleTagAssociation
    from app.features.connector.connector_core import (
        _get_or_create_shadow_user, _upsert_rule, _upsert_bundle,
        _extract_tag_family, build_tag_cache,
        _prepare_new_rule, _import_rule_history_new, _sync_tags, _sync_cve_ids, _sync_attacks,
    )
    from app.core.utils.activity_log import log_activity
    from sqlalchemy import or_

    import time as _time

    payload      = job.payload or {}
    connector_id = payload.get('connector_id')
    job_uuid     = job.uuid
    t_start      = _time.monotonic()

    with app.app_context():
        from app.core.db_class.db import BackgroundJob as BJ
        job = BJ.query.filter_by(uuid=job_uuid).first()
        connector = Connector.query.get(connector_id)
        if not connector or not connector.is_active:
            job.status = 'failed'
            job.error  = 'Connector not found or inactive.'
            db.session.commit()
            return

        if connector.owner_mode == 'self':
            effective_user_id = connector.owner_id
        else:
            shadow = _get_or_create_shadow_user(connector)
            effective_user_id = shadow.id
        headers = {'Accept': 'application/json'}
        if connector.api_key_outbound:
            headers['X-API-KEY'] = connector.api_key_outbound
        # Identify this instance on the remote so it can track pull history
        try:
            from app.core.db_class.db import InstanceConfig as _IC
            import os as _os
            _cfg = _IC.query.first()
            if _cfg:
                headers['X-Rulezet-Instance-UUID'] = str(_cfg.uuid)
            _pub = _os.environ.get('INSTANCE_PUBLIC_URL') or ''
            if _pub:
                headers['X-Rulezet-Instance-URL'] = _pub
        except Exception:
            pass

        # Per-pull content overrides (from trigger payload, fall back to connector flags)
        do_rules   = payload.get('sync_rules',   connector.sync_rules)
        do_bundles = payload.get('sync_bundles', connector.sync_bundles)


        since    = '1970-01-01T00:00:00'
        base     = connector.instance_url.rstrip('/')
        PER_PAGE = 500    # safe page size — remote serialises 500 rules per request

        # ── Build filter query-string params from the pull payload ──────────
        pull_filters = payload.get('filters', {}) or {}

        def _names_from_groups(groups, include_exclude=False):
            """Extract names from [{names, mode, exclude}, ...] filter groups.
            With include_exclude=False (default) only include non-excluded groups."""
            result = []
            for grp in (groups or []):
                if not isinstance(grp, dict):
                    continue
                if include_exclude or not grp.get('exclude', False):
                    result.extend(grp.get('names', []))
            return [n for n in result if n]

        # CVE filter
        cve_names  = _names_from_groups(pull_filters.get('cves', []))
        cve_qs     = ','.join(cve_names) if cve_names else ''

        # Format filter
        fmt_list   = [f for f in (pull_filters.get('formats') or []) if f]
        formats_qs = ','.join(fmt_list) if fmt_list else ''

        # Author filter
        auth_list   = [a for a in (pull_filters.get('authors') or []) if a]
        authors_qs  = ','.join(auth_list) if auth_list else ''

        # License filter (group structure, include only non-excluded)
        lic_names  = _names_from_groups(pull_filters.get('licenses', []))
        license_qs = ','.join(lic_names) if lic_names else ''

        # Tag filter
        tag_groups  = pull_filters.get('tags', []) or []
        tag_names   = _names_from_groups(tag_groups, include_exclude=True)  # include all for building params
        tags_qs     = ','.join(tag_names) if tag_names else ''
        tag_mode_qs = 'OR'
        tag_excl_qs = 'false'
        if tag_groups and isinstance(tag_groups[0], dict):
            tag_mode_qs = (tag_groups[0].get('mode') or 'OR').upper()
            tag_excl_qs = 'true' if tag_groups[0].get('exclude', False) else 'false'

        # Date range
        date_from_qs = (pull_filters.get('date_from') or '').strip()
        date_to_qs   = (pull_filters.get('date_to') or '').strip()

        # ATT&CK filter
        atk_list   = [a for a in (pull_filters.get('attacks') or []) if a]
        attacks_qs = ','.join(atk_list) if atk_list else ''

        def _build_rule_url(p: int) -> str:
            url = f"{base}/api/sync/rules?since={since}&page={p}&per_page={PER_PAGE}"
            if cve_qs:       url += f"&cve={cve_qs}"
            if formats_qs:   url += f"&formats={formats_qs}"
            if authors_qs:   url += f"&author={authors_qs}"
            if license_qs:   url += f"&license={license_qs}"
            if tags_qs:      url += f"&tags={tags_qs}&tag_mode={tag_mode_qs}&tag_exclude={tag_excl_qs}"
            if date_from_qs: url += f"&date_from={date_from_qs}"
            if date_to_qs:   url += f"&date_to={date_to_qs}"
            if attacks_qs:   url += f"&attacks={attacks_qs}"
            return url

        def _build_preflight_url() -> str:
            url = f"{base}/api/sync/rules?since={since}&count_only=true"
            if cve_qs:       url += f"&cve={cve_qs}"
            if formats_qs:   url += f"&formats={formats_qs}"
            if authors_qs:   url += f"&author={authors_qs}"
            if license_qs:   url += f"&license={license_qs}"
            if tags_qs:      url += f"&tags={tags_qs}&tag_mode={tag_mode_qs}&tag_exclude={tag_excl_qs}"
            if date_from_qs: url += f"&date_from={date_from_qs}"
            if date_to_qs:   url += f"&date_to={date_to_qs}"
            if attacks_qs:   url += f"&attacks={attacks_qs}"
            return url

        active_filters = [k for k in [cve_qs, formats_qs, authors_qs, license_qs, tags_qs, date_from_qs, date_to_qs, attacks_qs] if k]

        log_job(job, f"Starting pull from {base}", level='info', event='started')
        if active_filters:
            parts = []
            if cve_qs:       parts.append(f"cve={cve_qs}")
            if formats_qs:   parts.append(f"formats={formats_qs}")
            if authors_qs:   parts.append(f"authors={authors_qs}")
            if license_qs:   parts.append(f"license={license_qs}")
            if tags_qs:      parts.append(f"tags={tags_qs} ({tag_mode_qs}{', exclude' if tag_excl_qs=='true' else ''})")
            if date_from_qs: parts.append(f"from={date_from_qs}")
            if date_to_qs:   parts.append(f"to={date_to_qs}")
            if attacks_qs:   parts.append(f"attacks={attacks_qs}")
            log_job(job, f"Filters active: {' · '.join(parts)}", level='info', event='progress')

        # ── Manifest preflight: verify remote supports sync API ────────────────
        try:
            mf_resp = http_requests.get(f"{base}/api/sync/manifest", headers=headers, timeout=8)
            if mf_resp.status_code == 404:
                msg = ("Remote does not support the sync API — it may be running an older version of "
                       "Rulezet that does not support federation. Ask the remote admin to upgrade.")
                log_job(job, msg, level='error', event='done')
                job.status = 'failed'
                job.error  = msg
                connector.last_error = msg
                db.session.commit()
                return
            elif mf_resp.status_code != 200:
                msg = f"Remote manifest check failed (HTTP {mf_resp.status_code}) — check connectivity."
                log_job(job, msg, level='error', event='done')
                job.status = 'failed'
                job.error  = msg
                connector.last_error = msg
                db.session.commit()
                return
            mf_data    = mf_resp.json()
            remote_ver = mf_data.get('instance', {}).get('version', 'unknown')
            log_job(job, f"Remote version: {remote_ver}", level='info', event='progress')
            caps = mf_data.get('capabilities', {})
            if do_rules and not caps.get('sync_rules', True):
                log_job(job, "Remote reports sync_rules=false — no rules will be fetched.", level='warning', event='progress')
            if do_bundles and not caps.get('sync_bundles', True):
                log_job(job, "Remote reports sync_bundles=false — no bundles will be fetched.", level='warning', event='progress')
        except Exception as mf_exc:
            log_job(job, f"Manifest preflight failed: {mf_exc}", level='warning', event='progress')

        # ── Pre-flight: fetch totals for progress bar ─────────────────────────
        total_rules_remote   = 0
        total_bundles_remote = 0
        try:
            if do_rules:
                r = http_requests.get(_build_preflight_url(), headers=headers, timeout=10)
                if r.status_code == 200:
                    d = r.json()
                    total_rules_remote = d.get('count', d.get('total', 0))
            if do_bundles:
                r = http_requests.get(f"{base}/api/sync/bundles?since={since}&page=1&per_page=1",
                                      headers=headers, timeout=10)
                if r.status_code == 200:
                    total_bundles_remote = r.json().get('total', 0)
        except Exception:
            pass

        job.total = max(1, total_rules_remote + total_bundles_remote)
        job.done  = 0
        db.session.commit()
        log_job(job,
                f"Remote: {total_rules_remote} rule(s), {total_bundles_remote} bundle(s) available.",
                level='info', event='progress')

        rules_created  = 0
        rules_updated  = 0
        rules_skipped  = 0
        rules_errors   = 0
        bundles_created = 0
        bundles_updated = 0
        bundles_skipped = 0
        had_error       = False
        all_missing_tags: set = set()
        tag_cache: dict = None   # built once and reused across rules + bundles
        atk_assoc_set: set = set()  # {(rule_id, technique_id)} to avoid duplicate inserts
        attack_install_triggered = False  # only trigger the install job once

        # ── Check if ATT&CK data is installed ─────────────────────────────────
        from app.core.db_class.db import AttackTechnique as _ATK
        if not _ATK.query.first():
            log_job(job,
                    "ATT&CK technique database is empty — queuing an install now. "
                    "Techniques will be available on the next pull.",
                    level='warning', event='progress')
            from app.core.db_class.db import BackgroundJob as _BJ
            atk_job = _BJ(
                type='update_attack_data',
                status='pending',
                payload={},
                created_by=job.created_by,
            )
            db.session.add(atk_job)
            db.session.commit()
            attack_install_triggered = True

        MAX_PAGES = 10_000  # safety guard against infinite pagination loops

        # ── Pull rules ────────────────────────────────────────────────────────
        if do_rules:
            # Build a full tag cache once for the entire pull — reused for bundles too.
            tag_cache = build_tag_cache()
            log_job(job, f"Tag cache built: {len(tag_cache)} tags loaded.", level='info', event='progress')

            PREFETCH  = 4     # sliding window: up to 4 pages fetched in parallel

            def _http_get_rules(p):
                return http_requests.get(_build_rule_url(p), headers=headers, timeout=120)

            page          = 1
            page_futures  = {}   # page_num → Future
            executor      = ThreadPoolExecutor(max_workers=PREFETCH)

            def _enqueue(p):
                if p not in page_futures and p <= MAX_PAGES:
                    page_futures[p] = executor.submit(_http_get_rules, p)

            # Seed the sliding window
            for p in range(1, PREFETCH + 1):
                _enqueue(p)

            try:
                while page <= MAX_PAGES:
                    if _is_cancelled(job):
                        log_job(job, 'Cancelled.', level='warning', event='cancelled')
                        return
                    while _should_pause(job):
                        import time; time.sleep(2)

                    if page not in page_futures:
                        break

                    try:
                        resp = page_futures.pop(page).result(timeout=90)
                    except Exception as exc:
                        msg = f"Error fetching rules page {page}: {exc}"
                        log_job(job, msg, level='error', event='progress')
                        connector.last_error = msg
                        had_error = True
                        db.session.commit()
                        break

                    if resp.status_code != 200:
                        msg = f"Remote returned HTTP {resp.status_code} for rules page {page}."
                        log_job(job, msg, level='error', event='progress')
                        connector.last_error = msg
                        had_error = True
                        break

                    data  = resp.json()
                    items = data.get('rules', [])
                    if not items and page > 1:
                        break

                    # Advance the sliding window
                    _enqueue(page + PREFETCH)

                    # ── Batch UUID lookup: 1 query for the whole page ─────────
                    page_uuids = [item['uuid'] for item in items if item.get('uuid')]
                    existing_rules = Rule.query.filter(
                        or_(Rule.remote_rule_uuid.in_(page_uuids),
                            Rule.uuid.in_(page_uuids))
                    ).order_by(Rule.is_deleted.asc()).all()

                    rule_lookup: dict = {}
                    for r in existing_rules:
                        if r.remote_rule_uuid and r.remote_rule_uuid not in rule_lookup:
                            rule_lookup[r.remote_rule_uuid] = r
                        if r.uuid not in rule_lookup:
                            rule_lookup[r.uuid] = r

                    # ── Batch assoc lookup: 1 query for all matched rules ─────
                    matched_ids = [r.id for r in existing_rules]
                    assoc_set: set = set()
                    if matched_ids:
                        assocs = (RuleTagAssociation.query
                                  .filter(RuleTagAssociation.rule_id.in_(matched_ids))
                                  .with_entities(RuleTagAssociation.rule_id,
                                                 RuleTagAssociation.tag_id)
                                  .all())
                        assoc_set = {(a.rule_id, a.tag_id) for a in assocs}

                    # ── Two-pass page processing ──────────────────────────────
                    # Pass 1: existing rules (already have DB ids — no flush needed).
                    # Pass 2: new rules — batch all INSERTs into a single flush.
                    pg_created = pg_updated = pg_skipped = 0
                    new_rules_pending: list = []   # [(remote_item, Rule)]

                    for item in items:
                        remote_uuid = item.get('uuid')
                        if not remote_uuid:
                            rules_errors += 1
                            continue
                        pre_match = rule_lookup.get(remote_uuid)

                        if pre_match:
                            # Existing rule — handle inline (update or skip)
                            try:
                                result = _upsert_rule(
                                    connector, effective_user_id, item,
                                    triggered_by_id=job.created_by,
                                    missing_tags=all_missing_tags,
                                    local_match=pre_match,
                                    tag_cache=tag_cache,
                                    assoc_set=assoc_set,
                                )
                                if result == 'updated':
                                    rules_updated += 1; pg_updated += 1
                                elif result == 'skipped':
                                    rules_skipped += 1; pg_skipped += 1
                                else:
                                    rules_errors += 1
                            except Exception as item_exc:
                                rules_errors += 1
                                log_job(job, f"Error updating '{item.get('title', '?')}': {item_exc}",
                                        level='warning', event='progress')
                        else:
                            # New rule — stage for batch insert
                            try:
                                rule = _prepare_new_rule(connector, effective_user_id, item)
                                new_rules_pending.append((item, rule))
                            except Exception as item_exc:
                                rules_errors += 1
                                log_job(job, f"Error staging '{item.get('title', '?')}': {item_exc}",
                                        level='warning', event='progress')

                    # Single flush for ALL new rules on this page (1 DB round-trip)
                    if new_rules_pending:
                        try:
                            db.session.flush()
                            for item, rule in new_rules_pending:
                                missed = _sync_tags(rule, item.get('tags', []),
                                                    effective_user_id,
                                                    tag_cache=tag_cache,
                                                    assoc_set=assoc_set)
                                all_missing_tags.update(missed)
                                _sync_cve_ids(rule, item.get('cve_ids', []))
                                unknown_atk = _sync_attacks(rule, item.get('attack_ids', []),
                                                            effective_user_id,
                                                            atk_assoc_set=atk_assoc_set)
                                if '__empty__' in unknown_atk and not attack_install_triggered:
                                    attack_install_triggered = True
                                    log_job(job, "ATT&CK data missing — install job already queued.",
                                            level='warning', event='progress')
                                _import_rule_history_new(rule, item.get('update_history', []),
                                                         effective_user_id)
                            pg_created    = len(new_rules_pending)
                            rules_created += pg_created
                        except Exception as batch_exc:
                            rules_errors += len(new_rules_pending)
                            log_job(job, f"Batch insert error on page {page}: {batch_exc}",
                                    level='error', event='progress')
                            db.session.rollback()

                    db.session.commit()

                    processed = (rules_created + rules_updated + rules_skipped + rules_errors
                                 + bundles_created + bundles_updated + bundles_skipped)
                    job.done = min(processed, job.total)
                    log_job(job,
                            f"Rules p.{page}: +{pg_created} new, ~{pg_updated} updated, ={pg_skipped} skipped.",
                            level='info', event='progress')
                    if not data.get('has_more', False):
                        break
                    page += 1
            finally:
                executor.shutdown(wait=False)

        # ── Pull bundles ──────────────────────────────────────────────────────
        if do_bundles:
            if tag_cache is None:
                tag_cache = build_tag_cache()
                log_job(job, f"Tag cache built: {len(tag_cache)} tags loaded.", level='info', event='progress')

            # Phase 1 — collect all bundle pages and their referenced rule UUIDs
            all_bundle_items: list = []
            bundle_rule_uuids: set = set()
            page = 1
            while page <= MAX_PAGES:
                if _is_cancelled(job):
                    log_job(job, 'Cancelled.', level='warning', event='cancelled')
                    return
                url = f"{base}/api/sync/bundles?since={since}&page={page}&per_page={PER_PAGE}"
                try:
                    resp = http_requests.get(url, headers=headers, timeout=60)
                    if resp.status_code != 200:
                        had_error = True; break
                    data  = resp.json()
                    items = data.get('bundles', [])
                    if not items and page > 1:
                        break
                    all_bundle_items.extend(items)
                    for item in items:
                        bundle_rule_uuids.update(item.get('rules', []))
                    if not data.get('has_more', False):
                        break
                    page += 1
                except Exception as exc:
                    log_job(job, f"Error fetching bundles page {page}: {exc}",
                            level='error', event='progress')
                    had_error = True; break

            # Phase 2 — when not already pulling all rules, import only the rules
            # referenced by the bundles that don't exist locally yet.
            if bundle_rule_uuids and not do_rules:
                existing_local = set(
                    r[0] for r in Rule.query.filter(
                        or_(Rule.uuid.in_(bundle_rule_uuids),
                            Rule.remote_rule_uuid.in_(bundle_rule_uuids))
                    ).with_entities(Rule.uuid).all()
                ) | set(
                    r[0] for r in Rule.query.filter(
                        or_(Rule.uuid.in_(bundle_rule_uuids),
                            Rule.remote_rule_uuid.in_(bundle_rule_uuids))
                    ).with_entities(Rule.remote_rule_uuid).all()
                    if r[0]
                )
                missing_uuids = bundle_rule_uuids - existing_local
                if missing_uuids:
                    log_job(job,
                            f"Fetching {len(missing_uuids)} rule(s) referenced by bundles…",
                            level='info', event='progress')
                    # Chunk to keep URL size reasonable
                    CHUNK = 100
                    missing_list = list(missing_uuids)
                    for i in range(0, len(missing_list), CHUNK):
                        if _is_cancelled(job):
                            log_job(job, 'Cancelled.', level='warning', event='cancelled')
                            return
                        chunk = missing_list[i:i + CHUNK]
                        uuids_qs = ','.join(chunk)
                        try:
                            r = http_requests.get(
                                f"{base}/api/sync/rules?uuids={uuids_qs}",
                                headers=headers, timeout=60,
                            )
                            if r.status_code != 200:
                                log_job(job, f"Failed to fetch bundle rules chunk (HTTP {r.status_code})",
                                        level='warning', event='progress')
                                continue
                            chunk_rules = r.json().get('rules', [])
                            new_rules_pending = []
                            chunk_uuids = [item['uuid'] for item in chunk_rules if item.get('uuid')]
                            existing_chunk = Rule.query.filter(
                                or_(Rule.remote_rule_uuid.in_(chunk_uuids),
                                    Rule.uuid.in_(chunk_uuids))
                            ).all()
                            chunk_lookup = {}
                            for ex in existing_chunk:
                                if ex.remote_rule_uuid:
                                    chunk_lookup[ex.remote_rule_uuid] = ex
                                chunk_lookup[ex.uuid] = ex

                            for item in chunk_rules:
                                pre_match = chunk_lookup.get(item.get('uuid'))
                                if pre_match:
                                    _upsert_rule(connector, effective_user_id, item,
                                                 triggered_by_id=job.created_by,
                                                 missing_tags=all_missing_tags,
                                                 local_match=pre_match,
                                                 tag_cache=tag_cache)
                                    rules_updated += 1
                                else:
                                    rule = _prepare_new_rule(connector, effective_user_id, item)
                                    new_rules_pending.append((item, rule))

                            if new_rules_pending:
                                db.session.flush()
                                for item, rule in new_rules_pending:
                                    missed = _sync_tags(rule, item.get('tags', []),
                                                        effective_user_id,
                                                        tag_cache=tag_cache)
                                    all_missing_tags.update(missed)
                                    _sync_cve_ids(rule, item.get('cve_ids', []))
                                    _import_rule_history_new(rule, item.get('update_history', []),
                                                             effective_user_id)
                                rules_created += len(new_rules_pending)

                            db.session.commit()
                        except Exception as exc:
                            log_job(job, f"Error importing bundle rules chunk: {exc}",
                                    level='warning', event='progress')
                            db.session.rollback()

            # Phase 3 — upsert bundles (rules are now locally available)
            for item in all_bundle_items:
                if _is_cancelled(job):
                    log_job(job, 'Cancelled.', level='warning', event='cancelled')
                    return
                try:
                    result = _upsert_bundle(connector, effective_user_id, item,
                                            triggered_by_id=job.created_by,
                                            tag_cache=tag_cache)
                    if result == 'created':
                        bundles_created += 1
                    elif result == 'updated':
                        bundles_updated += 1
                    elif result == 'skipped':
                        bundles_skipped += 1
                except Exception as bundle_exc:
                    log_job(job, f"Error on bundle '{item.get('name', '?')}': {bundle_exc}",
                            level='warning', event='progress')
                processed = rules_created + rules_updated + rules_skipped + rules_errors + bundles_created + bundles_updated + bundles_skipped
                job.done = min(processed, job.total)
            db.session.commit()

        # ── Finalize ──────────────────────────────────────────────────────────
        now       = datetime.datetime.now(datetime.timezone.utc)
        duration  = round(_time.monotonic() - t_start, 1)

        # Compute unique tag families that had no local match
        missing_families = sorted({
            f for n in all_missing_tags
            for f in [_extract_tag_family(n)] if f
        })

        if not had_error:
            connector.last_sync_at = now
            connector.is_verified  = True
        connector.rules_synced   += rules_created + rules_updated
        connector.bundles_synced += bundles_created + bundles_updated
        job.done   = job.total
        job.status = 'done'
        db.session.commit()

        summary = (
            f"Pull done in {duration}s — "
            f"rules: +{rules_created} new, ~{rules_updated} updated, "
            f"={rules_skipped} skipped, {rules_errors} errors | "
            f"bundles: +{bundles_created} new, ~{bundles_updated} updated, ={bundles_skipped} skipped."
        )
        if missing_families:
            log_job(job,
                    f"Tag families from remote not installed locally: {', '.join(missing_families)}",
                    level='warning', event='progress')

        log_job(job, summary, level='success', event='done')
        log_activity('connector.pull_done',
                     f"Connector '{connector.name}': {summary}",
                     target_type='connector', target_id=connector.id,
                     target_uuid=connector.uuid,
                     actor_id=job.created_by,
                     extra={
                         'rules_added':         rules_created,
                         'rules_updated':       rules_updated,
                         'rules_skipped':       rules_skipped,
                         'rules_errors':        rules_errors,
                         'bundles_added':       bundles_created,
                         'bundles_updated':     bundles_updated,
                         'bundles_skipped':     bundles_skipped,
                         'remote_rules':        total_rules_remote,
                         'remote_bundles':      total_bundles_remote,
                         'had_error':           had_error,
                         'duration_s':          duration,
                         'missing_tag_families': missing_families,
                         'job_id':              job.id,
                         'job_uuid':            job.uuid,
                     })


# ─── Package management ───────────────────────────────────────────────────────

@register_handler('update_package')
def handle_update_package(job, app):
    payload = job.payload or {}
    name = payload.get('name', '').strip()
    if not name:
        job.status = 'failed'
        job.error = 'No package name provided.'
        db.session.commit()
        return

    job_uuid = job.uuid
    with app.app_context():
        # Re-fetch in this context's session — the worker's `job` object belongs
        # to another session, so commits here would silently drop its changes.
        job = BackgroundJob.query.filter_by(uuid=job_uuid).first()
        if job is None:
            return
        job.total = 1
        job.done = 0
        db.session.commit()
        log_job(job, f"Upgrading: {name}", level='info', event='started')
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '--upgrade', name],
                capture_output=True, text=True, timeout=180,
            )
            output = (result.stdout + result.stderr).strip()
            # Emit output lines as log entries
            for line in output.splitlines()[-30:]:
                if line.strip():
                    log_job(job, line, level='info', event='progress')
            if result.returncode == 0:
                log_job(job, f"Successfully upgraded {name}.", level='success', event='done')
                job.status = 'done'
                job.done = 1
            else:
                job.status = 'failed'
                job.error = output[-500:]
                log_job(job, f"pip returned code {result.returncode}.", level='error', event='failed')
        except Exception as e:
            job.status = 'failed'
            job.error = str(e)
            log_job(job, str(e), level='error', event='failed')
        db.session.commit()


@register_handler('uninstall_package')
def handle_uninstall_package(job, app):
    payload = job.payload or {}
    name = payload.get('name', '').strip()
    if not name:
        job.status = 'failed'
        job.error = 'No package name provided.'
        db.session.commit()
        return

    job_uuid = job.uuid
    with app.app_context():
        # Re-fetch in this context's session (see handle_update_package).
        job = BackgroundJob.query.filter_by(uuid=job_uuid).first()
        if job is None:
            return
        job.total = 1
        job.done = 0
        db.session.commit()
        log_job(job, f"Uninstalling: {name}", level='warning', event='started')
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'uninstall', '-y', name],
                capture_output=True, text=True, timeout=60,
            )
            output = (result.stdout + result.stderr).strip()
            for line in output.splitlines()[-20:]:
                if line.strip():
                    log_job(job, line, level='info', event='progress')
            if result.returncode == 0:
                log_job(job, f"Successfully uninstalled {name}.", level='success', event='done')
                job.status = 'done'
                job.done = 1
            else:
                job.status = 'failed'
                job.error = output[-500:]
                log_job(job, f"pip returned code {result.returncode}.", level='error', event='failed')
        except Exception as e:
            job.status = 'failed'
            job.error = str(e)
            log_job(job, str(e), level='error', event='failed')
        db.session.commit()


# ─── Git submodule management ─────────────────────────────────────────────────

@register_handler('update_submodule_bg')
def handle_update_submodule_bg(job, app):
    payload = job.payload or {}
    path = payload.get('path', '').strip()
    if not path:
        job.status = 'failed'
        job.error = 'No submodule path provided.'
        db.session.commit()
        return

    cwd = os.getcwd()
    job_uuid = job.uuid
    with app.app_context():
        # Re-fetch in this context's session (see handle_update_package).
        job = BackgroundJob.query.filter_by(uuid=job_uuid).first()
        if job is None:
            return
        job.total = 1
        job.done = 0
        db.session.commit()
        log_job(job, f"Updating submodule: {path}", level='info', event='started')
        try:
            result = subprocess.run(
                ['git', 'submodule', 'update', '--remote', '--merge', '--', path],
                capture_output=True, text=True, timeout=300, cwd=cwd,
            )
            output = (result.stdout + result.stderr).strip()
            for line in output.splitlines()[-30:]:
                if line.strip():
                    log_job(job, line, level='info', event='progress')
            if result.returncode == 0:
                log_job(job, f"Submodule '{path}' updated successfully.", level='success', event='done')
                job.status = 'done'
                job.done = 1
            else:
                job.status = 'failed'
                job.error = output[-500:]
                log_job(job, f"git returned code {result.returncode}.", level='error', event='failed')
        except Exception as e:
            job.status = 'failed'
            job.error = str(e)
            log_job(job, str(e), level='error', event='failed')
        db.session.commit()


@register_handler('remove_submodule')
def handle_remove_submodule(job, app):
    payload = job.payload or {}
    path = payload.get('path', '').strip()
    if not path:
        job.status = 'failed'
        job.error = 'No submodule path provided.'
        db.session.commit()
        return

    cwd = os.getcwd()
    job_uuid = job.uuid
    with app.app_context():
        # Re-fetch in this context's session (see handle_update_package).
        job = BackgroundJob.query.filter_by(uuid=job_uuid).first()
        if job is None:
            return
        job.total = 3
        job.done = 0
        db.session.commit()
        log_job(job, f"Removing submodule: {path}", level='warning', event='started')
        try:
            # Step 1: deinit
            r1 = subprocess.run(
                ['git', 'submodule', 'deinit', '--force', '--', path],
                capture_output=True, text=True, timeout=30, cwd=cwd,
            )
            log_job(job, (r1.stdout + r1.stderr).strip() or 'deinit done', level='info', event='progress')
            job.done = 1
            db.session.commit()

            # Step 2: git rm
            r2 = subprocess.run(
                ['git', 'rm', '-f', path],
                capture_output=True, text=True, timeout=30, cwd=cwd,
            )
            log_job(job, (r2.stdout + r2.stderr).strip() or 'git rm done', level='info', event='progress')
            job.done = 2
            db.session.commit()

            # Step 3: remove .git/modules entry
            modules_dir = os.path.join(cwd, '.git', 'modules', path)
            if os.path.isdir(modules_dir):
                import shutil
                shutil.rmtree(modules_dir, ignore_errors=True)
                log_job(job, f"Cleaned .git/modules/{path}", level='info', event='progress')

            if r1.returncode == 0 and r2.returncode == 0:
                log_job(job, f"Submodule '{path}' removed successfully.", level='success', event='done')
                job.status = 'done'
                job.done = 3
            else:
                err = (r1.stderr + r2.stderr).strip()
                job.status = 'failed'
                job.error = err[-500:]
                log_job(job, f"Removal may be incomplete: {err[:300]}", level='warning', event='failed')
        except Exception as e:
            job.status = 'failed'
            job.error = str(e)
            log_job(job, str(e), level='error', event='failed')
        db.session.commit()


# ─────────────────────────────────────────────────────────────────────────────
#  bulk_update_decision — accept or reject all pending rule updates for a scan
# ─────────────────────────────────────────────────────────────────────────────

@register_handler('bulk_update_decision')
def handle_bulk_update_decision(job, app):
    # No nested `with app.app_context()` here — the worker loop that calls
    # this handler already holds one, and `job`/`db.session` were bound to
    # that outer context. Pushing a second one gives `db.session` a *different*
    # underlying SQLAlchemy Session that has no idea `job` was mutated, so
    # `job.done = n; db.session.commit()` silently commits nothing for `job`
    # (see job_worker.py's own comment about this exact footgun for handlers
    # that spawn their own app_context).
    try:
        sid    = job.payload.get('sid')
        action = job.payload.get('action')  # 'accept' | 'reject'

        from app.features.rule.rule_core import (
            get_rule_update_list_filtered, accept_all_update, reject_all_update,
        )
        rule_list, count = get_rule_update_list_filtered(
            sid,
            f_found=job.payload.get('f_found'),
            f_error=job.payload.get('f_error'),
            f_syntax_valid=job.payload.get('f_syntax_valid'),
        )

        job.total = max(count, 1)
        if not rule_list or count == 0:
            log_job(job, 'No pending updates found.', level='info', event='done')
            job.status = 'done'
            job.done = job.total
            db.session.commit()
            return

        verb_ing = 'Accepted' if action == 'accept' else 'Rejected'
        stopped  = {'early': False}

        def _on_progress(n, rule):
            job.done = n
            log_job(job, f"{verb_ing} '{rule.name_rule}'", level='info', event='progress')

        def _should_stop():
            if _is_cancelled(job):
                log_job(job, f"Cancelled at {job.done}/{job.total} ({job.progress_pct}% done).",
                        level='warning', event='cancelled')
                stopped['early'] = True
                return True
            if _should_pause(job):
                db.session.commit()
                log_job(job, f"Paused at {job.done}/{job.total} ({job.progress_pct}% done). Click Resume to continue.",
                        level='info', event='paused')
                stopped['early'] = True
                return True
            return False

        ok = (accept_all_update(rule_list, on_progress=_on_progress, should_stop=_should_stop) if action == 'accept'
              else reject_all_update(rule_list, on_progress=_on_progress, should_stop=_should_stop))

        if stopped['early']:
            db.session.commit()
            return

        job.done   = job.total
        job.status = 'done' if ok else 'failed'
        verb = 'accepted' if action == 'accept' else 'rejected'
        log_job(job, f'{count} update(s) {verb}.', level='success' if ok else 'error', event='done')
    except Exception as e:
        job.status = 'failed'
        job.error  = str(e)
        log_job(job, str(e), level='error', event='failed')
    db.session.commit()


# ─────────────────────────────────────────────────────────────────────────────
#  bulk_new_rules_decision — add or reject all new rules found in a scan
# ─────────────────────────────────────────────────────────────────────────────

@register_handler('bulk_new_rules_decision')
def handle_bulk_new_rules_decision(job, app):
    # No nested `with app.app_context()` — see the comment on
    # handle_bulk_update_decision() just above for why that silently breaks
    # progress tracking (job.done/total mutations end up on the wrong session).
    try:
        sid     = job.payload.get('sid')
        action  = job.payload.get('action')   # 'add' | 'reject'
        user_id = job.payload.get('user_id')

        from app.features.rule.rule_core import (
            get_valid_new_rules_by_sid, reject_all_new_rules_by_sid,
            import_single_new_rule,
        )
        from app.core.db_class.db import User

        if action == 'reject':
            reject_all_new_rules_by_sid(sid)
            job.done = job.total = 1
            job.status = 'done'
            log_job(job, 'All new rules rejected.', level='success', event='done')
            db.session.commit()
            return

        # action == 'add'
        new_rules = get_valid_new_rules_by_sid(sid)
        job.total = max(len(new_rules), 1)

        if not new_rules:
            log_job(job, 'No valid new rules to add.', level='info', event='done')
            job.status = 'done'
            job.done = job.total
            db.session.commit()
            return

        user   = User.query.get(user_id)
        added  = errors = 0

        for i, nr in enumerate(new_rules):
            if _is_cancelled(job):
                log_job(job, f"Cancelled — {added} added, {errors} error(s) before stopping.",
                        level='warning', event='cancelled')
                return
            if _should_pause(job):
                db.session.commit()
                log_job(job, f"Paused — {added} added, {errors} error(s) so far. Click Resume to continue.",
                        level='info', event='paused')
                return

            added_ok, message = import_single_new_rule(nr, user)
            if added_ok:
                added += 1
                log_job(job, message, level='success', event='progress')
            else:
                errors += 1
                log_job(job, message, level='warning', event='progress')

            job.done = i + 1
            db.session.commit()

        job.status = 'done'
        log_job(job, f'{added} rule(s) added, {errors} error(s).', level='success', event='done')
    except Exception as e:
        job.status = 'failed'
        job.error  = str(e)
        log_job(job, str(e), level='error', event='failed')
    db.session.commit()


# ─── ownership_transfer_bulk ───────────────────────────────────────────────────

OWNERSHIP_BATCH = 100

@register_handler('ownership_transfer_bulk')
def handle_ownership_transfer_bulk(job, app):
    """
    Transfer ownership of a large set of rules to a new owner in batches.

    Payload:
        request_id : int        — RequestOwnerRule id
        rule_ids   : list[int]  — rules to transfer
    """
    payload    = job.payload or {}
    request_id = payload.get('request_id')
    rule_ids   = payload.get('rule_ids', [])

    if not request_id or not rule_ids:
        log_job(job, "Missing request_id or rule_ids.", level='error', event='done')
        job.status = 'failed'
        db.session.commit()
        return

    ownership_request = RequestOwnerRule.query.get(request_id)
    if not ownership_request:
        log_job(job, f"RequestOwnerRule #{request_id} not found.", level='error', event='done')
        job.status = 'failed'
        db.session.commit()
        return

    total = len(rule_ids)
    if job.total == 0:
        job.total = total
        db.session.commit()

    # Mark request as approved upfront
    ownership_request.status = 'approved'
    db.session.commit()
    log_job(job, f"Starting transfer of {total} rule(s) to user #{ownership_request.user_id}.",
            level='info', event='started')

    offset    = payload.get('_resume_offset', 0)
    new_owner = ownership_request.user_id
    source    = ownership_request.rule_source
    transferred = 0

    for i in range(offset, total, OWNERSHIP_BATCH):
        if _is_cancelled(job):
            log_job(job, "Cancelled.", level='warning', event='cancelled')
            return
        while _should_pause(job):
            import time; time.sleep(2)

        chunk_ids = rule_ids[i:i + OWNERSHIP_BATCH]

        # Transfer ownership
        Rule.query.filter(Rule.id.in_(chunk_ids)).update(
            {"user_id": new_owner}, synchronize_session=False
        )

        # Auto-reject other pending requests for these rules
        RequestOwnerRule.query.filter(
            RequestOwnerRule.rule_id.in_(chunk_ids),
            RequestOwnerRule.status == 'pending',
            RequestOwnerRule.id != request_id,
        ).update(
            {"status": "rejected", "user_id_to_send": new_owner},
            synchronize_session=False,
        )

        db.session.commit()
        transferred += len(chunk_ids)
        job.done = transferred
        _save_offset(job, i + OWNERSHIP_BATCH)
        db.session.commit()
        log_job(job, f"{transferred}/{total} rule(s) transferred.", level='info', event='progress')

    # Also reject pending source-level requests if applicable
    if source:
        RequestOwnerRule.query.filter(
            RequestOwnerRule.rule_source == source,
            RequestOwnerRule.status == 'pending',
            RequestOwnerRule.id != request_id,
        ).update(
            {"status": "rejected", "user_id_to_send": new_owner},
            synchronize_session=False,
        )
        db.session.commit()

    # Notify the requester
    try:
        from app.features.notification.notification_core import notify_ownership_decision
        notify_ownership_decision(ownership_request, approved=True,
                                  rule_title=f"{transferred} rules from {source or 'source'}")
    except Exception as _e:
        log_job(job, f"Notification error: {_e}", level='warning')

    log_job(job, f"Done — {transferred} rule(s) transferred.", level='success', event='done')


# ─── bulk_transfer_ownership (admin manual grant, no formal request) ──────────

@register_handler('bulk_transfer_ownership')
def handle_bulk_transfer_ownership(job, app):
    """
    Admin-initiated ownership transfer — picks rules directly via the
    RuleList selector (no RequestOwnerRule involved), grants ownership to an
    arbitrary target user.

    Payload:
        new_owner_id : int   — user to become the new owner
        filters      : dict  — same shape _build_rule_query expects
                                ({'rule_ids': [...]} for a manual pick, or
                                filter criteria for "all matching")
    """
    payload      = job.payload or {}
    new_owner_id = payload.get('new_owner_id')
    filters      = payload.get('filters', {})
    offset       = payload.get('_resume_offset', 0)

    if not new_owner_id:
        raise ValueError("No new_owner_id provided.")

    new_owner = User.query.get(new_owner_id)
    if not new_owner:
        raise ValueError(f"Target user #{new_owner_id} not found.")

    rule_query = _build_rule_query(filters)

    if job.total == 0:
        job.total = rule_query.count()
        db.session.commit()
        log_job(job,
            f"Job started — granting ownership of {job.total} rule(s) to "
            f"{new_owner.get_username()} (#{new_owner_id}).",
            level='info', event='started')
    elif offset > 0:
        log_job(job,
            f"Resuming from offset {offset} ({offset}/{job.total} already processed, "
            f"{job.progress_pct}% done)",
            level='info', event='resumed')

    if job.total == 0:
        log_job(job, "No rules matched the filters — nothing to do.", level='warning', event='done')
        return

    batch_num   = 0
    transferred = 0

    while True:
        if _is_cancelled(job):
            log_job(job,
                f"Job cancelled at offset {offset} ({job.progress_pct}% done — "
                f"{transferred} rule(s) transferred so far).",
                level='warning', event='cancelled')
            return
        if _should_pause(job):
            _save_offset(job, offset)
            db.session.commit()
            log_job(job,
                f"Job paused at offset {offset} ({job.progress_pct}% done). Click Resume to continue.",
                level='info', event='paused')
            return

        batch_ids = [
            r[0] for r in
            rule_query.with_entities(Rule.id).offset(offset).limit(OWNERSHIP_BATCH).all()
        ]
        if not batch_ids:
            break

        # Snapshot pre-transfer state so each rule's OWN history shows the
        # ownership change (old owner -> new owner) — the bulk .update() below
        # bypasses ORM instance tracking entirely, so this is the only place
        # that can capture it.
        from app.features.rule.rule_core import rule_metadata_snapshot, create_rule_history, add_contributor
        batch_rules    = Rule.query.filter(Rule.id.in_(batch_ids)).all()
        old_snapshots  = {r.id: rule_metadata_snapshot(r) for r in batch_rules}

        Rule.query.filter(Rule.id.in_(batch_ids)).update(
            {"user_id": new_owner_id}, synchronize_session=False
        )

        # A rule reassigned by an admin shouldn't leave a stale pending claim
        # for the OLD owner sitting in the requests queue.
        RequestOwnerRule.query.filter(
            RequestOwnerRule.rule_id.in_(batch_ids),
            RequestOwnerRule.status == 'pending',
        ).update(
            {"status": "rejected", "user_id_to_send": new_owner_id},
            synchronize_session=False,
        )

        db.session.commit()

        new_owner_name = f"{new_owner.first_name} {new_owner.last_name}".strip()
        for rid, old_snap in old_snapshots.items():
            new_snap = {**old_snap, "owner_id": new_owner_id, "owner_name": new_owner_name}
            create_rule_history({
                "id": rid,
                "title": old_snap.get("title") or "Unknown Title",
                "success": True,
                "manual_submit": False,
                "message": f"Ownership transferred to {new_owner_name} (bulk admin action)",
                "old_snapshot": old_snap,
                "new_snapshot": new_snap,
                "change_type": "ownership",
                "analyzed_by_user_id": job.created_by,
            })
            log_activity("rule.ownership_transfer",
                         f"Ownership of '{old_snap.get('title') or 'Unknown Title'}' transferred to {new_owner_name} (bulk admin action)",
                         target_type="rule", target_id=rid,
                         icon="fa-solid fa-user-shield", category="rule",
                         actor_id=job.created_by,
                         extra={'job_id': job.id, 'job_uuid': job.uuid})

            # The dispossessed owner authored/held this rule — credit them as a contributor.
            previous_owner_id = old_snap.get("owner_id")
            if previous_owner_id and previous_owner_id != new_owner_id:
                add_contributor(previous_owner_id, rid)

        transferred += len(batch_ids)
        offset      += len(batch_ids)
        batch_num   += 1
        job.done     = transferred
        _save_offset(job, offset)
        _append_transferred_ids(job, batch_ids)
        db.session.commit()

        if batch_num % LOG_EVERY == 0:
            log_job(job,
                f"Progress: {job.done}/{job.total} rules ({job.progress_pct}%) transferred.",
                level='info', event='progress')

    all_transferred_ids = (job.payload or {}).get('_transferred_ids', [])

    try:
        from app.features.notification.notification_core import notify_ownership_granted
        notify_ownership_granted(new_owner_id, transferred)
    except Exception as _e:
        log_job(job, f"Notification error: {_e}", level='warning')

    log_job(job,
        f"Done — {transferred} rule(s) transferred to {new_owner.get_username()}.",
        level='success', event='done')
    log_activity('admin.bulk_transfer_ownership',
                 f"Manually transferred ownership of {transferred} rule(s) to {new_owner.get_username()} (#{new_owner_id})",
                 target_type='user', target_id=new_owner_id, target_uuid=getattr(new_owner, 'uuid', None),
                 actor_id=job.created_by,
                 extra={'rule_count': transferred, 'filters': filters, 'job_id': job.id, 'job_uuid': job.uuid})

    # Manual grants bypass the formal request/approval flow entirely, so
    # without this the History tab would show no record of them at all.
    # Mirror the shape of a normal request that got approved: the new owner
    # is the "requester" (user_id) and the admin who granted it is the
    # approver (user_id_to_send) — same as if the new owner had asked and
    # the admin had said yes, just recorded after the fact as already
    # "approved" since the transfer already happened.
    if transferred > 0:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        history_entry = RequestOwnerRule(
            uuid=str(uuid_mod.uuid4()),
            user_id=new_owner_id,
            user_id_to_send=job.created_by,
            title=f"Ownership grant — {transferred} rule(s)",
            content=(f"{new_owner.get_username()} was granted ownership of {transferred} rule(s) "
                     f"(manually approved by an administrator)."),
            status="approved",
            created_at=now,
            updated_at=now,
            rule_ids=all_transferred_ids or None,
        )
        db.session.add(history_entry)
        db.session.commit()


# ─── github_proposal_bulk_import (accepted GitHub import proposals) ─────────

@register_handler('github_proposal_bulk_import')
def handle_github_proposal_bulk_import(job, app):
    """
    Sequentially imports every accepted GithubProposal in the batch, one repo
    at a time (single-threaded — Session_class.run_sync, no daemon threads),
    attributing new rules' ownership to either the requester or the admin who
    accepted the batch.

    Payload:
        proposal_uuids : list[str]
        ownership_mode : 'requester' | 'admin'
    """
    from app.features.rule.rule_from_github.import_rule import session_class as SessionModel
    from app.features.rule.rule_format.utils_format.utils_import_update import (
        clone_or_access_repo, github_repo_metadata, valider_repo_github,
    )

    payload = job.payload or {}
    proposal_uuids = payload.get('proposal_uuids', [])
    ownership_mode = payload.get('ownership_mode', 'admin')
    offset = payload.get('_resume_offset', 0)

    acting_admin = User.query.get(job.created_by)
    if not acting_admin:
        raise ValueError(f"Acting admin #{job.created_by} not found.")

    if job.total == 0:
        job.total = len(proposal_uuids)
        db.session.commit()
        log_job(job, f"Job started — importing {job.total} accepted proposal(s).",
                level='info', event='started')
    elif offset > 0:
        log_job(job, f"Resuming from proposal {offset + 1}/{job.total}.",
                level='info', event='resumed')

    if job.total == 0:
        log_job(job, "No proposals to import.", level='warning', event='done')
        return

    done = offset
    while offset < len(proposal_uuids):
        if _is_cancelled(job):
            log_job(job, f"Job cancelled after {done}/{job.total} proposal(s).",
                    level='warning', event='cancelled')
            return
        if _should_pause(job):
            _save_offset(job, offset)
            db.session.commit()
            log_job(job, f"Job paused after {done}/{job.total} proposal(s). Click Resume to continue.",
                    level='info', event='paused')
            return

        proposal_uuid = proposal_uuids[offset]
        proposal = GithubProposal.query.filter_by(uuid=proposal_uuid).first()
        if not proposal:
            log_job(job, f"Proposal {proposal_uuid} no longer exists — skipping.", level='warning')
            offset += 1
            done += 1
            job.done = done
            _save_offset(job, offset)
            db.session.commit()
            continue

        owner = proposal.requester if ownership_mode == 'requester' else acting_admin
        try:
            if not valider_repo_github(proposal.repo_url):
                raise ValueError("Invalid repository URL.")

            repo_dir, _ = clone_or_access_repo(proposal.repo_url, branch=proposal.branch)
            if not repo_dir:
                raise ValueError("Failed to clone or access the repository.")

            info = github_repo_metadata(proposal.repo_url, proposal.license)
            if proposal.branch:
                info['branch'] = proposal.branch

            session = SessionModel.Session_class(repo_dir, owner, info)
            imported, skipped, bad_rules, _total = session.run_sync(app, owner)

            proposal.status = 'imported'
            proposal.importer_result_uuid = session.uuid
            db.session.commit()

            log_job(job,
                    f"Imported '{proposal.repo_url}': {imported} imported, {skipped} skipped, {bad_rules} invalid.",
                    level='success', event='progress')

            try:
                from app.features.notification.notification_core import notify_github_proposal_import_done
                notify_github_proposal_import_done(proposal.user_id, proposal.repo_url, imported, success=True)
            except Exception as e:
                log_job(job, f"Notification error: {e}", level='warning')

        except Exception as e:
            db.session.rollback()
            proposal.status = 'failed'
            db.session.commit()
            log_job(job, f"Failed importing '{proposal.repo_url}': {e}", level='error', event='progress')

            try:
                from app.features.notification.notification_core import notify_github_proposal_import_done
                notify_github_proposal_import_done(proposal.user_id, proposal.repo_url, 0, success=False, error=str(e))
            except Exception as e2:
                log_job(job, f"Notification error: {e2}", level='warning')

        offset += 1
        done += 1
        job.done = done
        _save_offset(job, offset)
        db.session.commit()

    log_job(job, f"Done — processed {done}/{job.total} proposal(s).", level='success', event='done')
    log_activity('admin.github_proposal_bulk_import',
                 f"Imported {done} accepted GitHub proposal(s) (ownership: {ownership_mode})",
                 target_type='job', target_id=job.id, target_uuid=job.uuid,
                 actor_id=job.created_by,
                 extra={'proposal_uuids': proposal_uuids, 'ownership_mode': ownership_mode})


# ─── ATT&CK: update catalogue from MITRE ─────────────────────────────────────

@register_handler('update_attack_data')
def handle_update_attack_data(job, app):
    """Download MITRE ATT&CK STIX bundle and upsert AttackTechnique rows."""
    log_job(job, 'Fetching ATT&CK data from MITRE GitHub…', level='info', event='start')
    try:
        from app.features.attack.attack_core import fetch_and_update_attack_data
        created, updated = fetch_and_update_attack_data()
        job.done = 1
        db.session.commit()
        log_job(job, f'Done — {created} techniques created, {updated} updated.',
                level='success', event='done')
    except Exception as exc:
        log_job(job, f'Error: {exc}', level='error', event='error')
        raise


# ─── ATT&CK: bulk auto-parse rules ───────────────────────────────────────────

ATTACK_PARSE_BATCH = 500

@register_handler('bulk_parse_attack_rules')
def handle_bulk_parse_attack_rules(job, app):
    """
    Scan all (or format-filtered) rules and auto-create RuleAttackAssociation
    entries by parsing rule content for ATT&CK technique IDs.
    """
    payload  = job.payload or {}
    fmt      = payload.get('format')        # optional format filter, e.g. 'sigma'
    offset   = payload.get('_resume_offset', 0)

    from app.features.attack.attack_core import _extract_technique_ids
    from app.core.db_class.db import AttackTechnique, RuleAttackAssociation
    import datetime as _dt

    # Build query
    q = Rule.query.filter(Rule.is_deleted == False)
    if fmt:
        q = q.filter(Rule.format == fmt)

    if job.total == 0:
        job.total = q.count()
        db.session.commit()
        log_job(job, f'Starting — {job.total} rules to parse.', level='info', event='start')

    # Cache all known technique IDs — include deprecated ones so sigma rules
    # that explicitly reference deprecated IDs (e.g. T1068) are still associated.
    known_ids = {
        t.technique_id
        for t in AttackTechnique.query.all()
    }
    if not known_ids:
        log_job(job, 'No ATT&CK techniques in DB — run "Update ATT&CK data" job first.',
                level='warning', event='done')
        job.done = job.total
        db.session.commit()
        return

    total_added = 0
    batch_num   = 0

    while True:
        if _is_cancelled(job): # noqa — defined in local scope via job_worker helpers
            log_job(job, 'Cancelled.', level='warning', event='cancelled')
            return
        while _should_pause(job):
            import time; time.sleep(2)

        rules = (
            q.with_entities(Rule.id, Rule.format, Rule.to_string)
            .offset(offset)
            .limit(ATTACK_PARSE_BATCH)
            .all()
        )
        if not rules:
            break

        new_assocs = []
        # Fetch existing associations for this batch to avoid duplicates
        rule_ids = [r.id for r in rules]
        existing = {
            (a.rule_id, a.technique_id)
            for a in RuleAttackAssociation.query.filter(
                RuleAttackAssociation.rule_id.in_(rule_ids)
            ).all()
        }

        for rule_id, rule_fmt, content in rules:
            ids = _extract_technique_ids(rule_fmt or '', content or '')
            for tid in dict.fromkeys(ids):   # dedup
                if tid not in known_ids:
                    continue
                if (rule_id, tid) in existing:
                    continue
                new_assocs.append({
                    'uuid':         str(uuid_mod.uuid4()),
                    'rule_id':      rule_id,
                    'technique_id': tid,
                    'user_id':      None,
                    'source':       'auto',
                    'added_at':     _dt.datetime.now(tz=_dt.timezone.utc),
                })
                existing.add((rule_id, tid))

        if new_assocs:
            db.session.bulk_insert_mappings(RuleAttackAssociation, new_assocs)
            db.session.commit()
            total_added += len(new_assocs)
            _refresh_quality_scores({a['rule_id'] for a in new_assocs})

        offset   += len(rules)
        job.done  = offset
        _save_offset(job, offset)
        db.session.commit()

        batch_num += 1
        if batch_num % LOG_EVERY == 0:
            log_job(job, f'{offset}/{job.total} rules processed, {total_added} associations created.',
                    level='info', event='progress')

    log_job(job, f'Done — {offset} rules parsed, {total_added} ATT&CK associations created.',
            level='success', event='done')


# ── Bulk Field Parser ────────────────────────────────────────────────────────

FIELD_PARSE_BATCH = 200
FIELD_PARSE_LOG_EVERY = 10

@register_handler('bulk_parse_fields')
def handle_bulk_parse_fields(job, app):
    """
    Parse rule content and update metadata fields (license, author, original_uuid, etc.)
    based on keyword/regex config provided in the job payload.
    """
    from app.features.rule.field_parser_core import parse_field_from_content, rescan_cve_ids, PARSEABLE_FIELD_KEYS

    payload       = job.payload or {}
    rule_ids      = payload.get('rule_ids', 'ALL')
    format_filter = payload.get('format_filter') or None
    fields_config = payload.get('fields_config', {})
    rescan_cve    = bool(payload.get('rescan_cve'))
    offset        = payload.get('_resume_offset', 0)

    enabled_fields = [k for k, v in fields_config.items() if v.get('enabled')]
    if not enabled_fields and not rescan_cve:
        log_job(job, 'No fields enabled — nothing to do.', level='warning', event='done')
        job.done = job.total or 0
        db.session.commit()
        return

    # with_entities column order: id, to_string, license, author, original_uuid, description, version, title, cve_id
    FIELD_IDX  = {k: i + 2 for i, k in enumerate(PARSEABLE_FIELD_KEYS)}
    CVE_IDX    = 2 + len(PARSEABLE_FIELD_KEYS)

    # Deterministic order is required: this job UPDATES the very rows it pages
    # through via OFFSET/LIMIT, and OFFSET pagination without a stable ORDER BY
    # can silently skip or re-show rows as the table is mutated mid-scan —
    # rows skipped this way looked like "new" CVEs again on the next full run.
    q = Rule.query.filter(Rule.is_deleted == False).order_by(Rule.id.asc())
    if rule_ids != 'ALL':
        q = q.filter(Rule.id.in_(rule_ids))
    elif format_filter:
        q = q.filter(Rule.format == format_filter)

    label_bits = list(enabled_fields) + (['cve/vulnerability'] if rescan_cve else [])
    if job.total == 0:
        job.total = q.count()
        db.session.commit()
        log_job(job, f'Starting — {job.total} rules to process, fields: {", ".join(label_bits)}.',
                level='info', event='start')
    else:
        log_job(job, f'Resuming from offset {offset}.', level='info', event='resume')

    total_updated = 0
    total_cve_added = 0
    batch_num     = 0

    while True:
        if _is_cancelled(job):
            log_job(job, 'Cancelled.', level='warning', event='cancelled')
            return
        while _should_pause(job):
            import time; time.sleep(2)

        rows = (
            q.with_entities(
                Rule.id, Rule.to_string,
                Rule.license, Rule.author, Rule.original_uuid,
                Rule.description, Rule.version, Rule.title,
                Rule.cve_id,
            )
            .offset(offset)
            .limit(FIELD_PARSE_BATCH)
            .all()
        )
        if not rows:
            break

        for row in rows:
            rule_id = row[0]
            content = row[1] or ''
            updates = {}

            for field_key in enabled_fields:
                if field_key not in FIELD_IDX:
                    continue
                cfg         = fields_config.get(field_key, {})
                current_val = row[FIELD_IDX[field_key]]

                if current_val and not cfg.get('overwrite', False):
                    continue

                new_val = parse_field_from_content(content, cfg)
                if new_val:
                    updates[field_key] = new_val

            if rescan_cve:
                changed, new_cve_json = rescan_cve_ids(content, row[CVE_IDX])
                if changed:
                    updates['cve_id'] = new_cve_json
                    total_cve_added += 1

            if updates:
                Rule.query.filter(Rule.id == rule_id).update(updates)
                total_updated += 1

        db.session.commit()
        offset    += len(rows)
        job.done   = offset
        _save_offset(job, offset)
        db.session.commit()

        batch_num += 1
        if batch_num % FIELD_PARSE_LOG_EVERY == 0:
            msg = f'{offset}/{job.total} rules processed, {total_updated} rules updated'
            if rescan_cve:
                msg += f' ({total_cve_added} with new CVE/vulnerability ids)'
            log_job(job, msg + '.', level='info', event='progress')

    done_msg = f'Done — {offset} rules processed, {total_updated} rules updated'
    if rescan_cve:
        done_msg += f', {total_cve_added} rule(s) got new CVE/vulnerability ids merged in'
    log_job(job, done_msg + '.', level='success', event='done')


# ─────────────────────────────────────────────────────────────────────────────
# bulk_tag_platforms — detect OS/platform mentions (or any other admin-defined
# regex → tag mapping) in rule content and attach the matching tag. Fully
# config-driven: the pattern list is an admin-authored FieldParserConfig row
# (config_type='platform_tags'), not a hardcoded dict — see
# field_parser_core.validate_platform_tag_config() and the "Platform Tags" tab
# on /account/admin/bulk_parse_fields.
# ─────────────────────────────────────────────────────────────────────────────

@register_handler('bulk_tag_platforms')
def handle_bulk_tag_platforms(job, app):
    """Scan rule title/description/content against an admin-defined config of
    (tag, regex) patterns and attach the matching tag. Additive only — never
    removes an existing tag, and never re-adds one a rule already has, so
    re-running this job is always safe.

    The config is re-validated here (not just trusted from when it was
    saved) since a referenced tag could have been deleted in the meantime —
    if that happened, the job stops immediately rather than silently running
    with a smaller pattern set than the admin configured.
    """
    from app.features.rule.field_parser_core import get_config, validate_platform_tag_config, CONFIG_TYPE_PLATFORM_TAGS

    payload       = job.payload or {}
    rule_ids      = payload.get('rule_ids', 'ALL')
    format_filter = payload.get('format_filter') or None
    offset        = payload.get('_resume_offset', 0)
    config_id     = payload.get('config_id')
    user_id       = job.created_by

    if not config_id:
        log_job(job, 'No config_id in job payload — nothing to run.', level='error', event='error')
        job.status = 'failed'
        job.error  = 'Missing config_id'
        db.session.commit()
        return

    cfg = get_config(config_id, config_type=CONFIG_TYPE_PLATFORM_TAGS)
    if not cfg:
        log_job(job, f'Config #{config_id} not found (deleted?) — aborting.', level='error', event='error')
        job.status = 'failed'
        job.error  = 'Config not found'
        db.session.commit()
        return

    ok, error, resolved_patterns = validate_platform_tag_config(cfg.config)
    if not ok:
        log_job(job, f'Config "{cfg.name}" is no longer valid — aborting without changing anything: {error}',
                level='error', event='error')
        job.status = 'failed'
        job.error  = error
        db.session.commit()
        return

    active_patterns = [p for p in resolved_patterns if p['enabled']]
    if not active_patterns:
        log_job(job, f'Config "{cfg.name}" has no enabled patterns — nothing to do.',
                level='warning', event='done')
        job.done = job.total or 0
        db.session.commit()
        return

    # Compile once; label kept alongside for logging.
    compiled = []
    for p in active_patterns:
        try:
            compiled.append((p, re.compile(p['regex'], re.IGNORECASE)))
        except re.error:
            # Already checked by validate_platform_tag_config, but a config
            # is free-form JSON — defense in depth against it changing shape
            # between validation and use within the same run.
            continue

    q = Rule.query.filter(Rule.is_deleted == False).order_by(Rule.id.asc())
    if rule_ids != 'ALL':
        q = q.filter(Rule.id.in_(rule_ids))
    elif format_filter:
        q = q.filter(Rule.format == format_filter)

    if job.total == 0:
        job.total = q.count()
        db.session.commit()
        pattern_names = ', '.join(p['label'] for p, _ in compiled)
        log_job(job, f'Starting — scanning {job.total} rule(s) using config "{cfg.name}" ({pattern_names}).',
                level='info', event='start')
    else:
        log_job(job, f'Resuming from offset {offset}.', level='info', event='resume')

    total_tagged       = 0
    total_associations = 0
    batch_num          = 0

    while True:
        if _is_cancelled(job):
            log_job(job, 'Cancelled.', level='warning', event='cancelled')
            return
        while _should_pause(job):
            import time; time.sleep(2)

        rows = (
            q.with_entities(Rule.id, Rule.title, Rule.description, Rule.to_string)
            .offset(offset)
            .limit(FIELD_PARSE_BATCH)
            .all()
        )
        if not rows:
            break

        touched_rule_ids = []
        for rule_id, title, description, content in rows:
            haystack = ' '.join(filter(None, [title, description, content]))
            if not haystack:
                continue
            matched = [p for p, pat in compiled if pat.search(haystack)]
            if not matched:
                continue

            existing_tag_ids = {
                tid for (tid,) in db.session.query(RuleTagAssociation.tag_id)
                    .filter(RuleTagAssociation.rule_id == rule_id).all()
            }
            new_assocs = 0
            for p in matched:
                if p['tag_id'] in existing_tag_ids:
                    continue
                db.session.add(RuleTagAssociation(
                    uuid=str(uuid_mod.uuid4()),
                    rule_id=rule_id,
                    tag_id=p['tag_id'],
                    user_id=user_id,
                    added_at=_now(),
                ))
                new_assocs += 1
            if new_assocs:
                total_tagged += 1
                total_associations += new_assocs
                touched_rule_ids.append(rule_id)

        db.session.commit()
        _refresh_quality_scores(touched_rule_ids)
        offset  += len(rows)
        job.done = offset
        _save_offset(job, offset)
        db.session.commit()

        batch_num += 1
        if batch_num % FIELD_PARSE_LOG_EVERY == 0:
            log_job(job, f'{offset}/{job.total} rules scanned, {total_tagged} rules tagged '
                         f'({total_associations} new tag association(s)).',
                    level='info', event='progress')

    log_job(job, f'Done — {offset} rule(s) scanned, {total_tagged} rule(s) tagged with '
                 f'{total_associations} new platform tag(s).', level='success', event='done')


# ─────────────────────────────────────────────────────────────────────────────
# blog_from_cve — auto-generate a blog post from vulnerability data
# ─────────────────────────────────────────────────────────────────────────────

def _circl_severity(score):
    try:
        s = float(score)
        if s >= 9.0: return 'Critical'
        if s >= 7.0: return 'High'
        if s >= 4.0: return 'Medium'
        return 'Low'
    except Exception:
        return 'Unknown'


def _parse_circl_v5(raw):
    """Normalise a CIRCL v5 CVE record into a flat dict used by _render_cve_section."""
    meta = raw.get('cveMetadata', {})
    containers = raw.get('containers', {})
    cna  = containers.get('cna', {})
    adps = containers.get('adp', []) if isinstance(containers.get('adp'), list) else []

    # ── Basic metadata ────────────────────────────────────────────────────
    cve_id   = meta.get('cveId', '')
    assigner = meta.get('assignerShortName', '')
    pub_raw  = meta.get('datePublished', '') or cna.get('datePublic', '')
    mod_raw  = meta.get('dateUpdated', '')
    pub      = pub_raw[:10] if pub_raw else ''
    mod      = mod_raw[:10] if mod_raw else ''

    # ── Title & description ───────────────────────────────────────────────
    cna_title = cna.get('title', '')
    descs     = cna.get('descriptions', [])
    summary   = next((d.get('value', '') for d in descs if d.get('lang', 'en').startswith('en')), '')

    # ── CVSS from CNA metrics ─────────────────────────────────────────────
    cvss_score, cvss_vector, cvss_sev = '', '', ''
    for m in (cna.get('metrics') or []):
        for key in ('cvssV3_1', 'cvssV3_0', 'cvssV4_0', 'cvssV2_0'):
            if key in m:
                c = m[key]
                cvss_score  = str(c.get('baseScore', ''))
                cvss_vector = c.get('vectorString', '')
                cvss_sev    = c.get('baseSeverity', _circl_severity(cvss_score))
                break
        if cvss_score:
            break

    # ── CWE ───────────────────────────────────────────────────────────────
    cwes = []
    for pt in (cna.get('problemTypes') or []):
        for d in (pt.get('descriptions') or []):
            cid  = d.get('cweId', '')
            cname = d.get('description', '')
            if cid:
                cwes.append((cid, cname))

    # ── Affected products ────────────────────────────────────────────────
    affected = []
    for a in (cna.get('affected') or []):
        entry = {
            'vendor':  a.get('vendor', ''),
            'product': a.get('product', '') or a.get('packageName', ''),
            'url':     a.get('collectionURL', ''),
            'versions': [
                v for v in (a.get('versions') or [])
                if v.get('status') == 'affected'
            ],
            'default': a.get('defaultStatus', ''),
        }
        if entry['product']:
            affected.append(entry)

    # ── References (CNA + CVE Program ADP) ───────────────────────────────
    refs = []
    seen = set()
    for src in [cna] + adps:
        for r in (src.get('references') or []):
            u = r.get('url', '')
            if u and u not in seen:
                seen.add(u)
                refs.append({'url': u, 'name': r.get('name', ''), 'tags': r.get('tags', [])})

    # ── Credits ───────────────────────────────────────────────────────────
    credits_ = []
    for c in (cna.get('credits') or []):
        v = c.get('value', '') or c.get('user', '')
        if v:
            credits_.append(v)

    # ── Timeline ──────────────────────────────────────────────────────────
    timeline = [
        {'date': t.get('time', '')[:10], 'event': t.get('value', '')}
        for t in (cna.get('timeline') or [])
        if t.get('value')
    ]

    # ── SSVC from CISA ADP ────────────────────────────────────────────────
    ssvc = {}
    for adp in adps:
        for m in (adp.get('metrics') or []):
            o = m.get('other', {})
            if o.get('type') == 'ssvc':
                content = o.get('content', {})
                for opt in (content.get('options') or []):
                    for k, v in opt.items():
                        ssvc[k] = v
                break

    return {
        'cve_id':      cve_id,
        'cna_title':   cna_title,
        'summary':     summary,
        'assigner':    assigner,
        'pub':         pub,
        'mod':         mod,
        'cvss_score':  cvss_score,
        'cvss_vector': cvss_vector,
        'cvss_sev':    cvss_sev or _circl_severity(cvss_score),
        'cwes':        cwes,
        'affected':    affected,
        'refs':        refs,
        'credits':     credits_,
        'timeline':    timeline,
        'ssvc':        ssvc,
    }



def _render_cve_section(cve_id, parsed, epss_pct=None, rule_count=0, bundle_count=0):
    """Generate rich, human-readable markdown from a parsed CIRCL v5 record."""
    summary    = parsed.get('summary', '')
    cna_title  = parsed.get('cna_title', '')
    cvss_score = parsed.get('cvss_score', '')
    cvss_vec   = parsed.get('cvss_vector', '')
    cvss_sev   = parsed.get('cvss_sev', '')
    cwes       = parsed.get('cwes', [])
    affected   = parsed.get('affected', [])
    refs       = parsed.get('refs', [])
    cred_names = parsed.get('credits', [])
    timeline   = parsed.get('timeline', [])
    ssvc       = parsed.get('ssvc', {})
    assigner   = parsed.get('assigner', '')
    pub        = parsed.get('pub', '')
    mod        = parsed.get('mod', '')

    sev = cvss_sev or _circl_severity(cvss_score)
    sev_lower = sev.lower() if sev else ''

    lines = []

    # ── Lead paragraph ────────────────────────────────────────────────────
    prod_names = list({a['product'] for a in affected if a['product']})[:4]
    prod_str   = ', '.join(f'**{p}**' for p in prod_names) if prod_names else ''

    if cna_title:
        lines.append(f'> {_html.escape(cna_title)}\n')

    if summary:
        lines.append(_html.escape(summary) + '\n')
    elif prod_str:
        lines.append(f'{cve_id} is a {sev_lower} vulnerability affecting {prod_str}.\n')

    # ── Severity & Risk Assessment ────────────────────────────────────────
    lines.append('## Severity & Risk Assessment\n')

    sev_prose = {
        'Critical': (
            f'This vulnerability is rated **Critical** (CVSS {cvss_score}) — '
            'the highest possible severity level. Successful exploitation can lead to '
            'complete system compromise, often remotely and without authentication.'
        ),
        'High': (
            f'Rated **High** severity (CVSS {cvss_score}), this vulnerability represents '
            'a significant risk to affected systems and should be treated as a priority.'
        ),
        'Medium': (
            f'This vulnerability carries a **Medium** severity rating (CVSS {cvss_score}). '
            'Exploitation typically requires specific conditions or user interaction, but it '
            'should not be ignored in exposed environments.'
        ),
        'Low': (
            f'Classified as **Low** severity (CVSS {cvss_score}), the practical impact of '
            'this vulnerability is limited in most deployment scenarios.'
        ),
    }.get(sev, '')
    if sev_prose:
        lines.append(sev_prose + '\n')

    # CVSS breakdown
    if cvss_vec:
        # Parse vector components for human explanation
        parts = {}
        for segment in cvss_vec.split('/'):
            if ':' in segment:
                k, v = segment.split(':', 1)
                parts[k] = v
        av_map  = {'N': 'Network (remotely exploitable)', 'A': 'Adjacent network', 'L': 'Local access', 'P': 'Physical access'}
        ac_map  = {'L': 'Low complexity', 'H': 'High complexity'}
        pr_map  = {'N': 'No privileges required', 'L': 'Low privileges', 'H': 'High privileges'}
        ui_map  = {'N': 'No user interaction required', 'R': 'Requires user interaction'}
        imp_map = {'H': 'High', 'L': 'Low', 'N': 'None'}
        lines.append('**CVSS v3.1 Breakdown:**\n')
        lines.append(f'| Attribute | Value |')
        lines.append(f'|-----------|-------|')
        lines.append(f'| Score | **{cvss_score}** ({sev}) |')
        if 'AV' in parts: lines.append(f'| Attack Vector | {av_map.get(parts["AV"], parts["AV"])} |')
        if 'AC' in parts: lines.append(f'| Attack Complexity | {ac_map.get(parts["AC"], parts["AC"])} |')
        if 'PR' in parts: lines.append(f'| Privileges Required | {pr_map.get(parts["PR"], parts["PR"])} |')
        if 'UI' in parts: lines.append(f'| User Interaction | {ui_map.get(parts["UI"], parts["UI"])} |')
        if 'C'  in parts: lines.append(f'| Confidentiality Impact | {imp_map.get(parts["C"], parts["C"])} |')
        if 'I'  in parts: lines.append(f'| Integrity Impact | {imp_map.get(parts["I"], parts["I"])} |')
        if 'A'  in parts: lines.append(f'| Availability Impact | {imp_map.get(parts["A"], parts["A"])} |')
        lines.append(f'| Vector String | `{cvss_vec}` |\n')

    # EPSS
    if epss_pct is not None:
        risk_level = 'extremely high' if epss_pct > 50 else 'high' if epss_pct > 10 else 'moderate' if epss_pct > 1 else 'low'
        lines.append(
            f'**EPSS Score: {epss_pct:.2f}%** — {risk_level} probability of real-world exploitation '
            f'within the next 30 days based on threat intelligence data.\n'
        )

    # SSVC
    if ssvc:
        lines.append('**SSVC Assessment (CISA):**\n')
        for k, v in ssvc.items():
            lines.append(f'- **{k}**: {v}')
        lines.append('')

    # CWE
    if cwes:
        lines.append('**Weakness Classification:**\n')
        for cid, cname in cwes:
            num = cid.replace('CWE-', '')
            lines.append(f'- [{cid}](https://cwe.mitre.org/data/definitions/{num}.html) — {cname}')
        lines.append('')

    # ── Affected products & versions ──────────────────────────────────────
    if affected:
        lines.append('## Affected Products & Versions\n')
        shown = []
        for a in affected:
            prod    = a['product']
            vendor  = a['vendor']
            vers    = a['versions']
            default = a['default']
            url     = a['url']

            if not prod or prod in shown:
                continue
            shown.append(prod)

            header = f'**{prod}**'
            if vendor:
                header += f' by {vendor}'
            if url:
                header += f' ([source]({url}))'
            lines.append(f'### {header}\n')

            if vers:
                lines.append('Affected versions:\n')
                for v in vers[:10]:
                    ver_str = v.get('version', '')
                    thru    = v.get('versionEndIncluding', '') or v.get('lessThanOrEqual', '')
                    lt      = v.get('lessThan', '')
                    if thru:
                        lines.append(f'- `{ver_str}` through `{thru}` (inclusive)')
                    elif lt:
                        lines.append(f'- `{ver_str}` up to (but not including) `{lt}`')
                    else:
                        lines.append(f'- `{ver_str}`')
                lines.append('')
            elif default == 'unaffected':
                lines.append('*Default status: unaffected — specific versions listed above may still be impacted.*\n')

    # ── Timeline ─────────────────────────────────────────────────────────
    if timeline or pub:
        lines.append('## Vulnerability Timeline\n')
        if pub:
            lines.append(f'- **{pub}** — CVE published by {assigner or "the assigning organization"}')
        for t in timeline:
            d, e = t['date'], t['event']
            if d:
                lines.append(f'- **{d}** — {e}')
            else:
                lines.append(f'- {e}')
        if mod and mod != pub:
            lines.append(f'- **{mod}** — Entry last updated')
        lines.append('')

    # ── Detection with Rulezet ────────────────────────────────────────────
    if rule_count or bundle_count:
        lines.append('## Detect This Threat with Rulezet\n')
        parts = []
        if rule_count:
            parts.append(f'**{rule_count}** detection rule{"s" if rule_count != 1 else ""}')
        if bundle_count:
            parts.append(f'**{bundle_count}** detection bundle{"s" if bundle_count != 1 else ""}')
        lines.append(
            f'Rulezet already has {" and ".join(parts)} that cover {cve_id}. '
            'These have been automatically attached to this post so your security team can deploy '
            'them immediately. Browse and download them in the **Detection Rules** section below.\n'
        )
        if rule_count:
            lines.append(
                f'Using these rules you can identify exploitation attempts, post-exploitation '
                f'activity, and malicious artifacts associated with {cve_id} in your environment.\n'
            )

    # ── What to do ────────────────────────────────────────────────────────
    lines.append('## What Should You Do?\n')
    lines.append(
        '**Patch immediately.** Apply the latest security updates from the vendor. '
        'If patching is not immediately possible, consider the following interim measures:\n'
    )
    lines.append('1. Identify all instances of affected software in your environment')
    lines.append('2. Apply available workarounds or mitigations from the vendor advisory')
    lines.append('3. Increase monitoring for indicators of compromise')
    if rule_count or bundle_count:
        lines.append('4. Deploy the detection rules available in Rulezet to catch exploitation attempts')
    lines.append('5. Review access controls and restrict exposure of vulnerable services')
    lines.append(
        f'\nFor the latest patch information and affected version ranges, '
        f'consult the [official {cve_id} advisory](https://vulnerability.circl.lu/vuln/{cve_id.lower()}) '
        f'on Vulnerability Lookup.\n'
    )

    # ── References ────────────────────────────────────────────────────────
    if refs:
        lines.append('## External References\n')
        # Categorize
        advisories, patches, other_refs = [], [], []
        for r in refs[:20]:
            u    = r['url']
            name = r['name'] or u
            tags = r.get('tags', [])
            label = r['name'] if r['name'] and r['name'] != u else None
            entry = f'- [{label or u}]({u})' if label else f'- {u}'
            if any(t in tags for t in ('vendor-advisory', 'x_refsource_REDHAT', 'x_refsource_DEBIAN')):
                advisories.append(entry)
            elif any(t in tags for t in ('patch', 'issue-tracking')):
                patches.append(entry)
            else:
                other_refs.append(entry)
        if advisories:
            lines.append('**Vendor Advisories:**\n')
            lines += advisories + ['']
        if patches:
            lines.append('**Patches & Issue Trackers:**\n')
            lines += patches + ['']
        if other_refs:
            lines.append('**Additional Resources:**\n')
            lines += other_refs[:8] + ['']

    # ── Credits ───────────────────────────────────────────────────────────
    if cred_names:
        lines.append('## Credits\n')
        if len(cred_names) == 1:
            lines.append(f'This vulnerability was discovered and responsibly disclosed by **{cred_names[0]}**.\n')
        else:
            lines.append('Responsibly disclosed by:\n')
            lines += [f'- {n}' for n in cred_names]
            lines.append('')

    lines += [
        '---',
        f'*Data sourced from [Vulnerability Lookup](https://vulnerability.circl.lu) '
        f'(assigner: {assigner}). For real-time updates and additional technical details, '
        f'visit the [{cve_id} entry](https://vulnerability.circl.lu/vuln/{cve_id.lower()}).*',
    ]
    return '\n'.join(lines)


@register_handler('blog_from_cve')
def handle_blog_from_cve(job, app):
    payload         = job.payload or {}
    post_id         = payload.get('post_id')
    cve_ids         = payload.get('cve_ids') or []
    formats         = payload.get('formats') or []
    include_rules   = payload.get('include_rules', True)
    include_bundles = payload.get('include_bundles', True)

    with app.app_context():
        import requests as _req
        from app.core.db_class.db import BlogPost, Bundle
        from app.features.blog.blog_core import _sync_tags, _sync_rules, _sync_bundles, _make_slug

        post = BlogPost.query.get(post_id)
        if not post:
            log_job(job, f'BlogPost {post_id} not found.', level='error', event='error')
            return

        log_job(job, f'Generating CVE post for: {", ".join(cve_ids)}', event='start')

        # 1. Fetch CVE data
        cve_data = {}
        for cve_id in cve_ids:
            try:
                resp = _req.get(
                    f'https://vulnerability.circl.lu/api/cve/{cve_id.lower()}',
                    timeout=15,
                    headers={'Accept': 'application/json', 'User-Agent': 'Rulezet/1.0'},
                )
                if resp.ok:
                    cve_data[cve_id] = resp.json()
                    log_job(job, f'Fetched {cve_id} from Vulnerability Lookup.', event='progress')
                else:
                    log_job(job, f'CIRCL API {resp.status_code} for {cve_id}.', level='warning', event='warning')
                    cve_data[cve_id] = {}
            except Exception as exc:
                log_job(job, f'Could not fetch {cve_id}: {exc}', level='warning', event='warning')
                cve_data[cve_id] = {}

        # 2. Match rules / bundles
        matched_rule_ids, matched_bundle_ids = [], []
        if include_rules:
            q = Rule.query.filter(Rule.is_deleted == False)
            if formats:
                q = q.filter(Rule.format.in_(formats))
            for cve_id in cve_ids:
                for r in q.filter(Rule.cve_id.ilike(f'%{cve_id}%')).all():
                    if r.id not in matched_rule_ids:
                        matched_rule_ids.append(r.id)
            log_job(job, f'{len(matched_rule_ids)} matching rule(s) found.', event='progress')

        if include_bundles:
            for cve_id in cve_ids:
                for b in Bundle.query.filter(
                    Bundle.vulnerability_identifiers.ilike(f'%{cve_id}%')
                ).all():
                    if b.id not in matched_bundle_ids:
                        matched_bundle_ids.append(b.id)
            log_job(job, f'{len(matched_bundle_ids)} matching bundle(s) found.', event='progress')

        # 3. Cover image — use the bundled Vulnerability Lookup default
        cover_url = '/static/uploads/blog/vendor/vulnerability_to_rulezet.png'

        # 4. Parse v5 format + fetch EPSS for each CVE
        parsed_data = {}
        epss_map    = {}
        for cve_id in cve_ids:
            raw = cve_data.get(cve_id, {})
            parsed_data[cve_id] = _parse_circl_v5(raw) if raw else {}
            try:
                er = _req.get(
                    f'https://vulnerability.circl.lu/api/epss/{cve_id}',
                    timeout=8,
                    headers={'Accept': 'application/json', 'User-Agent': 'Rulezet/1.0'},
                )
                if er.ok:
                    edata = er.json().get('data') or []
                    if edata:
                        sc = edata[0].get('epss') or edata[0].get('score')
                        if sc:
                            epss_map[cve_id] = float(sc) * 100
            except Exception:
                pass

        def _make_title(cve_id, parsed, epss_pct, rule_count, bundle_count):
            """Generate a compelling, specific blog post title."""
            sev       = parsed.get('cvss_sev', '') or _circl_severity(parsed.get('cvss_score', ''))
            cvss      = parsed.get('cvss_score', '')
            cna_title = parsed.get('cna_title', '')
            affected  = parsed.get('affected', [])
            prod_names = [a['product'] for a in affected if a['product']]

            sev_label = {
                'Critical': 'Critical',
                'High':     'High-Severity',
                'Medium':   'Medium-Severity',
                'Low':      'Low-Risk',
            }.get(sev, sev)

            # Subject = cna_title or first product
            subject = cna_title or (prod_names[0] if prod_names else '')

            if epss_pct is not None and epss_pct > 50:
                exploit_note = ' — Active Exploitation Risk'
            elif epss_pct is not None and epss_pct > 10:
                exploit_note = ' — High Exploitation Probability'
            else:
                exploit_note = ''

            if rule_count or bundle_count:
                det_parts = []
                if rule_count:
                    det_parts.append(f'{rule_count} Rule{"s" if rule_count != 1 else ""}')
                if bundle_count:
                    det_parts.append(f'{bundle_count} Bundle{"s" if bundle_count != 1 else ""}')
                det = f' | {" & ".join(det_parts)} in Rulezet'
            else:
                det = ' | What You Need to Know'

            if subject:
                title = f'{cve_id} ({sev_label} CVSS {cvss}): {subject}{exploit_note}{det}'
            else:
                title = f'{cve_id} ({sev_label} CVSS {cvss}){exploit_note}{det}'

            return title[:500]

        def _make_excerpt(cve_id, parsed, epss_pct, rule_count, bundle_count):
            sev     = parsed.get('cvss_sev', '')
            cvss    = parsed.get('cvss_score', '')
            summary = (parsed.get('summary', '') or '')[:300]
            det = ''
            if rule_count or bundle_count:
                parts = []
                if rule_count:
                    parts.append(f'{rule_count} detection rule{"s" if rule_count != 1 else ""}')
                if bundle_count:
                    parts.append(f'{bundle_count} bundle{"s" if bundle_count != 1 else ""}')
                det = f' Rulezet contains {" and ".join(parts)} to protect your environment.'
            epss_note = f' EPSS: {epss_pct:.1f}% exploitation probability.' if epss_pct else ''
            intro = (
                f'{cve_id} is a {sev.lower()} vulnerability (CVSS {cvss}).'
                if cvss else f'Security advisory for {cve_id}.'
            )
            return f'{intro}{epss_note} {summary}{"…" if len(summary) == 300 else ""}{det}'.strip()

        # 5. Generate content
        nr, nb = len(matched_rule_ids), len(matched_bundle_ids)
        if len(cve_ids) == 1:
            cid     = cve_ids[0]
            parsed  = parsed_data.get(cid, {})
            epss_pct = epss_map.get(cid)
            title   = _make_title(cid, parsed, epss_pct, nr, nb)
            excerpt = _make_excerpt(cid, parsed, epss_pct, nr, nb)
            content = _render_cve_section(cid, parsed, epss_pct=epss_pct, rule_count=nr, bundle_count=nb)
        else:
            cids_str  = ', '.join(cve_ids)
            all_sevs  = [p.get('cvss_sev', '') for p in parsed_data.values() if p.get('cvss_sev')]
            worst_sev = next((s for s in ['Critical', 'High', 'Medium', 'Low'] if s in all_sevs), '')
            title     = (
                f'Security Advisory: {cids_str[:70]}{"…" if len(cids_str) > 70 else ""}'
                + (f' ({worst_sev})' if worst_sev else '')
                + (f' | {nr} Detection Rule{"s" if nr != 1 else ""} in Rulezet' if nr else '')
            )
            excerpt = (
                f'Combined vulnerability advisory covering {len(cve_ids)} CVEs: {cids_str[:200]}.'
                + (f' {nr} detection rule{"s" if nr != 1 else ""} available in Rulezet.' if nr else '')
            )
            sections = []
            for cid in cve_ids:
                parsed   = parsed_data.get(cid, {})
                epss_pct = epss_map.get(cid)
                sections.append(
                    f'# {cid}\n\n'
                    + _render_cve_section(cid, parsed, epss_pct=epss_pct,
                                          rule_count=nr, bundle_count=nb)
                )
            content = '\n\n---\n\n'.join(sections)

        # 5. Update the draft post
        post.title           = title[:500]
        post.slug            = _make_slug(title, exclude_id=post.id)
        post.excerpt         = excerpt
        post.content         = content
        post.cover_image_url = cover_url
        post.cve_ids         = cve_ids
        post.external_links  = [
            {'url': f'https://vulnerability.circl.lu/vuln/{c.lower()}',
             'label': f'{c} — Vulnerability Lookup'}
            for c in cve_ids
        ]
        post.updated_at = datetime.datetime.utcnow()
        db.session.flush()

        _sync_tags(post, ['vulnerability', 'cve'] + [c.lower() for c in cve_ids])
        _sync_rules(post, matched_rule_ids)
        _sync_bundles(post, matched_bundle_ids)
        db.session.commit()

        log_job(job, f'Post "{title[:80]}" ready.', level='success', event='done')


# ─── rule_test_bulk ───────────────────────────────────────────────────────────

@register_handler('rule_test_bulk')
def handle_rule_test_bulk(job, app):
    import time as _time
    from app.core.db_class.db import RuleTest
    from app.features.rule_tester import rule_tester_core as TesterModel
    from app.features.rule_tester.drivers import registry

    payload    = job.payload or {}
    test_uuid  = payload.get('test_uuid')
    fmt        = payload.get('format', '').lower()
    input_type = payload.get('input_type', 'string')
    input_data = payload.get('input_data', '')
    filters    = payload.get('bulk_filters', {})

    test = RuleTest.query.filter_by(uuid=test_uuid).first()
    if not test:
        raise ValueError(f'RuleTest {test_uuid} not found')

    driver = registry.get_driver(fmt)
    if not driver:
        raise ValueError(f'No driver for format: {fmt}')

    rule_query = _build_rule_query(filters)
    if fmt:
        rule_query = rule_query.filter(Rule.format.ilike(f'%{fmt}%'))

    # Load only IDs first — avoids pulling 100k ORM objects into memory at once
    rule_ids = [row[0] for row in rule_query.with_entities(Rule.id).all()]
    total    = len(rule_ids)

    job.total = total
    job.done  = 0
    db.session.commit()

    log_job(job, f'Bulk {fmt.upper()} test — {total} rule(s) found', level='info', event='started')
    TesterModel.mark_test_running(test)

    if total == 0:
        log_job(job, 'No rules matched the filters.', level='warning', event='done')
        TesterModel.mark_test_done(test, matched_count=0, total_rules=0)
        return

    input_dict    = {'type': input_type, 'value': input_data}
    matched_count = 0

    # ── YARA: mini-batches of 500 with resume support + 4 checkpoint logs ─────
    if fmt == 'yara':
        from app.features.rule_tester.drivers.yara_driver import YaraDriver

        MINI_BATCH  = 500
        resume_from = (job.payload or {}).get('_resume_offset', 0)
        if resume_from:
            log_job(job, f'Resuming from offset {resume_from}', level='info')
            matched_count = TesterModel.count_matched_results(test.id)

        logged_pcts = set()
        offset      = resume_from

        while offset < total:
            _reload(job)
            if _is_cancelled(job):
                log_job(job, 'Job cancelled.', level='warning', event='cancelled')
                return
            while _should_pause(job):
                _time.sleep(1)
                _reload(job)

            batch_ids   = rule_ids[offset:offset + MINI_BATCH]
            batch_rules = rule_query.filter(Rule.id.in_(batch_ids)).all()

            sources = {str(r.id): r.to_string or '' for r in batch_rules}
            try:
                batch_results = YaraDriver.run_batch(sources, input_dict)
            except Exception as e:
                log_job(job, f'Compile error at offset {offset}: {e}', level='error')
                batch_results = {}

            for rule in batch_rules:
                detail = batch_results.get(str(rule.id))
                if detail is None:
                    d_matched, d_score, d_details, d_hints, d_err, d_ms = \
                        False, 0.0, {}, [], 'No result', 0
                else:
                    d_matched  = detail.matched
                    d_score    = detail.score
                    d_details  = detail.details
                    d_hints    = detail.quality_hints
                    d_err      = detail.error
                    d_ms       = detail.execution_time_ms

                TesterModel.create_result(
                    test_id=test.id, rule_id=rule.id, rule_title=rule.title,
                    rule_uuid=rule.uuid, rule_format=rule.format,
                    matched=d_matched, score=d_score,
                    details=d_details, quality_hints=d_hints,
                    execution_time_ms=d_ms, error=d_err,
                )
                if d_matched:
                    matched_count += 1

            offset   += len(batch_rules)
            job.done  = offset

            # persist resume point so a server restart can continue here
            p = dict(job.payload or {})
            p['_resume_offset'] = offset
            job.payload = p

            # log every 2500 rules + at 25/50/75/100% checkpoints
            LOG_EVERY = 2500
            prev_log  = ((offset - len(batch_rules)) // LOG_EVERY) * LOG_EVERY
            curr_log  = (offset // LOG_EVERY) * LOG_EVERY
            if curr_log > prev_log or offset >= total:
                log_job(job,
                        f'{offset:,}/{total:,} rules — {matched_count} match(es) so far',
                        level='info', event='batch')

            for pct in [25, 50, 75, 100]:
                if pct not in logged_pcts and offset >= int(total * pct / 100):
                    log_job(job,
                            f'{pct}% checkpoint — {offset:,}/{total:,} processed, '
                            f'{matched_count} match(es)',
                            level='info', event='batch')
                    logged_pcts.add(pct)

            db.session.commit()

    # ── Other formats: rule-by-rule ────────────────────────────────────────────
    else:
        all_rules = rule_query.all()
        for i, rule in enumerate(all_rules):
            _reload(job)
            if _is_cancelled(job):
                log_job(job, 'Job cancelled.', level='warning', event='cancelled')
                return
            while _should_pause(job):
                _time.sleep(1)
                _reload(job)

            log_lines = []
            def _log_fn(level, message):
                log_lines.append(message)

            try:
                detail = driver.run_test(rule.to_string or '', input_dict, _log_fn)
            except Exception as e:
                TesterModel.create_result(
                    test_id=test.id, rule_id=rule.id, rule_title=rule.title,
                    rule_uuid=rule.uuid, rule_format=rule.format,
                    matched=False, score=0.0, details={}, quality_hints=[],
                    execution_time_ms=0, error=str(e),
                )
                log_job(job, f'[{rule.uuid[:8]}] ERROR: {e}', level='error')
                job.done += 1
                db.session.commit()
                continue

            TesterModel.create_result(
                test_id=test.id, rule_id=rule.id, rule_title=rule.title,
                rule_uuid=rule.uuid, rule_format=rule.format,
                matched=detail.matched, score=detail.score,
                details=detail.details, quality_hints=detail.quality_hints,
                execution_time_ms=detail.execution_time_ms, error=detail.error,
            )
            if detail.matched:
                matched_count += 1

            job.done += 1
            if (i + 1) % 10 == 0 or (i + 1) == total:
                log_job(job, f'Progress: {job.done}/{total} — {matched_count} match(es)',
                        level='info', event='batch')
            db.session.commit()

    test.matched_count = matched_count
    test.total_rules   = total
    TesterModel.mark_test_done(test, matched_count=matched_count, total_rules=total)
    log_job(job, f'Done — {matched_count}/{total} rules matched.',
            level='success', event='done')


# ─────────────────────────────────────────────────────────────────────────────
#  github_sync_schedule_run — execute one firing of a recurring Sync Schedule
# ─────────────────────────────────────────────────────────────────────────────

REPO_SYNC_TIMEOUT_SECONDS = 1800  # 30 min per repo — one hung repo must never block the rest of the schedule


@register_handler('github_sync_schedule_run')
def handle_github_sync_schedule_run(job, app):
    """
    One firing of a GithubSyncSchedule. Loops its repos, reusing the exact
    same mechanism as a manual GitHub update check (Update_class) for each
    one, then — per repo — reuses the exact same core functions the manual
    "Accept all" / "Add all new rules" buttons call if that repo has
    auto_accept_update / auto_add_new_rule enabled.

    IMPORTANT: there is exactly one global job_worker thread (job_worker.py).
    This handler must never enqueue another BackgroundJob and wait for it —
    that would deadlock, since this very thread is the only one that could
    ever pick it up. All per-rule decision logic is called in-process here.

    No nested `with app.app_context()` — see the comment on
    handle_bulk_update_decision() for why that silently breaks progress
    tracking.

    Payload: schedule_uuid, run_uuid.
    job.total is set to len(schedule.repos) when the run was created
    (scheduler_engine._fire_schedule) — progress is one unit per repo, not
    per rule, matching the fix already applied to Update_class/Session_class
    (a per-rule progress bar across N repos would reintroduce the exact
    "0→N jump" bug the whole GitHub import/update rework started from).
    """
    from app.core.db_class.db import GithubSyncSchedule, GithubSyncRun, GithubSyncRunRepo
    from app.features.rule.rule_core import (
        get_updater_result, get_rule_update_list_filtered, accept_all_update,
        get_valid_new_rules_by_sid, import_single_new_rule,
    )
    from app.features.rule.rule_from_github.update_rule import update_class as UpdateModel

    payload      = job.payload or {}
    schedule_uuid = payload.get('schedule_uuid')
    run_uuid      = payload.get('run_uuid')

    run = GithubSyncRun.query.filter_by(uuid=run_uuid).first()
    schedule = GithubSyncSchedule.query.filter_by(uuid=schedule_uuid).first()

    if not run or not schedule:
        job.status = 'failed'
        job.error = 'Sync Schedule or run not found (deleted before the job started?).'
        log_job(job, job.error, level='error', event='failed')
        db.session.commit()
        return

    try:
        run.status = 'running'
        db.session.commit()

        repos = list(schedule.repos)
        job.total = max(len(repos), 1)

        for i, repo_cfg in enumerate(repos):
            if _is_cancelled(job):
                log_job(job, f"Cancelled at {job.done}/{job.total} repo(s).", level='warning', event='cancelled')
                run.status = 'failed'
                db.session.commit()
                return
            if _should_pause(job):
                db.session.commit()
                log_job(job, f"Paused at {job.done}/{job.total} repo(s). Click Resume to continue.",
                        level='info', event='paused')
                return

            run_repo = GithubSyncRunRepo(run_id=run.id, repo_url=repo_cfg.repo_url, status='running')
            db.session.add(run_repo)
            db.session.commit()
            log_job(job, f"Checking '{repo_cfg.repo_url}'…", level='info', event='progress')

            info = {
                "mode": "by_url",
                "repo_url": repo_cfg.repo_url,
                "initiated_by": f"Sync Schedule — {schedule.title}",
                "author": (schedule.editor.last_name if schedule.editor else None),
                "license": None,
                "description": None,
            }
            update_session = UpdateModel.Update_class([repo_cfg.repo_url], schedule.editor, info, mode="by_url")
            update_session.start()
            UpdateModel.sessions.append(update_session)

            finished = update_session._save_done.wait(timeout=REPO_SYNC_TIMEOUT_SECONDS)
            if not finished:
                run_repo.status = 'error'
                run_repo.error_message = f'Timed out after {REPO_SYNC_TIMEOUT_SECONDS}s.'
                log_job(job, f"'{repo_cfg.repo_url}' timed out.", level='error', event='progress')
                job.done = i + 1
                db.session.commit()
                continue

            sid = update_session.uuid
            run_repo.update_result_uuid = sid
            result = get_updater_result(sid)
            if not result:
                run_repo.status = 'error'
                run_repo.error_message = 'Update session finished but produced no result (see server logs).'
                log_job(job, f"'{repo_cfg.repo_url}' produced no result.", level='error', event='progress')
                job.done = i + 1
                db.session.commit()
                continue

            if repo_cfg.auto_accept_update:
                rule_list, count = get_rule_update_list_filtered(sid)
                if count:
                    # accept_all_update force-rejects rule_syntax_valid == False rows —
                    # it never auto-accepts an invalid-syntax update, by design.
                    run_repo.auto_accepted = sum(1 for r in rule_list if r.rule_syntax_valid)
                    run_repo.auto_rejected = sum(1 for r in rule_list if not r.rule_syntax_valid)
                    accept_all_update(rule_list)
                    log_job(job, f"'{repo_cfg.repo_url}': auto-accepted {run_repo.auto_accepted} update(s), "
                                 f"auto-rejected {run_repo.auto_rejected} invalid-syntax update(s).",
                            level='success', event='progress')

            if repo_cfg.auto_add_new_rule:
                new_rules = get_valid_new_rules_by_sid(sid)
                added = 0
                for nr in new_rules:
                    added_ok, _message = import_single_new_rule(nr, schedule.editor)
                    if added_ok:
                        added += 1
                run_repo.auto_added = added
                if new_rules:
                    log_job(job, f"'{repo_cfg.repo_url}': auto-added {added}/{len(new_rules)} new rule(s).",
                            level='success', event='progress')

            run_repo.status = 'done'
            job.done = i + 1
            db.session.commit()

        run.status = 'done'
        run.finished_at = datetime.datetime.utcnow()
        schedule.last_run_at = run.finished_at
        job.status = 'done'
        db.session.commit()

        log_job(job, f'Sync Schedule run finished — {len(repos)} repo(s) processed.', level='success', event='done')

        try:
            from app.features.notification.notification_core import notify_admins_sync_run_finished
            notify_admins_sync_run_finished(run)
        except Exception as e:
            print(f"[job_handlers] notify_admins_sync_run_finished error: {e}")

    except Exception as e:
        job.status = 'failed'
        job.error = str(e)
        run.status = 'failed'
        log_job(job, str(e), level='error', event='failed')
        db.session.commit()


# ─── Velociraptor: push a generated artifact to a connected server ───────────

@register_handler('velociraptor_push')
def handle_velociraptor_push(job, app):
    """
    Generate the Velociraptor artifact YAML for a rule and push it to a
    configured Velociraptor server over gRPC (mutual TLS).

    Payload:
        server_id : int — local VelociraptorServer.id to push to
        rule_id   : int — local Rule.id to generate the artifact from
    """
    from app.core.db_class.db import VelociraptorServer
    from app.features.rule import rule_core as RuleModel
    from app.features.velociraptor import velociraptor_core as VelociraptorModel
    from app.features.rule.exporters.velociraptor_exporter import (
        generate_velociraptor_artifact, SUPPORTED_FORMATS,
    )

    payload   = job.payload or {}
    server_id = payload.get('server_id')
    rule_id   = payload.get('rule_id')

    server = VelociraptorServer.query.get(server_id)
    if not server or not server.is_active:
        log_job(job, 'Velociraptor server not found or disabled.', level='error', event='done')
        job.status = 'failed'
        job.error  = 'Server not found or disabled.'
        db.session.commit()
        return

    rule = RuleModel.get_rule(rule_id)
    if not rule:
        log_job(job, f'Rule {rule_id} not found (deleted?).', level='error', event='done')
        job.status = 'failed'
        job.error  = 'Rule not found.'
        db.session.commit()
        return

    if (rule.format or '').lower() not in SUPPORTED_FORMATS:
        msg = f"Velociraptor export is not supported for format '{rule.format}'."
        log_job(job, msg, level='error', event='done')
        job.status = 'failed'
        job.error  = msg
        db.session.commit()
        return

    log_job(job, f"Generating artifact for '{rule.title}'…", level='info', event='started')
    try:
        # No active `request` in a background job (unlike the route-based
        # generation, which uses request.host_url) — FLASK_URL/FLASK_PORT are
        # just a bare host/port, so reconstruct a real URL for the artifact's
        # "Source:" link.
        host = app.config.get('FLASK_URL', '127.0.0.1')
        port = app.config.get('FLASK_PORT', 7009)
        base_url = f"http://{host}:{port}"
        artifact_yaml = generate_velociraptor_artifact(rule, base_url=base_url)
    except Exception as e:
        log_job(job, f"Artifact generation failed: {e}", level='error', event='done')
        job.status = 'failed'
        job.error  = str(e)
        db.session.commit()
        return

    log_job(job, f"Pushing artifact to '{server.name}'…", level='info', event='progress')
    ok, msg = VelociraptorModel.push_artifact(server, artifact_yaml)

    job.done   = 1
    job.total  = 1
    job.status = 'done' if ok else 'failed'
    if not ok:
        job.error = msg
    db.session.commit()

    log_job(job, msg, level='success' if ok else 'error', event='done')
    log_activity('velociraptor.push_done', f"Push to '{server.name}': {msg}",
                 target_type='velociraptor_server', target_id=server.id, target_uuid=server.uuid,
                 actor_id=job.created_by,
                 extra={'rule_id': rule.id, 'rule_uuid': rule.uuid, 'rule_title': rule.title, 'success': ok,
                        'job_id': job.id, 'job_uuid': job.uuid})


# ─── MISP: push a rule's MISP Object/Event to a connected instance ──────────

@register_handler('misp_push')
def handle_misp_push(job, app):
    """
    Build a rule's MISP Object/Event, or a bundle's MISP Event, and push it to
    a configured MISP instance over its REST API.

    Payload:
        server_id : int — local MispServer.id to push to
        rule_id   : int — local Rule.id to build the object/event from (rule push)
        bundle_id : int — local Bundle.id to build the event from (bundle push)
        push_type : 'object' | 'event' — bundles only support 'event'
    """
    from app.core.db_class.db import MispServer
    from app.features.rule import rule_core as RuleModel
    from app.features.bundle import bundle_core as BundleModel
    from app.features.misp import misp_connector_core as MispModel
    from app.features.misp.rule.misp_object import (
        get_rule_misp_object_base, get_rule_misp_event_object,
    )
    from app.features.misp.bundle.misp_object import get_bundle_misp_event_object

    payload   = job.payload or {}
    server_id = payload.get('server_id')
    rule_id   = payload.get('rule_id')
    bundle_id = payload.get('bundle_id')
    push_type = payload.get('push_type', 'object')

    server = MispServer.query.get(server_id)
    if not server or not server.is_active:
        log_job(job, 'MISP server not found or disabled.', level='error', event='done')
        job.status = 'failed'
        job.error  = 'Server not found or disabled.'
        db.session.commit()
        return

    if bundle_id:
        target = BundleModel.get_bundle_by_id(bundle_id)
        target_kind, target_label = 'Bundle', target.name if target else None
    else:
        target = RuleModel.get_rule(rule_id)
        target_kind, target_label = 'Rule', target.title if target else None

    if not target:
        log_job(job, f'{target_kind} not found (deleted?).', level='error', event='done')
        job.status = 'failed'
        job.error  = f'{target_kind} not found.'
        db.session.commit()
        return

    log_job(job, f"Building MISP {push_type} for '{target_label}'…", level='info', event='started')
    try:
        if bundle_id:
            event = get_bundle_misp_event_object(bundle_id)
        else:
            event = (get_rule_misp_event_object(rule_id) if push_type == 'event'
                     else get_rule_misp_object_base(rule_id))
        if event is None or not event.objects:
            raise ValueError(f'Could not build a MISP {push_type} for this {target_kind.lower()}.')
    except Exception as e:
        log_job(job, f"MISP {push_type} generation failed: {e}", level='error', event='done')
        job.status = 'failed'
        job.error  = str(e)
        db.session.commit()
        return

    log_job(job, f"Pushing to '{server.name}'…", level='info', event='progress')
    ok, msg = MispModel.push_to_misp(server, event)

    job.done   = 1
    job.total  = 1
    job.status = 'done' if ok else 'failed'
    if not ok:
        job.error = msg
    db.session.commit()

    log_job(job, msg, level='success' if ok else 'error', event='done')
    extra = {'push_type': push_type, 'success': ok}
    if bundle_id:
        extra.update({'bundle_id': target.id, 'bundle_uuid': target.uuid, 'bundle_title': target.name})
    else:
        extra.update({'rule_id': target.id, 'rule_uuid': target.uuid, 'rule_title': target.title})
    extra.update({'job_id': job.id, 'job_uuid': job.uuid})
    log_activity('misp.push_done', f"Push to '{server.name}': {msg}",
                 target_type='misp_server', target_id=server.id, target_uuid=server.uuid,
                 actor_id=job.created_by,
                 extra=extra)


# ─────────────────────────────────────────────────────────────────────────────
# db_backup — run backup/scripts/backup_rulezet.sh as a background job with
# live logs, so an admin can take a fresh backup right before testing a risky
# bulk operation (e.g. platform tagging) without leaving the admin page.
# ─────────────────────────────────────────────────────────────────────────────

BACKUP_SCRIPT_TIMEOUT = 600  # 10 minutes — pg_dump on a very large DB could be slow


@register_handler('db_backup')
def handle_db_backup(job, app):
    script_path = os.path.join(os.getcwd(), 'backup', 'scripts', 'backup_rulezet.sh')
    if not os.path.exists(script_path):
        log_job(job, f'Backup script not found: {script_path}', level='error', event='error')
        job.status = 'failed'
        job.error  = 'Backup script not found'
        db.session.commit()
        return

    job.total = 1
    job.done  = 0
    db.session.commit()
    log_job(job, f'Running {script_path} …', level='info', event='start')

    try:
        proc = subprocess.run(
            ['bash', script_path],
            capture_output=True, text=True, timeout=BACKUP_SCRIPT_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        log_job(job, f'Backup timed out after {BACKUP_SCRIPT_TIMEOUT}s.', level='error', event='error')
        job.status = 'failed'
        job.error  = 'Timed out'
        db.session.commit()
        return
    except Exception as e:
        log_job(job, f'Failed to run backup script: {e}', level='error', event='error')
        job.status = 'failed'
        job.error  = str(e)
        db.session.commit()
        return

    for line in (proc.stdout or '').splitlines():
        if line.strip():
            log_job(job, line.strip(), level='info', event='output')

    if proc.returncode != 0:
        for line in (proc.stderr or '').splitlines():
            if line.strip():
                log_job(job, line.strip(), level='error', event='output')
        log_job(job, f'Backup script exited with code {proc.returncode}.', level='error', event='error')
        job.status = 'failed'
        job.error  = f'Exit code {proc.returncode}'
        db.session.commit()
        return

    job.done = 1
    db.session.commit()
    log_job(job, 'Backup complete — see /admin/get_backups to download it.', level='success', event='done')


# ─── rule_validation_run ───────────────────────────────────────────────────────

RULE_VALIDATION_MIRROR_DIR = ROOT_DIR / 'data' / 'rulezet_validation'


@register_handler('rule_validation_run')
def handle_rule_validation_run(job, app):
    """
    Run rulezet-validation's sync+gate pipeline against this instance:
    pull the rules from `INSTANCE_PUBLIC_URL` (or rulezet.org), scan them
    against a local known-clean binary baseline, and quarantine any rule
    that fires — a false-positive risk.

    rulezet-validation is imported as a library rather than shelled out to:
    `sync()` already accepts a `log=` callable (its own extension point for
    exactly this), so plugging in log_job() gives structured, granular
    progress instead of scraping CLI stdout.

    Payload:
        full  : bool — ignore the last-sync date, re-check every rule
        limit : int  — trial run, stop after N rules fetched
    """
    from app.features.rule.rule_core import _active
    from rulezet_validation import config as rv_config
    from rulezet_validation.sync import sync as rv_sync

    payload = job.payload or {}
    full    = bool(payload.get('full', False))
    limit   = payload.get('limit') or None

    settings = rv_config.load()
    settings['mirror_dir'] = str(RULE_VALIDATION_MIRROR_DIR)
    settings['url'] = os.environ.get('INSTANCE_PUBLIC_URL') or settings['url']
    paths = rv_config.paths(settings)

    job.total = 1
    job.done  = 0
    db.session.commit()

    log_job(job,
            f"Validating rules from {settings['url']} against "
            f"{len(settings.get('baseline_dirs', []))} baseline dir(s)"
            f"{' (full re-sync)' if full else ''}"
            f"{f', limit={limit}' if limit else ''} …",
            level='info', event='started')

    try:
        rv_sync(settings, paths, full=full, limit=limit,
                log=lambda msg: log_job(job, msg, level='info', event='progress'))
    except Exception as e:
        log_job(job, f'Validation run failed: {e}', level='error', event='error')
        job.status = 'failed'
        job.error  = str(e)
        db.session.commit()
        return

    # ── Read the merged quarantine.json and match against local rules ─────────
    # Read defensively (.get everywhere) — this file is owned by
    # rulezet-validation, and its schema is free to grow keys over time.
    try:
        doc     = json.loads(paths['quarantine_json'].read_text())
        entries = doc.get('quarantined') or {}
    except (OSError, ValueError):
        entries = {}

    quarantined_uuids = [u for u, e in entries.items() if e.get('status') == 'quarantined']

    quarantined = []
    if quarantined_uuids:
        rules_by_uuid = {
            r.uuid: r for r in _active().filter(Rule.uuid.in_(quarantined_uuids)).all()
        }
        for u in quarantined_uuids:
            e    = entries[u]
            rule = rules_by_uuid.get(u)
            quarantined.append({
                'uuid':       u,
                'rule_id':    rule.id if rule else None,
                'title':      rule.title if rule else e.get('rule', u),
                'hits':       e.get('hits', 0),
                'first_seen': e.get('first_seen'),
            })

    p = dict(job.payload or {})
    p['result'] = {'quarantined': quarantined, 'quarantined_count': len(quarantined)}
    job.payload = p
    job.done    = 1
    db.session.commit()

    log_job(job, f'Done — {len(quarantined)} rule(s) currently quarantined.',
            level='success', event='done')
