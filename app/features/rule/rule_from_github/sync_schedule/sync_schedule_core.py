"""
sync_schedule_core.py — CRUD + validation for GithubSyncSchedule (recurring
GitHub repo update automation, "Sync Schedules"). Keeps the same registration
of the live APScheduler trigger in lockstep with the DB row on every mutation
so a restart is never needed to pick up a change.
"""
import uuid as _uuid_mod

from flask import current_app

from app import db
from app.core.db_class.db import GithubSyncSchedule, GithubSyncScheduleRepo
from app.features.rule import rule_core as RuleModel
from app.features.rule.rule_format.utils_format.utils_import_update import valider_repo_github

VALID_FREQUENCIES = ('daily', 'weekly', 'monthly', 'cron')


def _validate_recurrence(data):
    freq = data.get('frequency')
    if freq not in VALID_FREQUENCIES:
        return False, f"Invalid frequency: {freq!r}"

    if freq == 'weekly':
        dow = data.get('days_of_week') or []
        if not isinstance(dow, list) or not dow or not all(isinstance(d, int) and 0 <= d <= 6 for d in dow):
            return False, "days_of_week must be a non-empty list of integers 0-6 (0 = Monday)."

    if freq == 'monthly':
        dom = data.get('day_of_month')
        if dom is None or not (dom == -1 or 1 <= dom <= 31):
            return False, "day_of_month must be 1-31, or -1 for the last day of the month."

    if freq == 'cron':
        cron_expr = data.get('cron_expr')
        if not cron_expr:
            return False, "cron_expr is required when frequency is 'cron'."
        try:
            from apscheduler.triggers.cron import CronTrigger
            CronTrigger.from_crontab(cron_expr, timezone=data.get('timezone') or 'UTC')
        except Exception as e:
            return False, f"Invalid cron expression: {e}"

    hour = data.get('hour', 3)
    minute = data.get('minute', 0)
    if not isinstance(hour, int) or not (0 <= hour <= 23):
        return False, "hour must be an integer 0-23."
    if not isinstance(minute, int) or not (0 <= minute <= 59):
        return False, "minute must be an integer 0-59."

    return True, None


def _apply_recurrence_fields(schedule, data):
    schedule.frequency = data.get('frequency')
    schedule.days_of_week = (','.join(str(d) for d in data.get('days_of_week', []))
                              if schedule.frequency == 'weekly' else None)
    schedule.day_of_month = data.get('day_of_month') if schedule.frequency == 'monthly' else None
    schedule.cron_expr = data.get('cron_expr') if schedule.frequency == 'cron' else None
    schedule.hour = data.get('hour', 3)
    schedule.minute = data.get('minute', 0)
    schedule.timezone = data.get('timezone') or 'UTC'


def resolve_repo_urls(repo_mode, repo_filters, selected_repo_urls, excluded_repo_urls):
    """Resolve the final repo URL set server-side — never trust a client-
    supplied full list when repo_mode == 'all'; re-run the same filtered
    query the picker table itself used and subtract what the user
    deliberately deselected."""
    repo_filters = repo_filters or {}
    if repo_mode == 'all':
        all_urls = RuleModel.get_all_github_urls_matching(
            search=repo_filters.get('search'),
            search_field=repo_filters.get('search_field', 'url'),
            format_filter=repo_filters.get('format'),
            author_filter=repo_filters.get('author'),
        )
        excluded = set(excluded_repo_urls or [])
        return [u for u in all_urls if u not in excluded]
    seen = set()
    ordered = []
    for u in (selected_repo_urls or []):
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    return ordered


def _sync_repo_rows(schedule, repo_urls, repo_settings=None, default_settings=None):
    """Replace schedule.repos with repo_urls. `repo_settings` (a list of
    {repo_url, auto_accept_update, auto_add_new_rule}) covers manually-picked
    repos where the client knows the exact URL; `default_settings` (one
    {auto_accept_update, auto_add_new_rule} pair) is the fallback applied
    uniformly when the picker was in 'select all matching filter' mode and
    the client never enumerated the individual URLs."""
    per_repo = {r.get('repo_url'): r for r in (repo_settings or [])}
    default_settings = default_settings or {}
    GithubSyncScheduleRepo.query.filter_by(schedule_id=schedule.id).delete()
    for url in repo_urls:
        cfg = per_repo.get(url, default_settings)
        db.session.add(GithubSyncScheduleRepo(
            schedule_id=schedule.id,
            repo_url=url,
            auto_accept_update=bool(cfg.get('auto_accept_update', False)),
            auto_add_new_rule=bool(cfg.get('auto_add_new_rule', False)),
            is_generic_source=bool(cfg.get('is_generic_source', False)),
        ))


def _register_live(schedule):
    """Keep the in-memory APScheduler trigger in lockstep with the DB row —
    call after every create/update/delete so no restart is needed."""
    from app.features.rule.rule_from_github.sync_schedule.scheduler_engine import register_schedule
    register_schedule(current_app._get_current_object(), schedule)
    db.session.commit()


def get_schedule_list_page(page=1, per_page=20, search='', sort='created_at', direction='desc'):
    per_page = max(1, min(per_page or 20, 100))
    query = GithubSyncSchedule.query
    if search:
        query = query.filter(GithubSyncSchedule.title.ilike(f"%{search}%"))
    sort_col = {
        'title': GithubSyncSchedule.title,
        'next_run_at': GithubSyncSchedule.next_run_at,
        'last_run_at': GithubSyncSchedule.last_run_at,
        'created_at': GithubSyncSchedule.created_at,
    }.get(sort, GithubSyncSchedule.created_at)
    query = query.order_by(sort_col.asc() if direction == 'asc' else sort_col.desc())
    return query.paginate(page=page, per_page=per_page, max_per_page=100)


def create_schedule(data, editor):
    ok, err = _validate_recurrence(data)
    if not ok:
        return None, err

    title = (data.get('title') or '').strip()
    if not title:
        return None, "Title is required."

    repo_urls = resolve_repo_urls(data.get('repo_mode', 'partial'), data.get('repo_filters'),
                                   data.get('selected_repo_urls'), data.get('excluded_repo_urls'))
    generic_map = {r.get('repo_url'): bool(r.get('is_generic_source')) for r in (data.get('repo_settings') or [])}
    valid_repo_urls = [u for u in repo_urls if valider_repo_github(u, is_generic_source=generic_map.get(u, False))]
    if not valid_repo_urls:
        return None, "At least one valid repository must be selected."

    schedule = GithubSyncSchedule(
        uuid=str(_uuid_mod.uuid4()),
        title=title,
        description=data.get('description'),
        editor_id=editor.id,
        is_active=bool(data.get('is_active', True)),
    )
    _apply_recurrence_fields(schedule, data)
    db.session.add(schedule)
    db.session.flush()

    _sync_repo_rows(schedule, valid_repo_urls, data.get('repo_settings'), data.get('default_repo_settings'))
    db.session.commit()

    _register_live(schedule)
    return schedule, None


def update_schedule(schedule_uuid, data):
    schedule = GithubSyncSchedule.query.filter_by(uuid=schedule_uuid).first()
    if not schedule:
        return None, "Schedule not found."

    ok, err = _validate_recurrence(data)
    if not ok:
        return None, err

    title = (data.get('title') or '').strip()
    if not title:
        return None, "Title is required."

    schedule.title = title
    schedule.description = data.get('description')
    schedule.is_active = bool(data.get('is_active', schedule.is_active))
    _apply_recurrence_fields(schedule, data)

    if 'repo_mode' in data or 'selected_repo_urls' in data:
        repo_urls = resolve_repo_urls(data.get('repo_mode', 'partial'), data.get('repo_filters'),
                                       data.get('selected_repo_urls'), data.get('excluded_repo_urls'))
        generic_map = {r.get('repo_url'): bool(r.get('is_generic_source')) for r in (data.get('repo_settings') or [])}
        valid_repo_urls = [u for u in repo_urls if valider_repo_github(u, is_generic_source=generic_map.get(u, False))]
        if not valid_repo_urls:
            return None, "At least one valid repository must be selected."
        _sync_repo_rows(schedule, valid_repo_urls, data.get('repo_settings'), data.get('default_repo_settings'))
    elif 'repo_settings' in data:
        # Only per-repo toggles changed — repo list itself untouched.
        by_url = {r.repo_url: r for r in schedule.repos}
        for cfg in data.get('repo_settings') or []:
            repo = by_url.get(cfg.get('repo_url'))
            if repo:
                repo.auto_accept_update = bool(cfg.get('auto_accept_update', repo.auto_accept_update))
                repo.auto_add_new_rule = bool(cfg.get('auto_add_new_rule', repo.auto_add_new_rule))
                repo.is_generic_source = bool(cfg.get('is_generic_source', repo.is_generic_source))

    db.session.commit()
    _register_live(schedule)
    return schedule, None


def delete_schedule(schedule_uuid):
    from app.features.rule.rule_from_github.sync_schedule.scheduler_engine import unregister_schedule
    schedule = GithubSyncSchedule.query.filter_by(uuid=schedule_uuid).first()
    if not schedule:
        return False
    unregister_schedule(schedule.uuid)
    db.session.delete(schedule)
    db.session.commit()
    return True


def _resolve_bulk_targets(mode, filters, selected_uuids, excluded_uuids):
    """Shared 'select all matching filter, minus excluded' resolution for
    bulk actions on the schedule list — same mode/filters/selected/excluded
    shape as the repo picker (§6 of the plan), never trusting a client-
    supplied full list when mode == 'all'."""
    filters = filters or {}
    query = GithubSyncSchedule.query
    if filters.get('search'):
        query = query.filter(GithubSyncSchedule.title.ilike(f"%{filters['search']}%"))

    if mode == 'all':
        excluded = set(excluded_uuids or [])
        return [s for s in query.all() if s.uuid not in excluded]
    return GithubSyncSchedule.query.filter(
        GithubSyncSchedule.uuid.in_(selected_uuids or [])
    ).all()


def bulk_delete_schedules(mode, filters, selected_uuids, excluded_uuids):
    from app.features.rule.rule_from_github.sync_schedule.scheduler_engine import unregister_schedule
    targets = _resolve_bulk_targets(mode, filters, selected_uuids, excluded_uuids)

    count = 0
    for schedule in targets:
        unregister_schedule(schedule.uuid)
        db.session.delete(schedule)
        count += 1
    db.session.commit()
    return count


def bulk_set_active_schedules(mode, filters, selected_uuids, excluded_uuids, is_active):
    """Bulk activate/deactivate — (de)registers each schedule's live
    APScheduler trigger to match, so the effect is immediate, no restart
    needed (same guarantee as a single-schedule toggle via update_schedule)."""
    targets = _resolve_bulk_targets(mode, filters, selected_uuids, excluded_uuids)

    count = 0
    for schedule in targets:
        schedule.is_active = is_active
        _register_live(schedule)
        count += 1
    db.session.commit()
    return count


def run_schedule_now(schedule_uuid):
    """Manually trigger one run immediately, outside its normal cadence —
    reuses the exact same _fire_schedule the scheduler itself calls, so a
    manual run and a cron-triggered run create identical GithubSyncRun +
    BackgroundJob rows."""
    from app.features.rule.rule_from_github.sync_schedule.scheduler_engine import _fire_schedule
    schedule = GithubSyncSchedule.query.filter_by(uuid=schedule_uuid).first()
    if not schedule:
        return False, "Schedule not found."
    if not schedule.is_active:
        return False, "Schedule is paused — activate it before running it manually."
    if not schedule.repos:
        return False, "Schedule has no repositories configured."
    _fire_schedule(current_app._get_current_object(), schedule.uuid)
    return True, None
