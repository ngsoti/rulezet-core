"""
notification_core.py
Business logic for the notification system.

Public surface:
  create_notification(user_id, notif_type, title, body, link, icon, ...)
  create_job_notification(job, user_id)       — creator + all admins
  update_job_notification(job)                — updates ALL matching notifs (creator + admins)
  notify_similarity_done(user_id, ...)        — creator done notif for similarity
  notify_followers_new_rule(rule, author_user_id)
  notify_rule_update_found(user_id, count, update_result_id)
  notify_github_import_done(user_id, imported, skipped, bad_rules, result_uuid)
  notify_github_update_done(user_id, updated, found, result_id)

  get_notifications(user_id, page, per_page, unread_only)
  get_unread_count(user_id)
  get_bell_items(user_id)   — recent unread + active job notifs for dropdown

  mark_read(notif_id, user_id)
  mark_all_read(user_id)
  delete_notification(notif_id, user_id)

  follow_user(follower_id, followed_id)
  unfollow_user(follower_id, followed_id)
  is_following(follower_id, followed_id)
  get_following(user_id)
  get_followers(user_id)
"""

import datetime

from app import db
from app.core.db_class.db import Notification, UserFollow, BackgroundJob, NotificationPreference

# ── Icons per notification type ────────────────────────────────────────────────

_TYPE_ICON = {
    'new_rule':                'fa-solid fa-shield-halved',
    'follow_new_bundle':       'fa-solid fa-layer-group',
    'follow_new_comment':      'fa-solid fa-comment',
    'rule_comment':            'fa-solid fa-comment-dots',
    'bundle_comment':          'fa-solid fa-comment-dots',
    'rule_update_found':       'fa-solid fa-rotate',
    'job_created':             'fa-solid fa-clock',
    'job_finished':            'fa-solid fa-circle-check',
    'job_failed':              'fa-solid fa-circle-xmark',
    'github_import_done':      'fa-brands fa-github',
    'github_update_done':      'fa-solid fa-code-branch',
    'proposal_submitted':      'fa-solid fa-code-pull-request',
    'proposal_comment':        'fa-solid fa-message-lines',
    'proposal_accepted':       'fa-solid fa-circle-check',
    'proposal_rejected':       'fa-solid fa-circle-xmark',
    'comment_reply':           'fa-solid fa-reply',
    'session_running':         'fa-solid fa-spinner',
    'session_done':            'fa-solid fa-circle-check',
    'report_submitted':        'fa-solid fa-triangle-exclamation',
    'ownership_requested':     'fa-solid fa-user-pen',
    'ownership_approved':      'fa-solid fa-user-check',
    'ownership_rejected':      'fa-solid fa-user-xmark',
    'blog_published':          'fa-solid fa-newspaper',
    'github_token_invalid':    'fa-solid fa-key',
    'sync_run_finished':       'fa-solid fa-arrows-rotate',
    'github_proposal_submitted':   'fa-brands fa-github',
    'github_proposal_approved':    'fa-solid fa-circle-check',
    'github_proposal_rejected':    'fa-solid fa-circle-xmark',
    'github_proposal_import_done': 'fa-brands fa-github',
    'role_granted':             'fa-solid fa-user-shield',
    'role_removed':             'fa-solid fa-user-slash',
}


# ── Preference helpers ─────────────────────────────────────────────────────────

def _get_pref(user_id):
    """Return the NotificationPreference for user_id, creating it if absent."""
    pref = NotificationPreference.query.filter_by(user_id=user_id).first()
    if not pref:
        pref = NotificationPreference(user_id=user_id)
        db.session.add(pref)
        db.session.flush()
    return pref


def get_preference(user_id):
    """Public: return preference, committing if newly created."""
    try:
        pref = NotificationPreference.query.filter_by(user_id=user_id).first()
        if not pref:
            pref = NotificationPreference(user_id=user_id)
            db.session.add(pref)
            db.session.commit()
        return pref
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] get_preference error: {e}")
        return NotificationPreference(user_id=user_id)


def update_preference(user_id, prefs_dict):
    """Update preference toggles. prefs_dict: {key: bool} where key matches to_json() keys."""
    try:
        pref = _get_pref(user_id)
        for key, val in prefs_dict.items():
            attr = f'pref_{key}'
            if hasattr(pref, attr):
                setattr(pref, attr, bool(val))
        db.session.commit()
        return pref
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] update_preference error: {e}")
        return None


# ── Admin helpers ──────────────────────────────────────────────────────────────

def _get_all_admin_ids():
    """Return IDs of all admin users."""
    from app.core.db_class.db import User
    return [u.id for u in User.query.filter_by(admin=True).all()]


# ── Core create / update ───────────────────────────────────────────────────────

def create_notification(user_id, notif_type, title, body=None, link=None,
                        icon=None, job_uuid=None, job_status=None, job_progress=None):
    """Insert one Notification row and return it (or None on failure)."""
    try:
        notif = Notification(
            user_id      = user_id,
            notif_type   = notif_type,
            title        = title,
            body         = body,
            link         = link,
            icon         = icon or _TYPE_ICON.get(notif_type),
            job_uuid     = job_uuid,
            job_status   = job_status,
            job_progress = job_progress,
            is_read      = False,
            created_at   = datetime.datetime.utcnow(),
        )
        db.session.add(notif)
        db.session.commit()
        return notif
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] create_notification error: {e}")
        return None


def create_job_notification(job, user_id):
    """Create a job_created notification for the job owner and all admins —
    covers every BackgroundJob type (bulk actions, connector pulls, Sync
    Schedule runs, ...). Respects pref_background_jobs per recipient so a
    user who doesn't want to hear about every job launch can turn it off
    entirely, independent of pref_job_done (which is specifically about
    GitHub import/update session completions)."""
    # Notify the job creator
    if _get_pref(user_id).pref_background_jobs:
        create_notification(
            user_id      = user_id,
            notif_type   = 'job_created',
            title        = f'Job started: {job.label or job.job_type}',
            body         = 'Your background job has been queued.',
            link         = '/jobs/list',
            icon         = 'fa-solid fa-clock',
            job_uuid     = job.uuid,
            job_status   = 'pending',
            job_progress = 0,
        )
    # Also notify all admins (skip creator to avoid duplicate)
    try:
        admin_ids = [uid for uid in _get_all_admin_ids() if uid != user_id]
        notifs = []
        for uid in admin_ids:
            if not _get_pref(uid).pref_background_jobs:
                continue
            notifs.append(Notification(
                user_id      = uid,
                notif_type   = 'job_created',
                title        = f'Job started: {job.label or job.job_type}',
                body         = f'Queued by user #{user_id}',
                link         = '/jobs/list',
                icon         = 'fa-solid fa-clock',
                job_uuid     = job.uuid,
                job_status   = 'pending',
                job_progress = 0,
                is_read      = False,
                created_at   = datetime.datetime.utcnow(),
            ))
        if notifs:
            db.session.add_all(notifs)
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] create_job_notification (admins) error: {e}")


def update_job_notification(job):
    """
    Called when a job reaches a terminal state (done / failed / cancelled).
    Updates ALL matching notifications (creator + any admins) so the bell shows
    the final result without creating duplicate rows.
    """
    try:
        notifs = Notification.query.filter_by(job_uuid=job.uuid).all()
        if not notifs:
            return

        final_type = 'job_finished' if job.status == 'done' else 'job_failed'
        progress   = 100 if job.status == 'done' else (job.progress_pct or 0)
        title      = f'Job finished: {job.label or job.job_type}'
        body       = (f'Completed — {progress}%'
                      if job.status == 'done'
                      else f'Failed: {job.error or "unknown error"}')

        for notif in notifs:
            notif.notif_type    = final_type
            notif.title         = title
            notif.body          = body
            notif.icon          = _TYPE_ICON.get(final_type)
            notif.job_status    = job.status
            notif.job_progress  = progress
            notif.is_read       = False   # resurface in the bell as done
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] update_job_notification error: {e}")


def notify_similarity_done(user_id, session_uuid, total, pairs_found):
    """Notify the user who triggered a similarity analysis that it finished."""
    return create_notification(
        user_id    = user_id,
        notif_type = 'session_done',
        title      = 'Similarity analysis finished',
        body       = f'{total} rules processed · {pairs_found} similar pairs found',
        link       = f'/rule/similar_loading/{session_uuid}',
        icon       = 'fa-solid fa-code-compare',
    )


def notify_proposal_submitted(proposal, rule):
    """
    Notify the rule owner + all admins when a new edit proposal is submitted.
    Skips the submitter (they don't need to notify themselves).
    """
    try:
        from app.core.db_class.db import User
        submitter = User.query.get(proposal.user_id)
        submitter_name = submitter.get_username() if submitter else 'Someone'

        recipients = set(_get_all_admin_ids())
        if rule.user_id:
            recipients.add(rule.user_id)
        recipients.discard(proposal.user_id)  # don't notify the submitter

        if not recipients:
            return

        notifs = []
        for uid in recipients:
            notifs.append(Notification(
                user_id    = uid,
                notif_type = 'proposal_submitted',
                title      = f'New proposal on "{rule.title}"',
                body       = f'{submitter_name} suggested an edit — review it now.',
                link       = f'/rule/proposal_content_discuss?id={proposal.id}',
                icon       = _TYPE_ICON['proposal_submitted'],
                is_read    = False,
                created_at = datetime.datetime.utcnow(),
            ))
        db.session.add_all(notifs)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] notify_proposal_submitted error: {e}")


def notify_admins_report_created(report, rule, reporter):
    """
    Notify all admins when a new rule report is submitted (first report only,
    de-duplicated at the callsite with is_new=True).
    """
    try:
        admin_ids = _get_all_admin_ids()
        if not admin_ids:
            return

        reporter_name = reporter.get_username() if reporter else 'Someone'
        rule_title = rule.title if rule else f'rule #{report.rule_id}'

        notifs = []
        for uid in admin_ids:
            notifs.append(Notification(
                user_id    = uid,
                notif_type = 'report_submitted',
                title      = f'Rule reported: "{rule_title}"',
                body       = f'{reporter_name} submitted a report — reason: {report.reason or "unspecified"}',
                link       = '/report/admin',
                icon       = _TYPE_ICON['report_submitted'],
                is_read    = False,
                created_at = datetime.datetime.utcnow(),
            ))
        db.session.add_all(notifs)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] notify_admins_report_created error: {e}")


def notify_admins_github_token_invalid(reason=None):
    """
    Alert all admins that GITHUB_TOKEN was rejected by the GitHub API, so
    GitHub-backed features (issue filing, branch lookups) are broken until
    someone sets a fresh one in Server Settings.

    De-duplicated: skips if an alert of this type already went out in the
    last 24h, so a burst of failed calls doesn't spam every admin's bell.
    """
    try:
        recent_cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
        already_sent = Notification.query.filter(
            Notification.notif_type == 'github_token_invalid',
            Notification.created_at >= recent_cutoff,
        ).first()
        if already_sent:
            return

        admin_ids = _get_all_admin_ids()
        if not admin_ids:
            return

        notifs = []
        for uid in admin_ids:
            notifs.append(Notification(
                user_id    = uid,
                notif_type = 'github_token_invalid',
                title      = 'GitHub token is invalid or expired',
                body       = reason or ('GITHUB_TOKEN was rejected by the GitHub API. '
                                         'Set a new one in Server Settings to restore GitHub features.'),
                link       = '/admin/settings',
                icon       = _TYPE_ICON['github_token_invalid'],
                is_read    = False,
                created_at = datetime.datetime.utcnow(),
            ))
        db.session.add_all(notifs)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] notify_admins_github_token_invalid error: {e}")


def notify_admins_session_started(user, session_type, session_uuid, label, link):
    """
    Notify all admins (and the triggering user) that a long-running session
    (import / update / similarity) has started.
    The notification stays visible in the bell while job_status='running',
    which keeps the bell polling so the completion toast always fires.
    """
    try:
        admin_ids = set(_get_all_admin_ids())
        # Always include the triggering user so their bell keeps polling
        # even if they are not an admin — this is the key invariant that
        # allows update_admin_session_notifications() to later fire a toast
        # for the session owner regardless of their role.
        if user and getattr(user, 'id', None):
            admin_ids.add(user.id)
        if not admin_ids:
            return

        _icons = {
            'github_import': 'fa-brands fa-github',
            'github_update': 'fa-solid fa-code-branch',
            'similarity':    'fa-solid fa-code-compare',
        }
        icon = _icons.get(session_type, _TYPE_ICON['session_running'])
        username = user.get_username() if user else 'Someone'

        notifs = []
        for uid in admin_ids:
            notifs.append(Notification(
                user_id      = uid,
                notif_type   = 'session_running',
                title        = label,
                body         = f'Started by {username}',
                link         = link,
                icon         = icon,
                job_uuid     = session_uuid,
                job_status   = 'running',
                job_progress = 0,
                is_read      = False,
                created_at   = datetime.datetime.utcnow(),
            ))
        db.session.add_all(notifs)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] notify_admins_session_started error: {e}")


def update_admin_session_notifications(session_uuid, summary, link=None):
    """
    Called when a session finishes. Finds all session_running notifications
    for this session UUID and marks them done with the final summary.
    Pass `link` to redirect the user to the specific results page.
    """
    try:
        notifs = Notification.query.filter_by(job_uuid=session_uuid, notif_type='session_running').all()
        for n in notifs:
            n.notif_type   = 'session_done'
            n.title        = n.title.replace(' running', ' done').replace('Running', 'Done')
            n.body         = summary
            n.job_status   = 'done'
            n.job_progress = 100
            n.is_read      = False   # resurface in the bell as "done"
            n.icon         = _TYPE_ICON['session_done']
            if link:
                n.link = link
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] update_admin_session_notifications error: {e}")


def notify_admins_sync_run_finished(run):
    """Notify every admin (honouring pref_sync_run_finished) that a
    recurring GitHub Sync Schedule run has finished. `run` is a
    GithubSyncRun row with its repo_results already populated."""
    try:
        admin_ids = _get_all_admin_ids()
        if not admin_ids:
            return

        schedule = run.schedule
        repo_count = len(run.repo_results)
        error_count = sum(1 for r in run.repo_results if r.status == 'error')
        added_total = sum(r.auto_added for r in run.repo_results)
        accepted_total = sum(r.auto_accepted for r in run.repo_results)

        body_parts = [f"{repo_count} repo{'s' if repo_count != 1 else ''} checked"]
        if accepted_total:
            body_parts.append(f"{accepted_total} update{'s' if accepted_total != 1 else ''} auto-accepted")
        if added_total:
            body_parts.append(f"{added_total} new rule{'s' if added_total != 1 else ''} auto-added")
        if error_count:
            body_parts.append(f"{error_count} error{'s' if error_count != 1 else ''}")

        notifs = []
        for uid in admin_ids:
            pref = _get_pref(uid)
            if not pref.pref_sync_run_finished:
                continue
            notifs.append(Notification(
                user_id    = uid,
                notif_type = 'sync_run_finished',
                title      = f"{schedule.title} launched an update",
                body       = ' · '.join(body_parts),
                link       = f'/rule/github/sync_run/{run.uuid}',
                icon       = _TYPE_ICON['sync_run_finished'],
                is_read    = False,
                created_at = datetime.datetime.utcnow(),
            ))
        if notifs:
            db.session.add_all(notifs)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] notify_admins_sync_run_finished error: {e}")


def notify_followers_new_rule(rule, author_user_id):
    """Notify every follower of author_user_id that a new rule was created."""
    try:
        follows = UserFollow.query.filter_by(followed_id=author_user_id).all()
        if not follows:
            return

        from app.core.db_class.db import User
        author = User.query.get(author_user_id)
        author_name = author.get_username() if author else 'Someone'

        notifs = []
        for follow in follows:
            pref = _get_pref(follow.follower_id)
            if not pref.pref_follow_new_rule:
                continue
            notifs.append(Notification(
                user_id    = follow.follower_id,
                notif_type = 'new_rule',
                title      = f'New rule by {author_name}',
                body       = rule.title,
                link       = f'/rule/detail_rule/{rule.id}',
                icon       = _TYPE_ICON['new_rule'],
                is_read    = False,
                created_at = datetime.datetime.utcnow(),
            ))
        if notifs:
            db.session.add_all(notifs)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] notify_followers_new_rule error: {e}")


def notify_followers_new_bundle(bundle, author_user_id):
    """Notify followers of author that a new bundle was created (honours pref_follow_new_bundle).
    Private bundles (access=False) are never broadcast to followers — only the owner sees them."""
    if not getattr(bundle, 'access', True):
        return  # private bundle — no follower notifications
    try:
        follows = UserFollow.query.filter_by(followed_id=author_user_id).all()
        if not follows:
            return

        from app.core.db_class.db import User
        author = db.session.get(User, author_user_id)
        author_name = author.get_username() if author else 'Someone'

        notifs = []
        for follow in follows:
            pref = _get_pref(follow.follower_id)
            if not pref.pref_follow_new_bundle:
                continue
            notifs.append(Notification(
                user_id    = follow.follower_id,
                notif_type = 'follow_new_bundle',
                title      = f'New bundle by {author_name}',
                body       = bundle.name,
                link       = f'/bundle/detail/{bundle.id}',
                icon       = _TYPE_ICON['follow_new_bundle'],
                is_read    = False,
                created_at = datetime.datetime.utcnow(),
            ))
        if notifs:
            db.session.add_all(notifs)
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] notify_followers_new_bundle error: {e}")


def notify_followers_new_comment(commenter_id, object_title, link, is_public=True):
    """Notify followers of commenter that they left a new comment (honours pref_follow_new_comment).
    Pass is_public=False for comments on private bundles to skip follower notifications."""
    if not is_public:
        return  # private content — followers should not be notified
    try:
        follows = UserFollow.query.filter_by(followed_id=commenter_id).all()
        if not follows:
            return

        from app.core.db_class.db import User
        commenter = db.session.get(User, commenter_id)
        commenter_name = commenter.get_username() if commenter else 'Someone'

        notifs = []
        for follow in follows:
            if follow.follower_id == commenter_id:
                continue
            pref = _get_pref(follow.follower_id)
            if not pref.pref_follow_new_comment:
                continue
            notifs.append(Notification(
                user_id    = follow.follower_id,
                notif_type = 'follow_new_comment',
                title      = f'{commenter_name} commented',
                body       = object_title,
                link       = link,
                icon       = _TYPE_ICON['follow_new_comment'],
                is_read    = False,
                created_at = datetime.datetime.utcnow(),
            ))
        if notifs:
            db.session.add_all(notifs)
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] notify_followers_new_comment error: {e}")


def notify_owner_new_comment(owner_user_id, commenter_id, notif_type, object_title, link):
    """Notify the owner of a rule/bundle that someone commented on it.

    notif_type: 'rule_comment' or 'bundle_comment'
    Skipped if commenter == owner (no self-notification).
    Honours pref_rule_comment / pref_bundle_comment.
    """
    if owner_user_id == commenter_id:
        return
    try:
        pref = _get_pref(owner_user_id)
        pref_key = 'pref_rule_comment' if notif_type == 'rule_comment' else 'pref_bundle_comment'
        if not getattr(pref, pref_key, True):
            return

        from app.core.db_class.db import User
        commenter = db.session.get(User, commenter_id)
        commenter_name = commenter.get_username() if commenter else 'Someone'

        create_notification(
            user_id    = owner_user_id,
            notif_type = notif_type,
            title      = f'{commenter_name} commented on your {"rule" if notif_type == "rule_comment" else "bundle"}',
            body       = object_title,
            link       = link,
        )
    except Exception as e:
        print(f"[notification_core] notify_owner_new_comment error: {e}")


def notify_proposal_comment(proposal_id, proposal_owner_id, commenter_id, rule_title, comment_id=None):
    """Notify the proposal creator when someone comments on their proposal (honours pref_proposal_comment)."""
    if proposal_owner_id == commenter_id:
        return
    try:
        pref = _get_pref(proposal_owner_id)
        if not pref.pref_proposal_comment:
            return

        from app.core.db_class.db import User
        commenter = db.session.get(User, commenter_id)
        commenter_name = commenter.get_username() if commenter else 'Someone'

        link = f'/rule/proposal_content_discuss?id={proposal_id}'
        if comment_id:
            link += f'&comment={comment_id}'

        create_notification(
            user_id    = proposal_owner_id,
            notif_type = 'proposal_comment',
            title      = f'{commenter_name} commented on your proposal',
            body       = rule_title or '',
            link       = link,
        )
    except Exception as e:
        print(f"[notification_core] notify_proposal_comment error: {e}")


def notify_proposal_status_change(proposal, status, rule_title):
    """Notify the proposal author when their proposal is accepted or rejected (honours pref_proposal_accepted)."""
    try:
        pref = _get_pref(proposal.user_id)
        if not pref.pref_proposal_accepted:
            return

        notif_type = 'proposal_accepted' if status == 'accepted' else 'proposal_rejected'
        verb = 'accepted' if status == 'accepted' else 'rejected'
        create_notification(
            user_id    = proposal.user_id,
            notif_type = notif_type,
            title      = f'Your proposal was {verb}',
            body       = rule_title or '',
            link       = f'/rule/proposal_content_discuss?id={proposal.id}',
        )
    except Exception as e:
        print(f"[notification_core] notify_proposal_status_change error: {e}")


def notify_comment_reply(parent_comment_author_id, replier_id, object_title, link):
    """Notify the author of the parent comment when someone replies (honours pref_comment_reply)."""
    if parent_comment_author_id == replier_id:
        return
    try:
        pref = _get_pref(parent_comment_author_id)
        if not pref.pref_comment_reply:
            return

        from app.core.db_class.db import User
        replier = db.session.get(User, replier_id)
        replier_name = replier.get_username() if replier else 'Someone'

        create_notification(
            user_id    = parent_comment_author_id,
            notif_type = 'comment_reply',
            title      = f'{replier_name} replied to your comment',
            body       = object_title or '',
            link       = link,
        )
    except Exception as e:
        print(f"[notification_core] notify_comment_reply error: {e}")


def notify_ownership_requested(ownership_request, rule, requester):
    """
    Notify all admins (and the current rule owner if different from requester)
    when a user submits an ownership claim for a rule or source.
    """
    try:
        requester_name = requester.get_username() if requester else 'Someone'
        recipients = set(_get_all_admin_ids())
        # Also notify current rule owner if it's a single-rule request
        if rule and rule.user_id and rule.user_id != requester.id:
            recipients.add(rule.user_id)

        if not recipients:
            return

        if rule:
            title = f'Ownership claim on "{rule.title}"'
            body  = f'{requester_name} is claiming ownership of this rule.'
            link  = f'/requests/{ownership_request.id}'
        else:
            title = f'Ownership claim on source rules'
            body  = f'{requester_name} is claiming ownership of rules from a GitHub source.'
            link  = f'/requests/{ownership_request.id}'

        notifs = [
            Notification(
                user_id    = uid,
                notif_type = 'ownership_requested',
                title      = title,
                body       = body,
                link       = link,
                icon       = _TYPE_ICON['ownership_requested'],
                is_read    = False,
                created_at = datetime.datetime.utcnow(),
            )
            for uid in recipients
        ]
        db.session.add_all(notifs)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] notify_ownership_requested error: {e}")


def notify_ownership_decision(ownership_request, approved, rule_title=None):
    """
    Notify the requester when their ownership claim is approved or rejected.
    """
    try:
        notif_type = 'ownership_approved' if approved else 'ownership_rejected'
        verb       = 'approved' if approved else 'rejected'
        title      = f'Ownership claim {verb}'
        body       = f'Your claim on "{rule_title}"' if rule_title else f'Your ownership claim has been {verb}.'
        link       = f'/requests/{ownership_request.id}'

        create_notification(
            user_id    = ownership_request.user_id,
            notif_type = notif_type,
            title      = title,
            body       = body,
            link       = link,
        )
    except Exception as e:
        print(f"[notification_core] notify_ownership_decision error: {e}")


def notify_ownership_granted(new_owner_id, rule_count):
    """
    Notify a user that an admin manually granted them ownership of some
    rules — the manual/bulk counterpart to notify_ownership_decision, which
    only fires for the formal claim-a-rule request flow.
    """
    try:
        create_notification(
            user_id    = new_owner_id,
            notif_type = 'ownership_approved',
            title      = 'You were granted rule ownership',
            body       = f'An admin made you the owner of {rule_count} rule(s).',
            link       = '/rule/owner_rules',
        )
    except Exception as e:
        print(f"[notification_core] notify_ownership_granted error: {e}")


def notify_role_assignment(user_id, role_name, granted):
    """Notify a user when an admin grants or revokes one of their roles
    (Roles & Permissions admin page) — a role can hand out real capabilities
    (e.g. rule.tag_any), so the affected user should know without having to
    stumble onto it."""
    try:
        verb  = 'granted' if granted else 'removed'
        title = f'Role {verb}: {role_name}'
        body  = (f'You were given the "{role_name}" role.' if granted
                 else f'The "{role_name}" role was removed from your account.')
        create_notification(
            user_id    = user_id,
            notif_type = 'role_granted' if granted else 'role_removed',
            title      = title,
            body       = body,
            link       = '/account/',
        )
    except Exception as e:
        print(f"[notification_core] notify_role_assignment error: {e}")


def notify_github_proposal_submitted(proposal, requester):
    """Notify all admins when a non-admin submits a GitHub import proposal."""
    try:
        recipients = set(_get_all_admin_ids())
        if not recipients:
            return
        requester_name = requester.get_username() if requester else 'Someone'
        title = 'New GitHub import proposal'
        body  = f'{requester_name} proposed importing {proposal.repo_url}'
        link  = f'/rule/github_proposal_detail/{proposal.uuid}'

        notifs = [
            Notification(
                user_id    = uid,
                notif_type = 'github_proposal_submitted',
                title      = title,
                body       = body,
                link       = link,
                icon       = _TYPE_ICON['github_proposal_submitted'],
                is_read    = False,
                created_at = datetime.datetime.utcnow(),
            )
            for uid in recipients
        ]
        db.session.add_all(notifs)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] notify_github_proposal_submitted error: {e}")


def notify_github_proposal_decision(proposal, approved, note=None):
    """Notify the requester when their GitHub import proposal is accepted or rejected."""
    try:
        notif_type = 'github_proposal_approved' if approved else 'github_proposal_rejected'
        verb       = 'accepted' if approved else 'rejected'
        title      = f'GitHub proposal {verb}'
        body       = f'Your proposal for {proposal.repo_url} was {verb}.'
        if note:
            body += f' Note: {note}'
        link = f'/rule/github_proposal_detail/{proposal.uuid}'

        create_notification(
            user_id    = proposal.user_id,
            notif_type = notif_type,
            title      = title,
            body       = body,
            link       = link,
        )
    except Exception as e:
        print(f"[notification_core] notify_github_proposal_decision error: {e}")


def notify_github_proposal_import_done(user_id, repo_url, imported, success, error=None):
    """Notification sent once the sequential import for one accepted GitHub
    proposal finishes. Respects pref_job_done (see notify_github_import_done)."""
    try:
        if not _get_pref(user_id).pref_job_done:
            return None
        if success:
            title = f'Import finished — {imported} rule{"s" if imported != 1 else ""} received'
            body  = f'Your proposed repository {repo_url} was imported.'
        else:
            title = 'Import failed'
            body  = f'Importing {repo_url} failed{": " + error if error else "."}'
        return create_notification(
            user_id    = user_id,
            notif_type = 'github_proposal_import_done',
            title      = title,
            body       = body,
            link       = '/rule/github/manage',
            icon       = _TYPE_ICON['github_proposal_import_done'],
        )
    except Exception as e:
        print(f"[notification_core] notify_github_proposal_import_done error: {e}")


def delete_all_notifications(user_id):
    """Hard-delete every notification row for this user."""
    try:
        Notification.query.filter_by(user_id=user_id).delete()
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] delete_all_notifications error: {e}")


def notify_rule_update_found(user_id, count, update_result_id=None):
    """Create a rule_update_found notification for a user."""
    link = '/rule/github/update_github/update_rules_from_github'
    if update_result_id:
        link += f'?result_id={update_result_id}'
    return create_notification(
        user_id    = user_id,
        notif_type = 'rule_update_found',
        title      = f'{count} rule update{"s" if count > 1 else ""} available',
        body       = 'New versions detected for your imported GitHub rules.',
        link       = link,
        icon       = _TYPE_ICON['rule_update_found'],
    )


def notify_github_import_done(user_id, imported, skipped, bad_rules, result_uuid=None):
    """Notification sent when a GitHub / ZIP import session finishes.
    Respects pref_job_done — this is specifically the "GitHub import/update
    finished" preference, distinct from pref_background_jobs (generic
    BackgroundJob started/finished, any job type)."""
    if not _get_pref(user_id).pref_job_done:
        return None
    total = imported + skipped + bad_rules
    link = f'/rule/import_loading/{result_uuid}' if result_uuid else '/rule/github/manage'
    return create_notification(
        user_id    = user_id,
        notif_type = 'github_import_done',
        title      = f'Import finished — {imported} rule{"s" if imported != 1 else ""} imported',
        body       = f'{imported} imported · {skipped} skipped · {bad_rules} invalid (total {total})',
        link       = link,
        icon       = _TYPE_ICON['github_import_done'],
    )


def notify_github_update_done(user_id, updated, found, result_id=None, result_uuid=None):
    """Notification sent when a GitHub update check session finishes.
    Respects pref_job_done (see notify_github_import_done)."""
    if not _get_pref(user_id).pref_job_done:
        return None
    if result_uuid:
        link = f'/rule/update_loading/{result_uuid}'
    elif result_id:
        link = f'/rule/github/update_github/update_rules_from_github?result_id={result_id}'
    else:
        link = '/rule/github/update_github/update_rules_from_github'
    if updated:
        title = f'{updated} rule update{"s" if updated != 1 else ""} available'
    else:
        title = 'Update check finished — rules are up to date'
    return create_notification(
        user_id    = user_id,
        notif_type = 'github_update_done',
        title      = title,
        body       = f'{found} rule{"s" if found != 1 else ""} checked · {updated} update{"s" if updated != 1 else ""} found',
        link       = link,
        icon       = _TYPE_ICON['github_update_done'],
    )


# ── Read / fetch ───────────────────────────────────────────────────────────────

def get_notifications(user_id, page=1, per_page=20, unread_only=False, notif_type=None):
    q = Notification.query.filter_by(user_id=user_id)
    if unread_only:
        q = q.filter_by(is_read=False)
    if notif_type:
        # notif_type may be a single string or a comma-separated list of types
        types = [t.strip() for t in notif_type.split(',') if t.strip()] if isinstance(notif_type, str) else list(notif_type)
        if len(types) == 1:
            q = q.filter(Notification.notif_type == types[0])
        elif len(types) > 1:
            q = q.filter(Notification.notif_type.in_(types))
    return q.order_by(Notification.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)


def get_unread_count(user_id):
    return Notification.query.filter_by(user_id=user_id, is_read=False).count()


def get_bell_items(user_id, limit=15):
    """
    Items to show in the bell dropdown:
      - Unread notifications (all types)
      - Active job notifications (job still running) even if read
    Deduplicated and sorted newest first, capped at `limit`.
    """
    # Unread
    unread = (Notification.query
              .filter_by(user_id=user_id, is_read=False)
              .order_by(Notification.created_at.desc())
              .limit(limit)
              .all())

    # Active BackgroundJobs (running / pending / paused) that may already be read
    active_job_uuids = [
        j.uuid for j in BackgroundJob.query
        .filter(BackgroundJob.status.in_(['pending', 'running', 'paused']))
        .filter_by(created_by=user_id)
        .all()
    ]
    active_job_notifs = []
    if active_job_uuids:
        active_job_notifs = (Notification.query
                             .filter(Notification.user_id == user_id,
                                     Notification.is_read == True,
                                     Notification.job_uuid.in_(active_job_uuids))
                             .order_by(Notification.created_at.desc())
                             .all())

    # Active thread-based sessions (import/update/similarity) that may already be read
    active_session_notifs = (Notification.query
                             .filter(Notification.user_id == user_id,
                                     Notification.is_read == True,
                                     Notification.notif_type == 'session_running',
                                     Notification.job_status.in_(['running', 'pending']))
                             .order_by(Notification.created_at.desc())
                             .all())

    # Merge, deduplicate by id
    seen = set()
    merged = []
    for n in (unread + active_job_notifs + active_session_notifs):
        if n.id not in seen:
            seen.add(n.id)
            merged.append(n)

    merged.sort(key=lambda n: n.created_at, reverse=True)
    return merged[:limit]


# ── Mutations ──────────────────────────────────────────────────────────────────

def mark_read(notif_id, user_id):
    notif = Notification.query.filter_by(id=notif_id, user_id=user_id).first()
    if not notif:
        return False
    try:
        notif.is_read = True
        notif.read_at = datetime.datetime.utcnow()
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] mark_read error: {e}")
        return False


def mark_all_read(user_id):
    try:
        Notification.query.filter_by(user_id=user_id, is_read=False).update({
            'is_read': True,
            'read_at': datetime.datetime.utcnow(),
        })
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] mark_all_read error: {e}")
        return False


def delete_notification(notif_id, user_id):
    notif = Notification.query.filter_by(id=notif_id, user_id=user_id).first()
    if not notif:
        return False
    try:
        db.session.delete(notif)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] delete_notification error: {e}")
        return False


# ── Follow / Unfollow ──────────────────────────────────────────────────────────

def follow_user(follower_id, followed_id):
    if follower_id == followed_id:
        return False, 'Cannot follow yourself'
    existing = UserFollow.query.filter_by(follower_id=follower_id, followed_id=followed_id).first()
    if existing:
        return True, 'Already following'
    try:
        db.session.add(UserFollow(follower_id=follower_id, followed_id=followed_id))
        db.session.commit()
        return True, 'Following'
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] follow_user error: {e}")
        return False, str(e)


def unfollow_user(follower_id, followed_id):
    follow = UserFollow.query.filter_by(follower_id=follower_id, followed_id=followed_id).first()
    if not follow:
        return True, 'Not following'
    try:
        db.session.delete(follow)
        db.session.commit()
        return True, 'Unfollowed'
    except Exception as e:
        db.session.rollback()
        print(f"[notification_core] unfollow_user error: {e}")
        return False, str(e)


def is_following(follower_id, followed_id):
    return UserFollow.query.filter_by(follower_id=follower_id, followed_id=followed_id).first() is not None


def get_following(user_id):
    follows = UserFollow.query.filter_by(follower_id=user_id).all()
    return [f.followed_id for f in follows]


def get_followers(user_id):
    follows = UserFollow.query.filter_by(followed_id=user_id).all()
    return [f.follower_id for f in follows]


def get_follower_count(user_id):
    return UserFollow.query.filter_by(followed_id=user_id).count()


def get_following_count(user_id):
    return UserFollow.query.filter_by(follower_id=user_id).count()


def notify_blog_published(post):
    """Notify all authenticated users (except the author) when a blog post is published.
    Respects pref_blog_published (default True). Only fires when post becomes
    is_draft=False AND is_public=True for the first time.

    Guards on post.is_public/is_draft itself (not just the caller's transition
    check) so a private or draft post can never trigger notifications even if
    a future call site forgets to gate on that first.
    """
    if not post.is_public or post.is_draft:
        return
    from app.core.db_class.db import User
    try:
        users = User.query.filter(User.id != post.user_id).all()
        link = f'/blog/post/{post.uuid}'
        for user in users:
            pref = _get_pref(user.id)
            if not pref.pref_blog_published:
                continue
            create_notification(
                user_id=user.id,
                notif_type='blog_published',
                title='New blog post published',
                body=post.title[:120],
                link=link,
            )
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f'[notification_core] notify_blog_published error: {e}')
