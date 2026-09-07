"""
proposal_core.py — DB logic for non-admin GitHub import proposals.

Non-admins propose a repo (url/branch/license/markdown message) instead of
importing it directly. Admins review proposals in bulk (accept/reject);
accepting dispatches ONE 'github_proposal_bulk_import' background job that
imports every accepted repo sequentially (see job_handlers.py).
"""

import datetime

from sqlalchemy import or_

from app import db
from app.core.db_class.db import GithubProposal, Rule, User
from app.features.jobs import jobs_core
from app.features.rule import rule_core as RuleModel
from app.features.rule.rule_format.utils_format.utils_import_update import valider_repo_github


def _normalize_repo_url(repo_url):
    """GitHub's API returns `html_url` with no ".git" suffix and no trailing
    slash, and that's what ends up stored in Rule.source on import (see
    github_repo_metadata()/extract_github_repo_metadata()) — regardless of
    whether the user typed a ".git"-suffixed clone URL. Strip both so a
    proposal's repo_url reliably matches already-imported rules' source."""
    url = (repo_url or "").strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    return url


def create_proposal(user, repo_url, branch, license, message, is_generic_source=False):
    """Validate and create a GithubProposal.
    Rejects the submission outright (no proposal created) when:
      - the repo is already in Rulezet (has existing rules with that source)
        — the requester should request ownership of those instead, not
        propose a re-import;
      - a pending proposal for the same repo already exists, from this user
        or anyone else — no duplicate proposals for the same repo.

    is_generic_source=True marks this as a non-GitHub git repository (e.g. a
    self-hosted GitLab/Gitea) — skips the github.com hostname check and,
    once accepted, the import job uses generic (API-free) metadata instead
    of calling GitHub's REST API.
    """
    repo_url = _normalize_repo_url(repo_url)
    if not valider_repo_github(repo_url, is_generic_source=is_generic_source):
        return None, "Please enter a valid repository URL."

    branch = (branch or "").strip() or None
    license = (license or "").strip() or None
    message = (message or "").strip() or None

    if count_existing_rules_for_source(repo_url) > 0:
        return None, "This repository is already in Rulezet. Request ownership of its existing rules instead of proposing it again."

    existing_pending = GithubProposal.query.filter_by(repo_url=repo_url, status='pending').first()
    if existing_pending:
        if existing_pending.user_id == user.id:
            return None, "You already have a pending proposal for this repository."
        return None, "This repository has already been proposed and is awaiting admin review."

    proposal = GithubProposal(
        user_id=user.id,
        repo_url=repo_url,
        branch=branch,
        license=license,
        message=message,
        is_generic_source=is_generic_source,
        status='pending',
    )
    db.session.add(proposal)
    db.session.commit()
    return proposal, None


def get_proposal_by_uuid(uuid_):
    return GithubProposal.query.filter_by(uuid=uuid_).first()


def get_proposals_query(filters=None):
    """Base query for the admin review table — status + search filters."""
    filters = filters or {}
    query = GithubProposal.query.join(User, GithubProposal.user_id == User.id)

    status = (filters.get('status') or '').strip()
    if status and status != 'all':
        query = query.filter(GithubProposal.status == status)

    search = (filters.get('search') or '').strip()
    if search:
        like = f"%{search}%"
        query = query.filter(or_(
            GithubProposal.repo_url.ilike(like),
            GithubProposal.message.ilike(like),
            User.first_name.ilike(like),
            User.last_name.ilike(like),
        ))

    sort_by = filters.get('sort_by') or 'created_at'
    direction = filters.get('sort_dir') or 'desc'
    sort_col = {
        'created_at': GithubProposal.created_at,
        'repo_url': GithubProposal.repo_url,
        'status': GithubProposal.status,
    }.get(sort_by, GithubProposal.created_at)
    query = query.order_by(sort_col.asc() if direction == 'asc' else sort_col.desc())

    return query


def get_user_proposals_query(user_id):
    """A user's own still-pending proposals, most recent first — for 'Mes
    propositions'. Once a proposal is decided (accepted/rejected/imported/
    failed/transferred) it drops out of this list — the user is notified of
    the outcome instead, this view is only for "still awaiting a decision"."""
    return GithubProposal.query.filter_by(user_id=user_id, status='pending').order_by(GithubProposal.created_at.desc())


def count_existing_rules_for_source(repo_url):
    """How many active (non-deleted) rules already have this GitHub repo as source."""
    return RuleModel._active().filter(Rule.source.ilike(f"%{_normalize_repo_url(repo_url)}%")).count()


def decide_proposals(uuids, decision, admin_user, ownership_mode=None, note=None):
    """Bulk accept/reject a set of pending proposals.

    On accept, every proposal is batched into ONE 'github_proposal_bulk_import'
    job — same exact import mechanism a direct "Add rule from GitHub" import
    uses (Session_class), regardless of whether the repo already has rules in
    Rulezet. That handler (job_handlers.py) runs the import first (so any
    rule added upstream since the last import is picked up), then — if the
    repo already had existing rules under a different owner — hands those
    over via a 'bulk_transfer_ownership' job, as a second step rather than an
    alternative to importing.
    On reject: just notifies each requester, no job.
    """
    from app.features.notification.notification_core import notify_github_proposal_decision

    proposals = GithubProposal.query.filter(
        GithubProposal.uuid.in_(uuids), GithubProposal.status == 'pending'
    ).all()
    if not proposals:
        return [], None, "No pending proposal matched the given ids."

    now = datetime.datetime.utcnow()
    job = None

    if decision == 'accept':
        if ownership_mode not in ('requester', 'admin'):
            return [], None, "ownership_mode must be 'requester' or 'admin'."

        for p in proposals:
            p.ownership_mode = ownership_mode
            p.decided_by_id = admin_user.id
            p.decided_at = now
            p.decision_note = note
            p.status = 'accepted'
        db.session.commit()

        job = jobs_core.create_job(
            job_type='github_proposal_bulk_import',
            payload={
                'proposal_uuids': [p.uuid for p in proposals],
                'ownership_mode': ownership_mode,
            },
            label=f"Import {len(proposals)} accepted GitHub proposal(s)",
            created_by=admin_user.id,
            total=len(proposals),
        )
        if job:
            for p in proposals:
                p.job_uuid = job.uuid
            db.session.commit()

        for p in proposals:
            try:
                notify_github_proposal_decision(p, approved=True)
            except Exception as e:
                print(f"[proposal_core] notify decision (accept) error: {e}")

    elif decision == 'reject':
        for p in proposals:
            p.status = 'rejected'
            p.decided_by_id = admin_user.id
            p.decided_at = now
            p.decision_note = note
        db.session.commit()

        for p in proposals:
            try:
                notify_github_proposal_decision(p, approved=False, note=note)
            except Exception as e:
                print(f"[proposal_core] notify decision (reject) error: {e}")
    else:
        return [], None, "decision must be 'accept' or 'reject'."

    return proposals, job, None


def delete_proposal(proposal):
    db.session.delete(proposal)
    db.session.commit()


def cancel_proposal(proposal):
    """Requester withdraws their own still-pending proposal."""
    if proposal.status != 'pending':
        return False, "Only pending proposals can be cancelled."
    db.session.delete(proposal)
    db.session.commit()
    return True, None
