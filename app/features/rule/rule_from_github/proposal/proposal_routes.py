"""
proposal_routes.py — JSON API for non-admin GitHub import proposals.

Permission model (mixed — no blanket admin gate on this blueprint):
    create, mine, cancel   -> any authenticated user, scoped to themselves
    list, bulk_decision, delete -> admin only
    detail (GET /<uuid>)   -> admin OR the requester

Accepting a proposal already resolves the "repo already imported" case
automatically (transfers ownership of the existing rules instead of
re-importing — see decide_proposals/_resolve_existing_source in
proposal_core.py), so there is no separate manual "transfer existing rules"
endpoint: it's just Accept or Reject, same as any other proposal.

All DB logic lives in proposal_core.py; the sequential import itself runs in
the 'github_proposal_bulk_import' BackgroundJob handler (job_handlers.py).
"""
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from app.core.utils.activity_log import log_activity
from app.features.rule.rule_from_github.proposal import proposal_core as ProposalModel

github_proposal_blueprint = Blueprint(
    'github_proposal',
    __name__,
    template_folder='templates',
)


def _admin_only():
    if not current_user.is_admin():
        return jsonify({"message": "Admin access required.", "toast_class": "danger-subtle"}), 403
    return None


@github_proposal_blueprint.route('/create', methods=['POST'])
@login_required
def proposal_create():
    data = request.get_json(silent=True) or {}
    proposal, err = ProposalModel.create_proposal(
        user=current_user,
        repo_url=data.get('repo_url'),
        branch=data.get('branch'),
        license=data.get('license'),
        message=data.get('message'),
    )
    if err:
        return jsonify({"message": err, "toast_class": "danger-subtle"}), 400

    try:
        from app.features.notification.notification_core import notify_github_proposal_submitted
        notify_github_proposal_submitted(proposal, current_user)
    except Exception as e:
        print(f"[proposal_routes] notify_github_proposal_submitted error: {e}")

    log_activity("github_proposal.create",
                 f"Proposed importing GitHub repo '{proposal.repo_url}'",
                 target_type="github_proposal", target_uuid=proposal.uuid,
                 extra={"repo_url": proposal.repo_url, "branch": proposal.branch},
                 icon="fa-brands fa-github")

    return jsonify({
        "message": "Your proposal has been submitted for admin review.",
        "toast_class": "success-subtle",
        "proposal": proposal.to_json(),
    }), 201


@github_proposal_blueprint.route('/list', methods=['GET'])
def proposal_list():
    guard = _admin_only()
    if guard:
        return guard

    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 50)
    filters = {
        "status": request.args.get('status', 'all'),
        "search": request.args.get('search', ''),
        "sort_by": request.args.get('sort_by', 'created_at'),
        "sort_dir": request.args.get('sort_dir', 'desc'),
    }

    pagination = ProposalModel.get_proposals_query(filters).paginate(page=page, per_page=per_page)
    return jsonify({
        "items": [p.to_json() for p in pagination.items],
        "total": pagination.total,
        "total_pages": pagination.pages,
        "current_page": pagination.page,
    }), 200


@github_proposal_blueprint.route('/mine', methods=['GET'])
@login_required
def proposal_mine():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 50)
    pagination = ProposalModel.get_user_proposals_query(current_user.id).paginate(page=page, per_page=per_page)
    return jsonify({
        "items": [p.to_json() for p in pagination.items],
        "total": pagination.total,
        "total_pages": pagination.pages,
        "current_page": pagination.page,
    }), 200


@github_proposal_blueprint.route('/<uuid>', methods=['GET'])
@login_required
def proposal_detail(uuid):
    proposal = ProposalModel.get_proposal_by_uuid(uuid)
    if not proposal:
        return jsonify({"message": "Proposal not found.", "toast_class": "danger-subtle"}), 404
    if current_user.id != proposal.user_id and not current_user.is_admin():
        return jsonify({"message": "Access denied.", "toast_class": "danger-subtle"}), 403

    return jsonify({
        "proposal": proposal.to_json(),
        "existing_rules_count": ProposalModel.count_existing_rules_for_source(proposal.repo_url),
        "is_owner": current_user.id == proposal.user_id,
        "is_admin": current_user.is_admin(),
    }), 200


@github_proposal_blueprint.route('/bulk_decision', methods=['POST'])
def proposal_bulk_decision():
    guard = _admin_only()
    if guard:
        return guard

    data = request.get_json(silent=True) or {}
    uuids = data.get('uuids') or []
    decision = data.get('decision')
    ownership_mode = data.get('ownership_mode')
    note = data.get('note')

    if not uuids or decision not in ('accept', 'reject'):
        return jsonify({"message": "uuids and a valid decision are required.", "toast_class": "danger-subtle"}), 400

    proposals, job, err = ProposalModel.decide_proposals(
        uuids, decision, current_user, ownership_mode=ownership_mode, note=note
    )
    if err:
        return jsonify({"message": err, "toast_class": "danger-subtle"}), 400

    verb = "accepted" if decision == "accept" else "rejected"
    log_activity("github_proposal.decision",
                 f"{verb.capitalize()} {len(proposals)} GitHub proposal(s)"
                 + (f" (ownership: {ownership_mode})" if decision == "accept" else ""),
                 target_type="github_proposal",
                 extra={"uuids": [p.uuid for p in proposals], "decision": decision, "note": note},
                 icon="fa-brands fa-github")

    return jsonify({
        "message": f"{len(proposals)} proposal(s) {verb}.",
        "toast_class": "success-subtle",
        "job_uuid": job.uuid if job else None,
    }), 200


@github_proposal_blueprint.route('/<uuid>/delete', methods=['POST'])
def proposal_delete(uuid):
    guard = _admin_only()
    if guard:
        return guard

    proposal = ProposalModel.get_proposal_by_uuid(uuid)
    if not proposal:
        return jsonify({"message": "Proposal not found.", "toast_class": "danger-subtle"}), 404

    repo_url = proposal.repo_url
    ProposalModel.delete_proposal(proposal)

    log_activity("github_proposal.delete", f"Deleted GitHub proposal for '{repo_url}'",
                 target_type="github_proposal", icon="fa-brands fa-github")
    return jsonify({"message": "Proposal deleted.", "toast_class": "success-subtle"}), 200


@github_proposal_blueprint.route('/<uuid>/cancel', methods=['POST'])
@login_required
def proposal_cancel(uuid):
    proposal = ProposalModel.get_proposal_by_uuid(uuid)
    if not proposal:
        return jsonify({"message": "Proposal not found.", "toast_class": "danger-subtle"}), 404
    if current_user.id != proposal.user_id:
        return jsonify({"message": "Access denied.", "toast_class": "danger-subtle"}), 403

    ok, err = ProposalModel.cancel_proposal(proposal)
    if not ok:
        return jsonify({"message": err, "toast_class": "danger-subtle"}), 400

    log_activity("github_proposal.cancel", f"Cancelled GitHub proposal for '{proposal.repo_url}'",
                 target_type="github_proposal", icon="fa-brands fa-github")
    return jsonify({"message": "Proposal cancelled.", "toast_class": "success-subtle"}), 200
