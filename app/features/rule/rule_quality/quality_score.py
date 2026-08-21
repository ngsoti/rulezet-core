"""
quality_score.py — admin-only Blueprint for the Rule Quality Score
dashboard. Scoring logic lives in quality_score_core.py; bulk (re)analysis
runs through the existing generic BackgroundJob pipeline — this blueprint
does NOT define its own "launch job" route, it reuses POST /jobs/create with
job_type='compute_rule_quality_score' (handler in job_handlers.py), exactly
like app/templates/jobs/bulk_tag.html already does for tag jobs.
"""
from flask import Blueprint, abort, jsonify, redirect, render_template, request, url_for
from flask_login import current_user

from app import db
import app.features.rule.rule_core as RuleModel
from app.core.db_class.db import BackgroundJob, Rule
from app.core.utils.activity_log import log_activity

JOB_TYPE = 'compute_rule_quality_score'
_ACTIVE_STATUSES = ('pending', 'running', 'paused')


def _job_mode_label(job):
    """Describe a job's scope from its stored payload — mirrors the two
    shapes the admin panel can send: {filters: {rule_ids: [...]}} (manual
    RuleList selection) or {filters: {...or {}}} ('all matching filters')."""
    filters = (job.payload or {}).get('filters', {}) or {}
    rule_ids = filters.get('rule_ids')
    if rule_ids:
        return f"Manual selection ({len(rule_ids)} rule(s))"
    if filters:
        return "All matching filters"
    return "All rules"

quality_blueprint = Blueprint(
    'quality',
    __name__,
    template_folder='templates',
)


@quality_blueprint.before_request
def _require_admin():
    if not current_user.is_authenticated:
        return redirect(url_for('account.login'))
    if not current_user.is_admin():
        abort(403)


@quality_blueprint.route('/admin', methods=['GET'])
def admin_panel():
    return render_template('admin/rule_quality_score.html')


@quality_blueprint.route('/stats', methods=['GET'])
def stats():
    """KPI + score-distribution data for the dashboard's ChartViewer.
    Buckets are 10-wide (0-10, 10-20, ..., 90-100) over quality_score —
    the objective base score, not display_score (which folds in the
    engagement boost and would blur the documentation signal this page
    exists to surface)."""
    base = RuleModel._active()
    total_rules = base.count()

    analyzed_q = base.filter(Rule.quality_score.isnot(None))
    analyzed_count = analyzed_q.count()
    not_analyzed_count = total_rules - analyzed_count

    avg_score = 0.0
    well_documented = 0
    poorly_documented = 0
    buckets = [0] * 10

    if analyzed_count:
        scores = [s for (s,) in analyzed_q.with_entities(Rule.quality_score).all()]
        avg_score = round(sum(scores) / len(scores), 1)
        well_documented = sum(1 for s in scores if s > 70)
        poorly_documented = sum(1 for s in scores if s < 40)
        for s in scores:
            idx = min(int(s // 10), 9)
            buckets[idx] += 1

    active_job = (
        BackgroundJob.query
        .filter(BackgroundJob.job_type == JOB_TYPE, BackgroundJob.status.in_(_ACTIVE_STATUSES))
        .order_by(BackgroundJob.created_at.desc())
        .first()
    )

    return jsonify({
        "total_rules": total_rules,
        "analyzed_count": analyzed_count,
        "not_analyzed_count": not_analyzed_count,
        "avg_score": avg_score,
        "well_documented_pct": round(well_documented / analyzed_count * 100, 1) if analyzed_count else 0,
        "poorly_documented_pct": round(poorly_documented / analyzed_count * 100, 1) if analyzed_count else 0,
        "distribution": {
            "title": "Quality score distribution",
            "categories": [f"{i*10}-{i*10+10}" for i in range(10)],
            "series": [
                {"name": "Rules in bucket", "values": buckets},
                # "At least this score" — reads right-to-left cumulative sum,
                # answers "how many rules score >= this bucket's floor".
                {"name": "Rules scoring at least this much",
                 "values": [sum(buckets[i:]) for i in range(10)]},
            ],
            "meta": {"unit": "rules"},
        },
        # Lets the dashboard reattach its JobTracker to a run already in
        # flight after a page reload/navigation-away, instead of losing
        # track of it the moment activeJobUuid resets to null client-side.
        "active_job": {
            "uuid": active_job.uuid,
            "label": active_job.label,
        } if active_job else None,
    }), 200


@quality_blueprint.route('/reset', methods=['POST'])
def reset_scores():
    """Wipe quality_score/breakdown/computed_at for every rule — a single
    bulk UPDATE, not a background job: unlike scoring itself (which parses/
    validates each rule's content in Python), clearing 3 columns needs no
    per-row work, so it completes instantly even across hundreds of
    thousands of rules. Confirmation happens client-side before this is
    ever called; this route itself just executes once confirmed."""
    reset_count = Rule.query.filter(Rule.quality_score.isnot(None)).update(
        {
            "quality_score": None,
            "quality_score_breakdown": None,
            "quality_score_computed_at": None,
        },
        synchronize_session=False,
    )
    db.session.commit()

    log_activity(
        "admin.reset_quality_scores",
        f"Reset quality scores for {reset_count} rule(s)",
        category="admin",
        level="warning",
    )

    return jsonify({"reset_count": reset_count}), 200


@quality_blueprint.route('/history', methods=['GET'])
def history():
    """Past compute_rule_quality_score runs — when they were launched and in
    what mode (all rules / all matching filters / manual selection), so the
    admin can see at a glance when they last ran an analysis."""
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(50, max(1, request.args.get('per_page', 15, type=int)))

    query = (
        BackgroundJob.query
        .filter(BackgroundJob.job_type == JOB_TYPE)
        .order_by(BackgroundJob.created_at.desc())
    )
    total = query.count()
    jobs = query.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "items": [
            {
                **j.to_json(),
                "mode": _job_mode_label(j),
            }
            for j in jobs
        ],
        "total": total,
        "total_pages": max(1, -(-total // per_page)),
    }), 200
