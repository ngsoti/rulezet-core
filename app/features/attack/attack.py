from flask import Blueprint, jsonify, request, render_template, abort
from flask_login import login_required, current_user
from . import attack_core as AttackModel
from ..jobs import jobs_core as JobModel

attack_blueprint = Blueprint('attack_blueprint', __name__)


# ── Technique catalogue ───────────────────────────────────────────────────────

@attack_blueprint.route('/techniques')
def list_techniques():
    tactic = request.args.get('tactic')
    return jsonify(AttackModel.get_all_techniques(tactic))


@attack_blueprint.route('/techniques/search')
def search_techniques():
    q = request.args.get('q', '')
    limit = min(int(request.args.get('limit', 20)), 50)
    return jsonify(AttackModel.search_techniques(q, limit))


@attack_blueprint.route('/stats')
def stats():
    return jsonify(AttackModel.get_stats())


@attack_blueprint.route('/techniques/usage')
def techniques_usage():
    """Techniques associated with at least one rule matching every currently
    active RuleList filter (format, tags, sources, licenses, CVEs, author...),
    with counts scoped to that filtered set. Used by the RuleList ATT&CK
    filter dropdown — this is what keeps its counts accurate as other
    filters are applied (e.g. picking format=suricata)."""
    from ...core.db_class.db import RuleAttackAssociation, AttackTechnique, Rule
    from app import db
    from sqlalchemy import func
    from app.features.rule import rule_core as RuleModel

    filters = RuleModel.parse_facet_filters(request.args, exclude=['attacks'])
    base_ids = RuleModel.filter_rules(**filters).order_by(None).with_entities(Rule.id).subquery()

    rows = (
        db.session.query(
            AttackTechnique.technique_id,
            AttackTechnique.name,
            func.count(func.distinct(RuleAttackAssociation.rule_id)).label('count'),
        )
        .join(RuleAttackAssociation, RuleAttackAssociation.technique_id == AttackTechnique.technique_id)
        .filter(RuleAttackAssociation.rule_id.in_(db.session.query(base_ids)))
        .group_by(AttackTechnique.technique_id, AttackTechnique.name)
        .order_by(func.count(func.distinct(RuleAttackAssociation.rule_id)).desc())
        .all()
    )
    # Fetch tactic_keys separately to avoid GROUP BY on JSON column
    tech_ids = [r.technique_id for r in rows]
    tactic_map = {}
    if tech_ids:
        tac_rows = (
            db.session.query(AttackTechnique.technique_id, AttackTechnique.tactic_keys)
            .filter(AttackTechnique.technique_id.in_(tech_ids))
            .all()
        )
        tactic_map = {r.technique_id: r.tactic_keys or [] for r in tac_rows}
    return jsonify({'techniques': [
        {'id': r.technique_id, 'name': r.name, 'tactic_keys': tactic_map.get(r.technique_id, []), 'count': r.count}
        for r in rows
    ]})


# ── Per-rule associations ─────────────────────────────────────────────────────

@attack_blueprint.route('/rule/<int:rule_id>')
def get_rule_techniques(rule_id):
    return jsonify(AttackModel.get_techniques_for_rule(rule_id))


@attack_blueprint.route('/rule/<int:rule_id>/add', methods=['POST'])
@login_required
def add_to_rule(rule_id):
    from ...core.db_class.db import Rule
    rule = Rule.query.get(rule_id)
    if not rule or rule.is_deleted:
        return jsonify({'error': 'Rule not found'}), 404
    if rule.user_id != current_user.id and not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403

    technique_id = (request.json or {}).get('technique_id', '')
    if not technique_id:
        return jsonify({'error': 'technique_id required'}), 400

    assoc, status = AttackModel.add_technique_to_rule(rule_id, technique_id, current_user.id, 'manual')
    if status == 'technique_not_found':
        return jsonify({'error': 'Technique not found'}), 404
    return jsonify({'success': True, 'status': status, 'assoc': assoc.to_json() if assoc else None})


@attack_blueprint.route('/rule/<int:rule_id>/remove/<technique_id>', methods=['DELETE'])
@login_required
def remove_from_rule(rule_id, technique_id):
    from ...core.db_class.db import Rule
    rule = Rule.query.get(rule_id)
    if not rule or rule.is_deleted:
        return jsonify({'error': 'Rule not found'}), 404
    if rule.user_id != current_user.id and not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403

    removed = AttackModel.remove_technique_from_rule(rule_id, technique_id)
    return jsonify({'success': removed})


# ── Heatmap & technique detail ────────────────────────────────────────────────

@attack_blueprint.route('/heatmap')
def heatmap():
    return render_template('attack/heatmap.html')


@attack_blueprint.route('/heatmap_data')
def heatmap_data():
    from app.features.attack.attack_core import get_global_coverage
    return jsonify(get_global_coverage())


@attack_blueprint.route('/technique/<string:technique_id>')
def technique_detail(technique_id):
    """Public technique detail page."""
    from app.core.db_class.db import AttackTechnique
    tech = AttackTechnique.query.filter_by(technique_id=technique_id.upper()).first()
    if not tech:
        abort(404)
    return render_template('attack/technique_detail.html', technique=tech)


@attack_blueprint.route('/technique/<string:technique_id>/stats')
def technique_stats(technique_id):
    """Per-technique stats: rules by format + rules over time."""
    import datetime
    from collections import defaultdict
    from app import db
    from app.core.db_class.db import RuleAttackAssociation, Rule, AttackTechnique

    tid = technique_id.upper()
    tech = AttackTechnique.query.filter_by(technique_id=tid).first()
    if not tech:
        return jsonify({'error': 'not found'}), 404

    from sqlalchemy import func

    # Rules by format
    fmt_rows = (
        db.session.query(Rule.format, func.count(Rule.id))
        .join(RuleAttackAssociation, RuleAttackAssociation.rule_id == Rule.id)
        .filter(RuleAttackAssociation.technique_id == tid)
        .filter(Rule.is_deleted == False)
        .group_by(Rule.format)
        .order_by(func.count(Rule.id).desc())
        .all()
    )

    # Rules added over time (last 12 months, by month)
    now = datetime.datetime.utcnow()
    cutoff = now - datetime.timedelta(days=365)
    date_rows = (
        db.session.query(Rule.creation_date)
        .join(RuleAttackAssociation, RuleAttackAssociation.rule_id == Rule.id)
        .filter(RuleAttackAssociation.technique_id == tid)
        .filter(Rule.is_deleted == False)
        .filter(Rule.creation_date >= cutoff)
        .all()
    )
    bucket = defaultdict(int)
    for (dt,) in date_rows:
        if dt:
            if isinstance(dt, str):
                try: dt = datetime.datetime.fromisoformat(dt)
                except: continue
            bucket[dt.strftime('%Y-%m')] += 1

    labels, vals = [], []
    d = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_keys = []
    for _ in range(12):
        month_keys.append(d.strftime('%Y-%m'))
        d = (d - datetime.timedelta(days=1)).replace(day=1)
    month_keys.reverse()
    for mk in month_keys:
        try:
            nice = datetime.datetime.strptime(mk, '%Y-%m').strftime('%b %Y')
        except:
            nice = mk
        labels.append(nice)
        vals.append(bucket.get(mk, 0))

    # Sub-techniques count if this is a parent
    sub_count = AttackTechnique.query.filter_by(parent_technique_id=tid).count()

    return jsonify({
        'total_rules': sum(r[1] for r in fmt_rows),
        'sub_techniques': sub_count,
        'formats': {
            'title': 'Rules by Format',
            'categories': [r[0] or 'Unknown' for r in fmt_rows],
            'series': [{'values': [r[1] for r in fmt_rows]}],
        },
        'over_time': {
            'title': 'Rules covering this technique',
            'subtitle': 'Last 12 months',
            'categories': labels,
            'series': [{'name': 'Rules', 'values': vals}],
        },
    })


@attack_blueprint.route('/admin/analytics')
@login_required
def admin_analytics():
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    from app.features.attack.attack_core import get_analytics_data
    return jsonify(get_analytics_data())


@attack_blueprint.route('/admin/gaps')
@login_required
def admin_gaps():
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    from app.features.attack.attack_core import get_coverage_gaps
    return jsonify({'gaps': get_coverage_gaps()})


# ── Admin: trigger jobs ───────────────────────────────────────────────────────

@attack_blueprint.route('/admin/list')
@login_required
def admin_list():
    if not current_user.is_admin():
        abort(403)
    return render_template('admin/attack_list.html')


@attack_blueprint.route('/admin/techniques')
@login_required
def admin_techniques():
    """Server-side paginated + sorted admin API for ATT&CK techniques."""
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403

    from app import db
    from app.core.db_class.db import AttackTechnique, RuleAttackAssociation
    from sqlalchemy import func, asc, desc, cast, Text

    search          = request.args.get('search', '').strip()
    tactic          = request.args.get('tactic', '').strip()
    show_deprecated = request.args.get('show_deprecated', 'false').lower() == 'true'
    sort_by         = request.args.get('sort_by', 'technique_id')
    sort_dir        = request.args.get('sort_dir', 'asc').lower()
    try:
        page     = max(1, int(request.args.get('page', 1)))
        per_page = min(500, max(10, int(request.args.get('per_page', 50))))
    except (ValueError, TypeError):
        page, per_page = 1, 50

    count_subq = (
        db.session.query(
            RuleAttackAssociation.technique_id,
            func.count(RuleAttackAssociation.id).label('cnt'),
        )
        .group_by(RuleAttackAssociation.technique_id)
        .subquery()
    )

    q = (
        db.session.query(AttackTechnique, func.coalesce(count_subq.c.cnt, 0).label('rule_count'))
        .outerjoin(count_subq, count_subq.c.technique_id == AttackTechnique.technique_id)
    )

    if not show_deprecated:
        q = q.filter(AttackTechnique.deprecated == False)

    if search:
        like = f'%{search}%'
        q = q.filter(db.or_(
            AttackTechnique.technique_id.ilike(like),
            AttackTechnique.name.ilike(like),
        ))

    if tactic:
        # Works on both PostgreSQL JSON and SQLite TEXT-cast
        q = q.filter(cast(AttackTechnique.tactic_keys, Text).ilike(f'%"{tactic}"%'))

    # Sorting
    _SORT_COLS = {
        'technique_id':  AttackTechnique.technique_id,
        'name':          AttackTechnique.name,
        'rule_count':    count_subq.c.cnt,
        'is_subtechnique': AttackTechnique.is_subtechnique,
        'deprecated':    AttackTechnique.deprecated,
    }
    sort_col = _SORT_COLS.get(sort_by, AttackTechnique.technique_id)
    order_fn = desc if sort_dir == 'desc' else asc
    # Secondary sort by technique_id for stable ordering
    q = q.order_by(order_fn(sort_col), AttackTechnique.technique_id)

    total = q.count()
    pages = max(1, (total + per_page - 1) // per_page)
    page  = min(page, pages)

    rows = q.offset((page - 1) * per_page).limit(per_page).all()

    result = []
    for tech, rule_count in rows:
        d = tech.to_json()
        d['rule_count'] = int(rule_count)
        result.append(d)

    return jsonify({
        'techniques': result,
        'total':      total,
        'page':       page,
        'pages':      pages,
        'per_page':   per_page,
    })


@attack_blueprint.route('/admin/trigger_update', methods=['POST'])
@login_required
def trigger_update():
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    job = JobModel.create_job(
        job_type='update_attack_data',
        payload={},
        label='Update MITRE ATT&CK data',
        created_by=current_user.id,
        total=1,
    )
    return jsonify({'success': True, 'job_id': job.id, 'job_uuid': job.uuid})


@attack_blueprint.route('/admin/trigger_parse', methods=['POST'])
@login_required
def trigger_parse():
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json or {}
    job = JobModel.create_job(
        job_type='bulk_parse_attack_rules',
        payload={'format': data.get('format')},
        label='Auto-parse ATT&CK techniques from rules',
        created_by=current_user.id,
        total=0,
    )
    return jsonify({'success': True, 'job_id': job.id, 'job_uuid': job.uuid})
