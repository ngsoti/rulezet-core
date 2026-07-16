import re

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from . import workspace_core as WsModel
from app.core.utils.activity_log import log_activity

workspace_blueprint = Blueprint('workspace', __name__)

# Mirrors the client-side v_pattern in static/js/vulnerability/vulnerabilityInput.js
VULN_ID_PATTERN = re.compile(
    r'^(CVE[-\s]\d{4}[-\s]\d{4,7}'
    r'|GCVE-\d+-\d{4}-\d+'
    r'|GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}'
    r'|PYSEC-\d{4}-\d{2,5}'
    r'|GSD-\d{4}-\d{4,5}'
    r'|wid-sec-w-\d{4}-\d{4}'
    r'|cisco-sa-\d{8}-[a-zA-Z0-9]+'
    r'|RHSA-\d{4}:\d{4}'
    r'|msrc_CVE-\d{4}-\d{4,}'
    r'|CERTFR-\d{4}-[A-Z]{3}-\d{3})$',
    re.IGNORECASE
)


@workspace_blueprint.route('/my_rules')
@login_required
def my_rules():
    return render_template('workspace/my_rules.html')


@workspace_blueprint.route('/list')
@login_required
def list_workspaces():
    if request.args.get('scope') == 'all' and current_user.is_admin():
        workspaces = WsModel.get_all_workspaces()
    else:
        workspaces = WsModel.get_user_workspaces(current_user.id)
    return jsonify([ws.to_json() for ws in workspaces])


@workspace_blueprint.route('/create', methods=['POST'])
@login_required
def create_workspace():
    data = request.get_json(force=True)
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'message': 'Name is required'}), 400
    ws = WsModel.create_workspace(
        user_id=current_user.id,
        name=name,
        description=data.get('description'),
        icon=data.get('icon', 'fa-folder'),
        color=data.get('color', '#0d6efd'),
    )
    log_activity('workspace.create', f"Created workspace '{ws.name}'",
                 target_type='workspace', target_id=ws.id, target_uuid=ws.uuid)
    return jsonify({'success': True, 'workspace': ws.to_json()}), 201


@workspace_blueprint.route('/<ws_uuid>', methods=['PATCH'])
@login_required
def update_workspace(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws:
        return jsonify({'success': False}), 404
    if ws.user_id != current_user.id and not current_user.is_admin():
        return jsonify({'success': False}), 403
    import json as _json
    from app import db
    data = request.get_json(force=True)
    ws = WsModel.update_workspace(
        ws,
        name=data.get('name'),
        description=data.get('description'),
        icon=data.get('icon'),
        color=data.get('color'),
    )
    if 'url' in data:
        ws.url = (data['url'] or '').strip() or None
    if 'cves' in data:
        cves = data['cves'] or []
        if not isinstance(cves, list) or not all(isinstance(c, str) and VULN_ID_PATTERN.match(c.strip()) for c in cves):
            return jsonify({'success': False, 'message': 'Invalid vulnerability identifier format'}), 400
        ws.cve_id = _json.dumps([c.strip() for c in cves]) if cves else None
    db.session.commit()
    return jsonify({'success': True, 'workspace': ws.to_json()})


@workspace_blueprint.route('/<ws_uuid>', methods=['DELETE'])
@login_required
def delete_workspace(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws:
        return jsonify({'success': False}), 404
    if ws.user_id != current_user.id and not current_user.is_admin():
        return jsonify({'success': False}), 403
    name = ws.name
    WsModel.delete_workspace(ws)
    log_activity('workspace.delete', f"Deleted workspace '{name}'")
    return jsonify({'success': True})


@workspace_blueprint.route('/<ws_uuid>/rules', methods=['POST'])
@login_required
def add_rules(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws:
        return jsonify({'success': False}), 404
    if ws.user_id != current_user.id and not current_user.is_admin():
        return jsonify({'success': False}), 403
    data = request.get_json(force=True)
    raw_ids = data.get('rule_ids') or ([data['rule_id']] if data.get('rule_id') else [])
    rule_ids = [int(r) for r in raw_ids if str(r).lstrip('-').isdigit()]
    added = WsModel.bulk_add_rules_to_workspace(ws, rule_ids)
    return jsonify({'success': True, 'added': added, 'workspace': ws.to_json()})


@workspace_blueprint.route('/<ws_uuid>/rules/<int:rule_id>', methods=['DELETE'])
@login_required
def remove_rule(ws_uuid, rule_id):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws:
        return jsonify({'success': False}), 404
    if ws.user_id != current_user.id and not current_user.is_admin():
        return jsonify({'success': False}), 403
    ok = WsModel.remove_rule_from_workspace(ws, rule_id)
    return jsonify({'success': ok, 'workspace': ws.to_json()})


@workspace_blueprint.route('/<ws_uuid>/kpis')
@login_required
def workspace_kpis(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify({'total': 0, 'draft': 0, 'testing': 0, 'production': 0, 'deprecated': 0})
    from app.core.db_class.db import WorkspaceRule, Rule
    from app import db
    from sqlalchemy import func
    wr_subq = db.session.query(WorkspaceRule.rule_id).filter_by(workspace_id=ws.id).subquery()
    rows = (
        db.session.query(Rule.status, func.count(Rule.id))
        .filter(Rule.id.in_(wr_subq), Rule.is_deleted == False)
        .group_by(Rule.status)
        .all()
    )
    counts = {'draft': 0, 'testing': 0, 'production': 0, 'deprecated': 0}
    for status, cnt in rows:
        if status in counts:
            counts[status] = cnt
    counts['total'] = sum(counts.values())
    return jsonify(counts)


@workspace_blueprint.route('/<ws_uuid>/detail')
@login_required
def workspace_detail(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        from flask import abort
        abort(404)
    return render_template('workspace/workspace_detail.html', workspace=ws)


@workspace_blueprint.route('/<ws_uuid>/documents', methods=['GET'])
@login_required
def list_documents(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify([])
    from app.core.db_class.db import WorkspaceDocument
    docs = WorkspaceDocument.query.filter_by(workspace_id=ws.id).order_by(WorkspaceDocument.updated_at.desc()).all()
    return jsonify([d.to_json() for d in docs])


@workspace_blueprint.route('/<ws_uuid>/documents', methods=['POST'])
@login_required
def create_document(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify({'success': False}), 403
    data = request.get_json(force=True)
    from app.core.db_class.db import WorkspaceDocument
    from app import db
    doc = WorkspaceDocument(
        workspace_id=ws.id,
        title=data.get('title', 'Untitled'),
        content=data.get('content', ''),
    )
    db.session.add(doc)
    db.session.commit()
    return jsonify({'success': True, 'document': doc.to_json()}), 201


@workspace_blueprint.route('/<ws_uuid>/documents/<int:doc_id>', methods=['PATCH'])
@login_required
def update_document(ws_uuid, doc_id):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify({'success': False}), 403
    from app.core.db_class.db import WorkspaceDocument
    from app import db
    doc = WorkspaceDocument.query.filter_by(id=doc_id, workspace_id=ws.id).first()
    if not doc:
        return jsonify({'success': False}), 404
    data = request.get_json(force=True)
    if 'title' in data:
        doc.title = data['title']
    if 'content' in data:
        doc.content = data['content']
    db.session.commit()
    return jsonify({'success': True, 'document': doc.to_json()})


@workspace_blueprint.route('/<ws_uuid>/documents/<int:doc_id>', methods=['DELETE'])
@login_required
def delete_document(ws_uuid, doc_id):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify({'success': False}), 403
    from app.core.db_class.db import WorkspaceDocument
    from app import db
    doc = WorkspaceDocument.query.filter_by(id=doc_id, workspace_id=ws.id).first()
    if not doc:
        return jsonify({'success': False}), 404
    db.session.delete(doc)
    db.session.commit()
    return jsonify({'success': True})


@workspace_blueprint.route('/<ws_uuid>/links', methods=['GET'])
@login_required
def list_links(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify([])
    from app.core.db_class.db import WorkspaceLink
    links = WorkspaceLink.query.filter_by(workspace_id=ws.id).order_by(WorkspaceLink.created_at.desc()).all()
    return jsonify([l.to_json() for l in links])


@workspace_blueprint.route('/<ws_uuid>/links', methods=['POST'])
@login_required
def create_link(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify({'success': False}), 403
    data = request.get_json(force=True)
    if not data.get('url') or not data.get('title'):
        return jsonify({'success': False, 'message': 'URL and title required'}), 400
    from app.core.db_class.db import WorkspaceLink
    from app import db
    link = WorkspaceLink(
        workspace_id=ws.id,
        title=data['title'],
        url=data['url'],
        description=data.get('description'),
    )
    db.session.add(link)
    db.session.commit()
    return jsonify({'success': True, 'link': link.to_json()}), 201


@workspace_blueprint.route('/<ws_uuid>/links/<int:link_id>', methods=['DELETE'])
@login_required
def delete_link(ws_uuid, link_id):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify({'success': False}), 403
    from app.core.db_class.db import WorkspaceLink
    from app import db
    link = WorkspaceLink.query.filter_by(id=link_id, workspace_id=ws.id).first()
    if not link:
        return jsonify({'success': False}), 404
    db.session.delete(link)
    db.session.commit()
    return jsonify({'success': True})


@workspace_blueprint.route('/<ws_uuid>/rules/<int:rule_id>/note', methods=['PATCH'])
@login_required
def update_rule_note(ws_uuid, rule_id):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify({'success': False}), 403
    from app.core.db_class.db import WorkspaceRule
    from app import db
    assoc = WorkspaceRule.query.filter_by(workspace_id=ws.id, rule_id=rule_id).first()
    if not assoc:
        return jsonify({'success': False}), 404
    data = request.get_json(force=True)
    assoc.note = data.get('note', '')
    db.session.commit()
    return jsonify({'success': True, 'note': assoc.note})


@workspace_blueprint.route('/<ws_uuid>/rules/bulk', methods=['DELETE'])
@login_required
def bulk_remove_rules(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws:
        return jsonify({'success': False}), 404
    if ws.user_id != current_user.id and not current_user.is_admin():
        return jsonify({'success': False}), 403
    data = request.get_json(force=True)
    rule_ids = data.get('rule_ids', [])
    removed = sum(1 for rid in rule_ids if WsModel.remove_rule_from_workspace(ws, rid))
    return jsonify({'success': True, 'removed': removed, 'workspace': ws.to_json()})


# ── Export as Bundle ─────────────────────────────────────────────────────────
# The "new vs existing bundle" choice itself is handled client-side by the same
# <rule-bundle-manager> component the rule list's own "Export/Bundle" action
# uses (POSTing to the existing /rule/bundle/create-from-filters endpoint with
# an explicit rule id list). Placing the rules into the bundle's folder
# structure is then done by the same in-modal Bundle Structure Editor +
# BundleRuleSelector drag/organize flow as the rule list — this route only
# marks the bundle as associated with this workspace (link_bundle) or removes
# that association again (unlink_bundle); it never touches bundle contents.

@workspace_blueprint.route('/<ws_uuid>/rule_ids', methods=['GET'])
@login_required
def workspace_rule_ids(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify({'rule_ids': []})
    return jsonify({'rule_ids': WsModel.get_workspace_rule_ids(ws)})


@workspace_blueprint.route('/<ws_uuid>/link_bundle', methods=['POST'])
@login_required
def link_bundle(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws:
        return jsonify({'success': False}), 404
    if ws.user_id != current_user.id and not current_user.is_admin():
        return jsonify({'success': False}), 403

    data = request.get_json(force=True) or {}
    bundle_id = data.get('bundle_id')
    if not bundle_id:
        return jsonify({'success': False, 'message': 'bundle_id is required'}), 400

    from app.features.bundle import bundle_core as BundleModel
    from app import db

    bundle = BundleModel.get_bundle_by_id(bundle_id)
    if not bundle:
        return jsonify({'success': False, 'message': 'Bundle not found'}), 404
    if bundle.user_id != current_user.id and not current_user.is_admin():
        return jsonify({'success': False, 'message': "You don't have permission to edit this bundle"}), 403

    bundle.source_workspace_id = ws.id
    db.session.commit()

    log_activity('bundle.create', f"Associated bundle '{bundle.name}' with workspace '{ws.name}'",
                 target_type='bundle', target_id=bundle.id, target_uuid=bundle.uuid)

    return jsonify({'success': True, 'bundle': bundle.to_json()}), 201


@workspace_blueprint.route('/<ws_uuid>/bundles', methods=['GET'])
@login_required
def list_workspace_bundles(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify([])
    from app.features.bundle import bundle_core as BundleModel
    bundles = BundleModel.get_bundles_by_workspace(ws.id)
    return jsonify([b.to_json() for b in bundles])


@workspace_blueprint.route('/<ws_uuid>/bundles/<int:bundle_id>', methods=['DELETE'])
@login_required
def unlink_bundle(ws_uuid, bundle_id):
    """Remove the association between a bundle and this workspace — the
    bundle itself (and its rules) is left untouched."""
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws:
        return jsonify({'success': False}), 404
    if ws.user_id != current_user.id and not current_user.is_admin():
        return jsonify({'success': False}), 403

    from app.features.bundle import bundle_core as BundleModel
    from app import db

    bundle = BundleModel.get_bundle_by_id(bundle_id)
    if not bundle or bundle.source_workspace_id != ws.id:
        return jsonify({'success': False}), 404

    bundle.source_workspace_id = None
    db.session.commit()
    return jsonify({'success': True})


# ── Workspace Tags ──────────────────────────────────────────────────────────

@workspace_blueprint.route('/<ws_uuid>/tags', methods=['GET'])
@login_required
def list_workspace_tags(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify([])
    from app.core.db_class.db import WorkspaceTagAssociation
    rows = WorkspaceTagAssociation.query.filter_by(workspace_id=ws.id).all()
    return jsonify([r.tag.to_json() for r in rows if r.tag])


@workspace_blueprint.route('/<ws_uuid>/tags', methods=['POST'])
@login_required
def add_workspace_tag(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify({'success': False}), 403
    from app.core.db_class.db import WorkspaceTagAssociation, Tag
    from app import db
    tag_id = (request.get_json(force=True) or {}).get('tag_id')
    if not tag_id or not Tag.query.get(tag_id):
        return jsonify({'success': False, 'message': 'Tag not found'}), 404
    if not WorkspaceTagAssociation.query.filter_by(workspace_id=ws.id, tag_id=tag_id).first():
        import datetime
        db.session.add(WorkspaceTagAssociation(
            workspace_id=ws.id, tag_id=tag_id, user_id=current_user.id,
            created_at=datetime.datetime.now(tz=datetime.timezone.utc)))
        db.session.commit()
    return jsonify({'success': True})


@workspace_blueprint.route('/<ws_uuid>/tags/<int:tag_id>', methods=['DELETE'])
@login_required
def remove_workspace_tag(ws_uuid, tag_id):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify({'success': False}), 403
    from app.core.db_class.db import WorkspaceTagAssociation
    from app import db
    assoc = WorkspaceTagAssociation.query.filter_by(workspace_id=ws.id, tag_id=tag_id).first()
    if assoc:
        db.session.delete(assoc)
        db.session.commit()
    return jsonify({'success': True})


# ── Workspace Attacks ───────────────────────────────────────────────────────

@workspace_blueprint.route('/<ws_uuid>/attacks', methods=['GET'])
@login_required
def list_workspace_attacks(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify([])
    from app.core.db_class.db import WorkspaceAttackAssociation
    rows = WorkspaceAttackAssociation.query.filter_by(workspace_id=ws.id).all()
    return jsonify([{
        'technique_id': r.technique.technique_id,
        'name': r.technique.name,
        'tactic_keys': r.technique.tactic_keys or [],
    } for r in rows if r.technique])


@workspace_blueprint.route('/<ws_uuid>/attacks', methods=['POST'])
@login_required
def add_workspace_attack(ws_uuid):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify({'success': False}), 403
    from app.core.db_class.db import WorkspaceAttackAssociation, AttackTechnique
    from app import db
    technique_id = (request.get_json(force=True) or {}).get('technique_id')
    if not technique_id or not AttackTechnique.query.filter_by(technique_id=technique_id).first():
        return jsonify({'success': False, 'message': 'Technique not found'}), 404
    if not WorkspaceAttackAssociation.query.filter_by(workspace_id=ws.id, technique_id=technique_id).first():
        db.session.add(WorkspaceAttackAssociation(workspace_id=ws.id, technique_id=technique_id))
        db.session.commit()
    return jsonify({'success': True})


@workspace_blueprint.route('/<ws_uuid>/attacks/<technique_id>', methods=['DELETE'])
@login_required
def remove_workspace_attack(ws_uuid, technique_id):
    ws = WsModel.get_workspace_by_uuid(ws_uuid)
    if not ws or (ws.user_id != current_user.id and not current_user.is_admin()):
        return jsonify({'success': False}), 403
    from app.core.db_class.db import WorkspaceAttackAssociation
    from app import db
    assoc = WorkspaceAttackAssociation.query.filter_by(workspace_id=ws.id, technique_id=technique_id).first()
    if assoc:
        db.session.delete(assoc)
        db.session.commit()
    return jsonify({'success': True})
