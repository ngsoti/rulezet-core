import json
import os
from flask import send_from_directory
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, send_from_directory, abort
from flask_login import current_user, login_required
from flask import get_flashed_messages
from flask_login import login_required, current_user

from app.core.utils.utils import get_version
from app.core.utils.activity_log import log_activity

from .features.rule import rule_core as RuleModel
from .features.account import account_core as AccountModel


home_blueprint = Blueprint(
    'home',
    __name__,
    template_folder='templates',
    static_folder='static'
)

#####################
#   Alert section   #
#####################

@home_blueprint.route("/request_to_check")
def inject_requests_to_validate() -> jsonify:
    """Get the number of  request to validate"""
    try:
        if current_user.is_admin():
            count = AccountModel.get_total_requests_to_check_admin()
        else:
            count = AccountModel.get_total_requests_to_check()
    except:
        count = 0
    return jsonify({"count": count})

###################
#   Home section  #
###################
@home_blueprint.route("/why_choose_rulezet")
def why():
    return render_template("why.html")


@home_blueprint.route("/starfield")
def starfield():
    """Hidden easter egg — a small space game. Not linked from any nav/sitemap."""
    return render_template("starfield.html")

@home_blueprint.route("/")
def home() -> render_template:
    """Go to home page"""
    from app.core.db_class.db import Rule, Bundle, User
    get_flashed_messages()
    show_import_hint = (
        current_user.is_authenticated
        and current_user.is_admin()
        and RuleModel.get_total_rules_count() == 0
    )
    from app.core.db_class.db import AttackTechnique
    total_rules   = Rule.query.filter_by(is_deleted=False).count()
    total_bundles = Bundle.query.count()
    total_attacks = AttackTechnique.query.count()
    rule_formats  = RuleModel.get_all_rule_format()
    return render_template("home.html",
        show_import_hint=show_import_hint,
        total_rules=total_rules,
        total_bundles=total_bundles,
        total_attacks=total_attacks,
        rule_formats=rule_formats,
    )

@home_blueprint.route("/home_charts/<tab>")
def home_charts(tab):
    """Lazy chart loader — fetches only the requested tab's data."""
    import datetime, json as _json
    from sqlalchemy import func
    from app.core.db_class.db import Rule
    from app import db

    if tab == 'total':
        now = datetime.datetime.utcnow()
        labels, nice = [], []
        d = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        for _ in range(6):
            labels.append(d.strftime('%Y-%m'))
            d = (d - datetime.timedelta(days=1)).replace(day=1)
        labels.reverse()
        for l in labels:
            try: nice.append(datetime.datetime.strptime(l, '%Y-%m').strftime('%b %Y'))
            except: nice.append(l)

        window_start = datetime.datetime.strptime(labels[0], '%Y-%m')

        # Net total as of just before the window — every rule ever created,
        # minus every rule still deleted at that point (restores clear
        # deleted_at, so a restored rule is naturally not subtracted).
        baseline_created = Rule.query.filter(Rule.creation_date < window_start).count()
        baseline_deleted = Rule.query.filter(Rule.deleted_at.isnot(None), Rule.deleted_at < window_start).count()
        running_total = baseline_created - baseline_deleted

        created_month_expr = (func.to_char(Rule.creation_date, 'YYYY-MM')
                              if db.engine.dialect.name == 'postgresql'
                              else func.strftime('%Y-%m', Rule.creation_date))
        deleted_month_expr = (func.to_char(Rule.deleted_at, 'YYYY-MM')
                              if db.engine.dialect.name == 'postgresql'
                              else func.strftime('%Y-%m', Rule.deleted_at))

        created_rows = (db.session.query(created_month_expr.label('m'), func.count(Rule.id))
                        .filter(Rule.creation_date >= window_start)
                        .group_by('m').all())
        created_bucket = {r[0]: r[1] for r in created_rows if r[0]}

        deleted_rows = (db.session.query(deleted_month_expr.label('m'), func.count(Rule.id))
                        .filter(Rule.deleted_at.isnot(None), Rule.deleted_at >= window_start)
                        .group_by('m').all())
        deleted_bucket = {r[0]: r[1] for r in deleted_rows if r[0]}

        values = []
        for l in labels:
            running_total += created_bucket.get(l, 0) - deleted_bucket.get(l, 0)
            values.append(running_total)

        return jsonify({'title': 'Total Rules Over Time', 'subtitle': 'Cumulative — last 6 months',
                        'categories': nice, 'series': [{'name': 'Total Rules', 'values': values}]})

    if tab == 'timeline':
        now = datetime.datetime.utcnow()
        labels, nice = [], []
        d = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        for _ in range(6):
            labels.append(d.strftime('%Y-%m'))
            d = (d - datetime.timedelta(days=1)).replace(day=1)
        labels.reverse()
        for l in labels:
            try: nice.append(datetime.datetime.strptime(l, '%Y-%m').strftime('%b %Y'))
            except: nice.append(l)
        cutoff = now - datetime.timedelta(days=186)
        month_expr = (func.to_char(Rule.creation_date, 'YYYY-MM')
                      if db.engine.dialect.name == 'postgresql'
                      else func.strftime('%Y-%m', Rule.creation_date))
        rows = (db.session.query(month_expr.label('m'), func.count(Rule.id))
                .filter(Rule.is_deleted == False, Rule.creation_date >= cutoff)
                .group_by('m').all())
        bucket = {r[0]: r[1] for r in rows if r[0]}
        return jsonify({'title': 'Rules Added / Month', 'subtitle': 'Last 6 months',
                        'categories': nice, 'series': [{'name': 'Rules Added', 'values': [bucket.get(l, 0) for l in labels]}]})

    if tab == 'formats':
        rows = (db.session.query(Rule.format, func.count(Rule.id))
                .filter(Rule.is_deleted == False)
                .group_by(Rule.format)
                .order_by(func.count(Rule.id).desc())
                .limit(10).all())
        return jsonify({'title': 'Rules by Format',
                        'categories': [r[0] or 'Unknown' for r in rows],
                        'series': [{'name': 'Rules', 'values': [r[1] for r in rows]}]})

    if tab == 'top_cve':
        raws = (db.session.query(Rule.cve_id)
                .filter(Rule.is_deleted == False, Rule.cve_id.isnot(None),
                        Rule.cve_id != '[]', Rule.cve_id != '').all())
        counter: dict = {}
        for (raw,) in raws:
            try:
                ids = _json.loads(raw) if raw else []
            except Exception:
                ids = []
            for cid in ids:
                if cid:
                    counter[cid] = counter.get(cid, 0) + 1
        top = sorted(counter.items(), key=lambda x: x[1], reverse=True)[:10]
        return jsonify({'title': 'CVEs with the most rules',
                        'categories': [c[0] for c in top],
                        'series': [{'name': 'Rules', 'values': [c[1] for c in top]}]})

    if tab == 'top_atk':
        from app.core.db_class.db import RuleAttackAssociation
        rows = (db.session.query(RuleAttackAssociation.technique_id,
                                 func.count(RuleAttackAssociation.id).label('n'))
                .join(Rule, Rule.id == RuleAttackAssociation.rule_id)
                .filter(Rule.is_deleted == False)
                .group_by(RuleAttackAssociation.technique_id)
                .order_by(func.count(RuleAttackAssociation.id).desc())
                .limit(10).all())
        return jsonify({'title': 'ATT&CK techniques with the most rules',
                        'categories': [r[0] for r in rows],
                        'series': [{'name': 'Rules', 'values': [r[1] for r in rows]}]})

    return jsonify({}), 400


@home_blueprint.route("/get_last_rules", methods=['GET'])
def get_last_rules() -> dict:
    """Get the last 10 rules create or update"""
    rules = RuleModel.get_last_rules_from_db()
    rule_ids = [r.id for r in rules]
    serialized = [r.to_json() for r in rules]

    try:
        from app.features.attack.attack_core import get_techniques_for_rules_batch
        atk_map = get_techniques_for_rules_batch(rule_ids)
        for item in serialized:
            item['attacks'] = atk_map.get(item['id'], [])
    except Exception:
        pass

    try:
        tags_map = RuleModel.get_tags_for_rules_batch(rule_ids)
        for item in serialized:
            item['tags'] = [
                {'id': t.id, 'name': t.name, 'color': t.color, 'icon': t.icon}
                for t in tags_map.get(item['id'], [])
            ]
    except Exception:
        for item in serialized:
            item.setdefault('tags', [])

    import json as _json
    for item in serialized:
        raw = item.get('cve_id') or '[]'
        try:
            parsed = _json.loads(raw) if isinstance(raw, str) else []
            item['cves'] = parsed if isinstance(parsed, list) else []
        except Exception:
            item['cves'] = []

    if current_user.is_authenticated:
        from app.core.db_class.db import RuleVote as _RV
        votes_map = {v.rule_id: v.vote_type for v in _RV.query.filter(
            _RV.rule_id.in_(rule_ids), _RV.user_id == current_user.id
        ).all()}
        for item in serialized:
            item['user_vote'] = votes_map.get(item['id'])
    else:
        for item in serialized:
            item['user_vote'] = None

    return {'rules': serialized, 'success': True}, 200

@home_blueprint.route("/get_current_user_connected", methods=['GET'])
def get_current_user_connected() -> jsonify:
    """Is the current user an admin to vue JS"""
    if current_user.is_authenticated:
        return jsonify({"is_authenticated": True, "user_id": current_user.id})
    else:
        return jsonify({"is_authenticated": False})

######################
#   Request section  #
######################

@home_blueprint.route("/owner_request", methods=["POST", "GET"])
@login_required
def owner_request() -> redirect:
    """Get all the request to validate"""
    choice = request.args.get('choice', 1, type=int)
    if choice == 1:
        # one rule
        rule_id = request.args.get('rule_id')
        if not rule_id:
            return {"success": False, "message": "No rule with this id!" , "toast_class" : "danger-subtle"}, 200
        rule = RuleModel.get_rule(rule_id)
        if current_user.id != rule.user_id:
            request_ = AccountModel.create_request(rule_id=rule_id, source="")
            if request_:
                log_activity(
                    "user.owner_request",
                    f"Requested ownership of rule id={rule_id}",
                    target_type="rule", target_id=int(rule_id),
                    extra={"rule_id": rule_id, "choice": 1},
                    is_public=False,
                )
                try:
                    from app.features.notification.notification_core import notify_ownership_requested
                    notify_ownership_requested(request_, rule, current_user)
                except Exception as _e:
                    print(f"[home] notify_ownership_requested error: {_e}")
                return {"success": True, "message": "Ownership request submitted successfully !" , "toast_class" : "success-subtle"}, 200
        return {"success": False, "message": "You can create a request for your own rule !" , "toast_class" : "danger-subtle"}, 200
    elif choice == 2:
        # with source
        source = request.args.get('source')
        if not source:
            return {"success": False, "message": "No Source given !" , "toast_class" : "danger-subtle"}, 200
        rules = RuleModel.get_rule_by_source(source)
        if not rules:
            return {"success": False, "message": "No rule with this source!" , "toast_class" : "danger-subtle"}, 200
        created_requests = AccountModel.create_request(rule_id=None, source=source)
        log_activity(
            "user.owner_request",
            f"Requested ownership of rules from source '{source}'",
            extra={"source": source, "choice": 2},
            is_public=False,
        )
        try:
            from app.features.notification.notification_core import notify_ownership_requested
            req_list = created_requests if isinstance(created_requests, list) else [created_requests]
            for req in req_list:
                if req:
                    notify_ownership_requested(req, None, current_user)
        except Exception as _e:
            print(f"[home] notify_ownership_requested (source) error: {_e}")
        return {"success": True, "message": "Ownership request submitted successfully !" , "toast_class" : "success-subtle"}, 200
    else:
        return {"success": False, "message": "Error system" , "toast_class" : "danger-subtle"}, 500

    



@home_blueprint.route("/admin/request", methods=["POST", "GET"])
@login_required
def admin_requests() -> render_template:
    """Redirect to request section"""
    return render_template("admin/request.html")


@home_blueprint.route("/requests/<int:id>", methods=[ "GET"])
@login_required
def requests(id) -> render_template:
    """Redirect to request section"""
    return render_template("account/request_detail.html" , request_id=id)


@home_blueprint.route("/get_requests_page", methods=['GET'])
@login_required
def get_requests_page() -> json:
    """Get all the request in a page"""
    page = request.args.get('page', 1, type=int)
    if current_user.is_admin():
        requests_paginated = AccountModel.get_requests_page(page)
    else:
        requests_paginated = AccountModel.get_requests_page_user(page)
    total_requests = AccountModel.get_total_requests_to_check_admin()
    if requests_paginated.items:
        requests_list = []
        for r in requests_paginated.items:
            user = AccountModel.get_username_by_id(r.user_id)
            request_data = r.to_json()  
            
            request_data['user_name'] = user
            requests_list.append(request_data)
        return {
            "success": True,
            "pending_requests_list": requests_list,
            "pending_totalPages": requests_paginated.pages,  
        } , 200
    return {"message": "No requests found"}

@home_blueprint.route("/get_process_requests_page", methods=['GET'])
@login_required
def get_process_requests_page() -> json:
    """Get all the request in a page"""
    page = request.args.get('page', 1, type=int)
    if current_user.is_admin():
        requests_paginated = AccountModel.get_process_requests_page(page)
    else:
        requests_paginated = AccountModel.get_process_requests_page_user(page)

    if requests_paginated.items:
        requests_list = []
        for r in requests_paginated.items:
            user = AccountModel.get_username_by_id(r.user_id)
            request_data = r.to_json()  
            
            request_data['user_name'] = user
            requests_list.append(request_data)
        return {
            "success": True,
            "process_requests_list": requests_list,
            "process_totalPages": requests_paginated.pages,  
        } , 200
    return {"message": "No requests found"}


@home_blueprint.route("/get_request", methods=['GET'])
@login_required
def get_request() -> json:
    """Get the request """
    request_id = request.args.get('request_id', 1, type=int)
    request_ = AccountModel.get_request_by_id(request_id)
    if request_:
        if current_user.is_admin() or request_.user_id_to_send == current_user.id or request_.user_id == current_user.id:
            return {
                "success": True,
                "current_request": request_.to_json() 
            } , 200
        else:
            return {
                "success": False,
                "current_request": None 
            } , 200
    return {"message": "No requests found"}

@home_blueprint.route("/get_concerned_rule", methods=['GET'])
@login_required
def get_concerned_rule() -> json:
    """Get all the get_concerned_rule in a page"""
    request_id = request.args.get('request_id', 1, type=int)
    page = request.args.get('page', 1, type=int)

    request_ = AccountModel.get_request_by_id(request_id)
    
    if current_user.is_admin():
        if request_.rule_source:
            concerned_rules_list = RuleModel.get_concerned_rules_admin_page(request_.rule_source, page , request_.user_id_to_send)
            nb_rules = RuleModel.get_concerned_rule_admin_count(request_.rule_source, page , request_.user_id_to_send)
        else:
            concerned_rules_list = []
            rule = RuleModel.get_rule(request_.rule_id)
            concerned_rules_list.append(rule)
            nb_rules = 1
    else:
        if request_.rule_source:
            concerned_rules_list = RuleModel.get_concerned_rules_page(request_.rule_source, page)
            nb_rules = RuleModel.get_concerned_rule_count(request_.rule_source)
        else:
            concerned_rules_list = []
            rule = RuleModel.get_rule(request_.rule_id)
            concerned_rules_list.append(rule)
            nb_rules = 1


    if concerned_rules_list:
        return {
            "success": True,
            "concerned_rules_list": [rule.to_json() for rule in concerned_rules_list],
            "Rules_totalPages": concerned_rules_list.pages if request_.rule_source else 1,
            "total_rules": nb_rules
        } , 200
    else:
        return {
            "success": False,
            "concerned_rules_list": [] 
        } , 200


@home_blueprint.route("/get_all_concerned_rules", methods=["GET"])
@login_required
def get_all_concerned_rules():
    request_id = request.args.get("request_id", type=int)

    if not request_id:
        return jsonify({"error": "Missing request_id"}), 400

    request_ = AccountModel.get_request_by_id(request_id)
    try:
        if current_user.is_admin():
            rules = RuleModel.get_concerned_rules_admin(request_.rule_source , request_.user_id_to_send)
            if len(rules) == 0:
                # not with source but only one rule
                rule_concerned = RuleModel.get_rule(request_.rule_id)
                rules.append(rule_concerned)
            result = [rule.to_json() for rule in rules]
            return jsonify({"all_concerned_rules": result})
        else:
            rules = RuleModel.get_concerned_rules(request_.rule_source)
            result = [rule.to_json() for rule in rules]
            return jsonify({"all_concerned_rules": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@home_blueprint.route("/get_made_requests_page", methods=["GET"])
@login_required
def get_made_requests_page() -> json:
    """Get all the requests made by the user in a page"""
    page = request.args.get('page', 1, type=int)
    requests_paginated = AccountModel.get_made_requests_page(page)
    if requests_paginated:
        return {
            "success": True,
            "made_requests_list": [request_.to_json() for request_ in requests_paginated],
            "made_totalPages": requests_paginated.pages,  
        } , 200
    return {"message": "No requests found"}, 200


@home_blueprint.route("/update_request_bulk", methods=["POST"])
@login_required
def update_request_bulk() -> jsonify:
    """Dispatch an ownership_transfer_bulk background job for large transfers."""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    request_id = data.get('request_id')
    rule_ids   = data.get('rule_ids', [])

    if not request_id or not rule_ids:
        return jsonify({"success": False, "error": "Missing request_id or rule_ids"}), 400

    request_ = AccountModel.get_request_by_id(request_id)
    if not request_:
        return jsonify({"success": False, "error": "Request not found"}), 404

    is_the_owner = AccountModel.is_the_owner(request_id)
    if not (current_user.is_admin() or is_the_owner):
        return jsonify({"success": False, "error": "Forbidden"}), 403

    from app.features.jobs.jobs_core import create_job
    job = create_job(
        job_type   = 'ownership_transfer_bulk',
        payload    = {'request_id': request_id, 'rule_ids': rule_ids},
        label      = f"Ownership transfer — {len(rule_ids)} rules (request #{request_id})",
        created_by = current_user.id,
        total      = len(rule_ids),
    )
    if not job:
        return jsonify({"success": False, "error": "Failed to create job"}), 500

    log_activity(
        "admin.request_approved",
        f"Approved ownership request id={request_id} — {len(rule_ids)} rules queued for transfer",
        extra={"request_id": request_id, "job_uuid": job.uuid, "rule_count": len(rule_ids)},
    )
    return jsonify({"success": True, "job_uuid": job.uuid}), 200


@home_blueprint.route("/update_request", methods=["POST" ])
@login_required
def update_request_status() -> jsonify:
    """Update the request for vue JS"""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid or missing JSON"}), 400
    request_id = data.get('request_id')
    status = data.get('status')
    rule_ids = data.get('rule_list')

    rules = RuleModel.get_rules_by_ids(rule_ids)


    is_the_owner = AccountModel.is_the_owner(request_id)

    if current_user.is_admin() or is_the_owner:
        updated = AccountModel.update_request_status(request_id, status)
        if updated and status == "approved":
            log_activity("admin.request_approved",
                         f"Approved ownership request id={request_id} ({len(rules)} rules impacted)",
                         extra={"request_id": request_id, "rule_ids": rule_ids})
            ownership_request = AccountModel.get_request_by_id(request_id)
            for rule in rules:
                if rule.user_id == current_user.id or current_user.is_admin():
                    # Update the rule ownership
                    rule.user_id = ownership_request.user_id

                    requests_list_to_refused = AccountModel.get_all_requests_one_rule_with_rule_id(rule.id)
                    if requests_list_to_refused:
                        for request_ in requests_list_to_refused:
                            if request_.status == "pending":
                                request_.status = "rejected"
                                request_.user_id_to_send = ownership_request.user_id
                    
                    requests_list_to_refused_source = AccountModel.get_all_requests_with_source(ownership_request.rule_source)
                    if requests_list_to_refused_source:
                        for request__ in requests_list_to_refused_source:
                            if request__.status == "pending":
                                request__.status = "rejected"
                                request__.user_id_to_send = ownership_request.user_id


                    # #Save the rule with the new ownership
                    # requests_list_to_update = AccountModel.get_all_requests_with_rule_id(rule.id)
                    # if requests_list_to_update:
                    #     for request_ in requests_list_to_update:
                    #         request_.user_id_to_send = ownership_request.user_id
                    # requests_list_to_update_source = AccountModel.get_all_requests_with_source(ownership_request.rule_source)
                    # if requests_list_to_update_source:
                    #         for request__ in requests_list_to_update_source:
                    #             request__.user_id_to_send = ownership_request.user_id   
                

            try:
                from app.features.notification.notification_core import notify_ownership_decision
                ownership_request = AccountModel.get_request_by_id(request_id)
                rule_title = rules[0].title if rules else None
                notify_ownership_decision(ownership_request, approved=True, rule_title=rule_title)
            except Exception as _e:
                print(f"[home] notify_ownership_decision (approved) error: {_e}")
            flash(f"Request Accepted! {len(rules)} rules are impacted", "success")
        else:
            if updated:
                log_activity("admin.request_rejected",
                             f"Rejected ownership request id={request_id}",
                             extra={"request_id": request_id})
                try:
                    from app.features.notification.notification_core import notify_ownership_decision
                    ownership_request = AccountModel.get_request_by_id(request_id)
                    rule_title = rules[0].title if rules else None
                    notify_ownership_decision(ownership_request, approved=False, rule_title=rule_title)
                except Exception as _e:
                    print(f"[home] notify_ownership_decision (rejected) error: {_e}")
            flash('Request decline with success!', 'success')
        return jsonify({"success": updated}), 200 if updated else 400
    else:
        return jsonify({"success": False}), 500


# about us page
@home_blueprint.route("/about")
def about() -> render_template:
    return render_template("/about_us.html")

# privacy policy page
@home_blueprint.route("/privacy")
def privacy_policy() -> render_template:
    return render_template("privacy_policy.html")

# legal notice page
@home_blueprint.route("/legal")
def legal_notice() -> render_template:
    return render_template("legal_notice.html")

# version
@home_blueprint.route("/version")
def version() -> jsonify:
    version = get_version()
    return jsonify({"version": version }), 200

##############
#   ADMIN   #
#############


BACKUP_DIR = os.path.join(os.getcwd(), "backup", "dumps")

@home_blueprint.route('/admin/get_backups', methods=['GET'])
def get_backups():
    if not current_user.is_admin():
        return render_template('access_denied.html')
    return render_template('admin/download_instance.html')

@home_blueprint.route('/admin/backups', methods=['GET'])
@login_required
def list_backups():
    try:
        if not current_user.is_admin():
            return jsonify({"error": "Unauthorized"}), 401
        files = [f for f in os.listdir(BACKUP_DIR) if f.endswith('.dump')]
        files.sort(reverse=True)
        return jsonify({"files": files, "success": True, "toast_class": "success-subtle", "message": "Success"}), 200
    except Exception as e:
        return jsonify({"message": str(e), "error": str(e), "success": False, "toast_class": "danger-subtle"}), 500

@home_blueprint.route('/admin/backups/download/<filename>', methods=['GET'])
@login_required
def download_backup(filename):
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    if ".." in filename or filename.startswith("/"):
        abort(400)
    return send_from_directory(BACKUP_DIR, filename, as_attachment=True)


@home_blueprint.route('/admin/vulnerabilities/update', methods=['GET'])
@login_required
def UpdateVulnerabilities():
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized", "toast_class": "danger-subtle", "message": "Unauthorized"}), 401
    success , msg = RuleModel.migrate_rule_cve_to_json()
    if not success:
        return jsonify({"success": success, "message": msg, "toast_class": "danger-subtle"}), 500
    return jsonify({"success": success, "message": msg, "toast_class": "success-subtle"}), 200

@home_blueprint.route('/admin/similar_rules', methods=['GET'])
@login_required
def similar_rules():
    if not current_user.is_admin():
        return render_template('access_denied.html')
    return render_template('admin/similar_rule_update.html')

@home_blueprint.route("/history_logo")
def history_logo() -> render_template:
    return render_template("macros/history_logo.html")




@home_blueprint.route('/doc/<path:filename>')
def serve_doc_images(filename):
    doc_path = os.path.join(home_blueprint.root_path, '../doc')
    return send_from_directory(doc_path, filename)


######################
#   Activity Logs    #
######################

@home_blueprint.route('/admin/logs', methods=['GET'])
@login_required
def admin_logs():
    if not current_user.is_admin():
        return render_template('access_denied.html')
    return render_template('admin/logs.html')


@home_blueprint.route('/admin/get_logs_page', methods=['GET'])
@login_required
def get_logs_page():
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    from app.core.db_class.db import ActivityLog
    from app import db

    from sqlalchemy import or_
    from datetime import datetime
    page      = request.args.get('page', 1, type=int)
    per_page  = min(100, request.args.get('per_page', 25, type=int))
    search    = request.args.get('search', '', type=str).strip()
    action    = request.args.get('action', '', type=str).strip()
    category  = request.args.get('category', '', type=str).strip()
    level     = request.args.get('level', '', type=str).strip()
    user_id_f = request.args.get('user_id', None, type=int)
    sort_key  = request.args.get('sort', 'created_at', type=str)
    sort_dir  = request.args.get('dir', 'desc', type=str)
    date_from = request.args.get('date_from', '', type=str).strip()
    date_to   = request.args.get('date_to',   '', type=str).strip()

    _allowed_sorts = {'id', 'created_at', 'category', 'level', 'action'}
    if sort_key not in _allowed_sorts:
        sort_key = 'created_at'
    if sort_dir not in ('asc', 'desc'):
        sort_dir = 'desc'

    q = ActivityLog.query
    if search:
        like = f'%{search}%'
        q = q.filter(or_(
            ActivityLog.title.ilike(like),
            ActivityLog.action.ilike(like),
            ActivityLog.description.ilike(like),
        ))
    if action:
        q = q.filter(ActivityLog.action.ilike(f'%{action}%'))
    if category:
        q = q.filter(ActivityLog.category == category)
    if level:
        q = q.filter(ActivityLog.level == level)
    if user_id_f:
        q = q.filter(ActivityLog.user_id == user_id_f)
    if date_from:
        try:
            dt_from = datetime.strptime(date_from, '%Y-%m-%d')
            q = q.filter(ActivityLog.created_at >= dt_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.strptime(date_to, '%Y-%m-%d')
            # include the full day
            from datetime import timedelta
            dt_to = dt_to + timedelta(days=1)
            q = q.filter(ActivityLog.created_at < dt_to)
        except ValueError:
            pass

    sort_col = getattr(ActivityLog, sort_key)
    q = q.order_by(sort_col.asc() if sort_dir == 'asc' else sort_col.desc())

    total       = q.count()
    total_pages = max(1, (total + per_page - 1) // per_page)
    page        = min(page, total_pages)
    items       = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "items":       [l.to_json() for l in items],
        "logs":        [l.to_json() for l in items],  # backward compat
        "total":       total,
        "page":        page,
        "per_page":    per_page,
        "total_pages": total_pages,
    }), 200


@home_blueprint.route('/admin/logs/delete/<int:log_id>', methods=['POST'])
@login_required
def delete_log(log_id):
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    from app.core.db_class.db import ActivityLog
    from app import db

    entry = ActivityLog.query.get(log_id)
    if not entry:
        return jsonify({"success": False, "message": "Log not found"}), 404
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"success": True, "message": "Log deleted"}), 200


@home_blueprint.route('/admin/logs/delete_bulk', methods=['POST'])
@login_required
def delete_logs_bulk():
    """Create a background job to mass-delete logs."""
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    data   = request.get_json() or {}
    ids    = data.get('ids', [])
    all_   = data.get('delete_all', False)
    action = data.get('action_filter', '')

    if not ids and not all_:
        return jsonify({"success": False, "message": "No logs selected"}), 400

    from app.features.jobs.jobs_core import create_job
    payload = {"log_ids": ids, "delete_all": all_, "action_filter": action}
    job = create_job(
        job_type   = 'delete_activity_logs',
        payload    = payload,
        label      = f"Delete {len(ids) if ids else 'all'} activity log(s)",
        created_by = current_user.id,
    )
    if not job:
        return jsonify({"success": False, "message": "Failed to create job"}), 500

    log_activity("admin.logs_bulk_delete",
                 f"Scheduled bulk deletion of {len(ids) if ids else 'all'} log(s)",
                 extra=payload)
    return jsonify({"success": True, "message": "Deletion job queued", "job": job.to_json()}), 200


@home_blueprint.route('/activity_feed', methods=['GET'])
def activity_feed():
    """Public activity feed — only is_public=True entries whose target is still accessible."""
    from app.core.db_class.db import ActivityLog, Rule, Bundle
    from app import db

    page     = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 50)

    def _is_accessible(log):
        tt = log.target_type
        if tt == 'rule':
            r = (Rule.query.filter_by(uuid=log.target_uuid).first() if log.target_uuid
                 else Rule.query.get(log.target_id) if log.target_id else None)
            return r is not None and not r.is_deleted
        if tt == 'bundle':
            b = (Bundle.query.filter_by(uuid=log.target_uuid).first() if log.target_uuid
                 else Bundle.query.get(log.target_id) if log.target_id else None)
            return b is not None and b.access
        if tt == 'comment':
            extra = log.extra or {}
            r = (Rule.query.filter_by(uuid=extra['rule_uuid']).first() if extra.get('rule_uuid')
                 else Rule.query.get(extra['rule_id']) if extra.get('rule_id') else None)
            return r is not None and not r.is_deleted
        if tt == 'bundle_comment':
            extra = log.extra or {}
            b = (Bundle.query.filter_by(uuid=extra['bundle_uuid']).first() if extra.get('bundle_uuid')
                 else Bundle.query.get(extra['bundle_id']) if extra.get('bundle_id') else None)
            return b is not None and b.access
        if tt == 'blog_post':
            from app.core.db_class.db import BlogPost
            p = (BlogPost.query.filter_by(uuid=log.target_uuid).first() if log.target_uuid
                 else BlogPost.query.get(log.target_id) if log.target_id else None)
            return p is not None and p.is_public and not p.is_draft
        return True  # user, tag, job, github — always visible

    # Fetch a larger batch to absorb entries whose target became private/deleted
    batch_size = per_page * 4
    offset     = (page - 1) * per_page
    candidates = (ActivityLog.query
                  .filter_by(is_public=True)
                  .order_by(ActivityLog.created_at.desc())
                  .offset(offset)
                  .limit(batch_size)
                  .all())

    visible = [l for l in candidates if _is_accessible(l)][:per_page]

    return jsonify({
        "logs":        [l.to_json_public() for l in visible],
        "total":       len(visible),
        "page":        page,
        "total_pages": 1,
    }), 200


@home_blueprint.route('/admin/logs/edit/<int:log_id>', methods=['POST'])
@login_required
def edit_log(log_id):
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    from app.core.db_class.db import ActivityLog
    from app import db

    entry = ActivityLog.query.get(log_id)
    if not entry:
        return jsonify({"success": False, "message": "Log not found"}), 404

    data = request.get_json() or {}
    if 'description' in data:
        entry.description = data['description']
    if 'is_public' in data:
        entry.is_public = bool(data['is_public'])
    if 'icon' in data:
        entry.icon = data['icon']
    db.session.commit()
    return jsonify({"success": True, "log": entry.to_json()}), 200


@home_blueprint.route('/admin/logs/actions', methods=['GET'])
@login_required
def get_log_actions():
    """Return the distinct action types present in the log."""
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    from app.core.db_class.db import ActivityLog
    from app import db

    actions = [r[0] for r in db.session.query(ActivityLog.action).distinct().order_by(ActivityLog.action).all()]
    return jsonify({"actions": actions}), 200


##############################
#   Log Definitions manager  #
##############################

@home_blueprint.route('/admin/log_definitions_data', methods=['GET'])
@login_required
def get_log_definitions_data():
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    from app.features.admin import log_definitions_core as LogDefModel

    page      = request.args.get('page', 1, type=int)
    per_page  = min(100, request.args.get('per_page', 20, type=int))
    search    = request.args.get('search', '', type=str).strip()
    category  = request.args.get('category', '', type=str).strip()
    sort_key  = request.args.get('sort', 'action_key', type=str)
    sort_dir  = request.args.get('dir', 'asc', type=str)

    return jsonify(LogDefModel.list_all_actions(
        search=search, category=category, sort_key=sort_key, sort_dir=sort_dir,
        page=page, per_page=per_page,
    )), 200


@home_blueprint.route('/admin/log_definitions/save', methods=['POST'])
@login_required
def save_log_definition():
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    from app.features.admin import log_definitions_core as LogDefModel

    data       = request.get_json() or {}
    action_key = (data.get('action_key') or '').strip()
    if not action_key:
        return jsonify({"success": False, "message": "action_key is required"}), 400

    row = LogDefModel.save_override(
        action_key = action_key,
        icon       = data.get('icon'),
        title      = data.get('title'),
        is_public  = data.get('is_public'),
        user_id    = current_user.id,
    )
    log_activity('admin.settings_changed', f"Customized log display for action '{action_key}'",
                 extra={'action_key': action_key})
    return jsonify({"success": True, "definition": row}), 200


@home_blueprint.route('/admin/log_definitions/reset', methods=['POST'])
@login_required
def reset_log_definition():
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    from app.features.admin import log_definitions_core as LogDefModel

    data       = request.get_json() or {}
    action_key = (data.get('action_key') or '').strip()
    if not action_key:
        return jsonify({"success": False, "message": "action_key is required"}), 400

    ok = LogDefModel.reset_override(action_key)
    return jsonify({"success": ok}), 200


###########################
#   Admin Settings section #
###########################

@home_blueprint.route('/admin/settings', methods=['GET'])
@login_required
def admin_settings():
    if not current_user.is_admin():
        abort(403)
    return render_template('admin/settings.html')


@home_blueprint.route('/admin/settings/system', methods=['GET'])
@login_required
def admin_settings_system():
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    from .features.admin import admin_core as AdminModel
    return jsonify(AdminModel.get_system_info())


@home_blueprint.route('/admin/settings/packages', methods=['GET'])
@login_required
def admin_settings_packages():
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    from .features.admin import admin_core as AdminModel
    return jsonify(AdminModel.get_installed_packages())


@home_blueprint.route('/admin/settings/submodules', methods=['GET'])
@login_required
def admin_settings_submodules():
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    from .features.admin import admin_core as AdminModel
    return jsonify(AdminModel.get_git_submodules())


@home_blueprint.route('/admin/settings/submodule/update', methods=['POST'])
@login_required
def admin_settings_submodule_update():
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    from .features.admin import admin_core as AdminModel
    data = request.get_json() or {}
    paths = data.get('paths', [])
    if not paths:
        return jsonify({'success': False, 'error': 'No paths provided'}), 400
    results = {path: AdminModel.update_submodule(path) for path in paths}
    log_activity('admin.submodule_update', f"Updated {len(paths)} submodule(s): {', '.join(paths)}")
    return jsonify({'success': True, 'results': results})


@home_blueprint.route('/admin/settings/config', methods=['GET'])
@login_required
def admin_settings_config():
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    from .features.admin import admin_core as AdminModel
    return jsonify(AdminModel.get_app_config())


@home_blueprint.route('/admin/settings/update_env', methods=['POST'])
@login_required
def admin_settings_update_env():
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    from .features.admin import admin_core as AdminModel
    data = request.get_json() or {}
    key = data.get('key', '').strip()
    value = data.get('value', '').strip()
    if key not in AdminModel._ENV_ALLOWED:
        return jsonify({'success': False, 'message': 'Key not allowed.'})
    ok = AdminModel.write_env_value(key, value)
    if ok:
        # Apply immediately to running config for everything except SECRET_KEY
        _NEEDS_RESTART = {'SECRET_KEY'}
        if key not in _NEEDS_RESTART:
            if key == 'MAIL_PORT' or key == 'FLASK_PORT':
                try:
                    current_app.config[key] = int(value)
                except ValueError:
                    pass
            elif key == 'MAIL_USE_TLS' or key == 'MAIL_USE_SSL':
                current_app.config[key] = value.lower() == 'true'
            else:
                current_app.config[key] = value
            # Keys read straight from os.environ (e.g. GITHUB_TOKEN in the
            # GitHub API helpers) need the process env updated too, not just
            # current_app.config, or "applied immediately" would be a lie.
            os.environ[key] = value
        log_activity(
            'admin.settings_changed',
            f"Updated {key} via admin settings",
            extra={'key': key, 'requires_restart': key in _NEEDS_RESTART},
        )
    needs_restart = key == 'SECRET_KEY'
    msg = ('Saved. Restart the server to apply the new SECRET_KEY.' if needs_restart and ok
           else 'Saved and applied.' if ok
           else 'Key not allowed or write failed.')
    return jsonify({'success': ok, 'message': msg})


@home_blueprint.route('/admin/settings/test_email', methods=['POST'])
@login_required
def admin_settings_test_email():
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    from .features.admin import admin_core as AdminModel
    data = request.get_json() or {}
    recipient = data.get('recipient', '').strip()
    if not recipient:
        return jsonify({'success': False, 'error': 'No recipient provided'}), 400
    result = AdminModel.send_test_email(recipient)
    if result.get('success'):
        log_activity('admin.test_email_sent', f"Test email sent to {recipient}")
    return jsonify(result)


@home_blueprint.route('/admin/settings/generate_key', methods=['POST'])
@login_required
def admin_settings_generate_key():
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    from .features.admin import admin_core as AdminModel
    key = AdminModel.generate_secret_key()
    return jsonify({'success': True, 'key': key})


@home_blueprint.route('/admin/settings/instance', methods=['GET'])
@login_required
def admin_settings_instance():
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    from .core.db_class.db import InstanceConfig
    cfg = InstanceConfig.query.first()
    if not cfg:
        return jsonify({'exists': False})
    reported_url = cfg.public_url or (
        f"http://{current_app.config.get('FLASK_URL', '127.0.0.1')}"
        f":{current_app.config.get('FLASK_PORT', 7009)}"
    )
    return jsonify({
        'exists':            True,
        'endpoint_uuid':     cfg.uuid,
        'telemetry_enabled': cfg.telemetry_enabled,
        'public_url':        cfg.public_url,
        'reported_url':      reported_url,
        'version':           cfg.version,
        'last_started_at':   cfg.last_started_at.strftime('%Y-%m-%d %H:%M:%S') if cfg.last_started_at else None,
        'created_at':        cfg.created_at.strftime('%Y-%m-%d %H:%M:%S') if cfg.created_at else None,
        'is_official':       current_app.config.get('IS_OFFICIAL_INSTANCE', False),
        'telemetry_url':     'https://rulezet.org/api/instance/register',
    })


@home_blueprint.route('/admin/settings/instance/init', methods=['POST'])
@login_required
def admin_settings_instance_init():
    """Generate / refresh endpoint_uuid, version, last_started_at in InstanceConfig."""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    import uuid as _uuid_mod
    import datetime as _dt
    from app import db
    from .core.db_class.db import InstanceConfig
    from .core.utils.activity_log import log_activity

    cfg = InstanceConfig.query.first()
    if not cfg:
        cfg = InstanceConfig(
            uuid=str(_uuid_mod.uuid4()),
            telemetry_enabled=True,
            public_url=current_app.config.get('INSTANCE_PUBLIC_URL'),
        )
        db.session.add(cfg)
        db.session.flush()

    reported_url = cfg.public_url or (
        f"http://{current_app.config.get('FLASK_URL', '127.0.0.1')}"
        f":{current_app.config.get('FLASK_PORT', 7009)}"
    )
    cfg.uuid            = str(_uuid_mod.uuid5(_uuid_mod.NAMESPACE_URL, reported_url))
    cfg.version         = current_app.config.get('APP_VERSION', 'unknown')
    cfg.last_started_at = _dt.datetime.utcnow()
    db.session.commit()
    log_activity('admin.instance_init', 'Instance config initialized/refreshed from admin settings')
    return jsonify({
        'success':         True,
        'endpoint_uuid':   cfg.uuid,
        'version':         cfg.version,
        'last_started_at': cfg.last_started_at.strftime('%Y-%m-%d %H:%M:%S'),
    })


@home_blueprint.route('/platform/insights')
def platform_insights():
    return render_template('platform/stats.html')


@home_blueprint.route('/platform/insights_data')
def platform_insights_data():
    import datetime
    from collections import defaultdict
    from sqlalchemy import func
    from app.core.db_class.db import (
        Rule, Bundle, User, Tag, Comment, RuleVote,
        RuleEditProposal, ActivityLog, RuleTagAssociation,
    )
    from app import db

    now = datetime.datetime.utcnow()

    # ── KPIs ──────────────────────────────────────────────────────────
    total_rules     = Rule.query.filter_by(is_deleted=False).count()
    total_deleted   = Rule.query.filter_by(is_deleted=True).count()
    total_bundles   = Bundle.query.count()
    total_users     = User.query.count()
    online_users    = User.query.filter_by(is_connected=True).count()
    admin_users     = User.query.filter_by(admin=True).count()
    total_tags      = Tag.query.count()
    total_comments  = Comment.query.count()
    total_votes     = RuleVote.query.count()
    total_proposals = RuleEditProposal.query.count()
    total_activity  = ActivityLog.query.count()

    # Distinct CVE ids referenced across all active rules (cve_id is a JSON-
    # encoded list column) — same parsing convention as /home_charts/top_cve.
    _cve_set = set()
    for (_raw,) in db.session.query(Rule.cve_id).filter(
        Rule.is_deleted == False, Rule.cve_id.isnot(None),
        Rule.cve_id != '[]', Rule.cve_id != '',
    ).all():
        try:
            _cve_set.update(json.loads(_raw) or [])
        except Exception:
            pass
    total_cves = len(_cve_set)

    # ── Monthly helper (Python-side grouping, DB-agnostic) ─────────────
    def monthly(date_col, months=12, extra_filter=None):
        cutoff = now - datetime.timedelta(days=months * 31)
        q = db.session.query(date_col)
        if extra_filter is not None:
            q = q.filter(extra_filter)
        q = q.filter(date_col >= cutoff)
        rows = [r[0] for r in q.all()]

        bucket = defaultdict(int)
        for dt in rows:
            if dt:
                if isinstance(dt, str):
                    try: dt = datetime.datetime.fromisoformat(dt)
                    except: continue
                bucket[dt.strftime('%Y-%m')] += 1

        labels = []
        d = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        for _ in range(months):
            labels.append(d.strftime('%Y-%m'))
            d = (d - datetime.timedelta(days=1)).replace(day=1)
        labels.reverse()

        nice = []
        for l in labels:
            try: nice.append(datetime.datetime.strptime(l, '%Y-%m').strftime('%b %Y'))
            except: nice.append(l)
        return nice, [bucket.get(l, 0) for l in labels]

    rule_cats,     rule_vals     = monthly(Rule.creation_date,    extra_filter=Rule.is_deleted == False)
    user_cats,     user_vals     = monthly(User.created_at)
    bundle_cats,   bundle_vals   = monthly(Bundle.created_at)
    activity_cats, activity_vals = monthly(ActivityLog.created_at)

    # ── Rules by format ────────────────────────────────────────────────
    fmt_rows = (db.session.query(Rule.format, func.count(Rule.id))
                .filter(Rule.is_deleted == False)
                .group_by(Rule.format)
                .order_by(func.count(Rule.id).desc())
                .limit(15).all())
    fmt_cats = [r[0] or 'Unknown' for r in fmt_rows]
    fmt_vals = [r[1] for r in fmt_rows]

    # ── Top tags ───────────────────────────────────────────────────────
    tag_rows = (db.session.query(Tag.name, func.count(RuleTagAssociation.id))
                .join(RuleTagAssociation, RuleTagAssociation.tag_id == Tag.id)
                .group_by(Tag.id, Tag.name)
                .order_by(func.count(RuleTagAssociation.id).desc())
                .limit(15).all())
    tag_cats = [r[0] for r in tag_rows]
    tag_vals = [r[1] for r in tag_rows]

    # ── Top contributors ───────────────────────────────────────────────
    contrib_rows = (db.session.query(User.first_name, func.count(Rule.id))
                    .join(Rule, Rule.user_id == User.id)
                    .filter(Rule.is_deleted == False)
                    .group_by(User.id, User.first_name)
                    .order_by(func.count(Rule.id).desc())
                    .limit(10).all())
    contrib_cats = [r[0] or 'Unknown' for r in contrib_rows]
    contrib_vals = [r[1] for r in contrib_rows]

    # ── Proposal status ────────────────────────────────────────────────
    prop_rows = (db.session.query(RuleEditProposal.status, func.count(RuleEditProposal.id))
                 .group_by(RuleEditProposal.status).all())
    prop_cats = [r[0] or 'unknown' for r in prop_rows]
    prop_vals = [r[1] for r in prop_rows]

    # ── Activity heatmap (last 90 days — day-of-week × hour) ──────────
    cutoff_90 = now - datetime.timedelta(days=90)
    act_rows  = (db.session.query(ActivityLog.created_at)
                 .filter(ActivityLog.created_at >= cutoff_90).all())
    hm = defaultdict(lambda: defaultdict(int))
    for (dt,) in act_rows:
        if dt:
            if isinstance(dt, str):
                try: dt = datetime.datetime.fromisoformat(dt)
                except: continue
            hm[dt.weekday()][dt.hour] += 1

    days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    heatmap_series = [
        {'name': days[d], 'values': [hm[d][h] for h in range(24)]}
        for d in range(7)
    ]
    heatmap_cats = [f'{h:02d}h' for h in range(24)]

    # ── MITRE ATT&CK coverage ──────────────────────────────────────────
    attack_kpi = {'techniques': 0, 'rules_covered': 0, 'coverage_pct': 0, 'total_assocs': 0}
    attack_charts = {}
    try:
        from app.features.attack.attack_core import get_analytics_data as _atk_analytics
        atk = _atk_analytics()
        tc  = atk.get('tactic_coverage', [])
        tot = sum(x['total'] for x in tc)
        cov = sum(x['covered'] for x in tc)
        attack_kpi = {
            'techniques':   tot,
            'rules_covered': sum(x['rule_count'] for x in tc),
            'coverage_pct': round(cov / tot * 100, 1) if tot else 0,
            'total_assocs': sum(x['rule_count'] for x in tc),
        }
        top = atk.get('top_techniques', [])
        attack_charts = {
            'top_techniques': {
                'title': 'Top Techniques',
                'subtitle': 'by rule count',
                'categories': [x['id'] + ' — ' + x['name'][:28] for x in top[:15]],
                'series': [{'name': 'Rules', 'values': [x['count'] for x in top[:15]]}],
            },
            'tactic_coverage': {
                'title': 'Coverage % per Tactic',
                'categories': [x['label'] for x in tc],
                'series': [{'name': 'Coverage %', 'values': [x['pct'] for x in tc]}],
            },
            'tactic_rules': {
                'title': 'Rule Associations by Tactic',
                'categories': [x['label'] for x in tc if x['rule_count'] > 0],
                'series': [{'values': [x['rule_count'] for x in tc if x['rule_count'] > 0]}],
            },
            'covered_donut': {
                'title': 'Techniques Covered',
                'categories': ['Covered', 'Uncovered'],
                'series': [{'values': [cov, tot - cov]}],
            },
        }
    except Exception:
        pass

    def chart(title, cats, vals, subtitle=None):
        c = {'title': title, 'categories': cats, 'series': [{'name': title, 'values': vals}]}
        if subtitle: c['subtitle'] = subtitle
        return c

    return jsonify({
        'kpi': {
            'total_rules':     total_rules,
            'total_deleted':   total_deleted,
            'total_bundles':   total_bundles,
            'total_users':     total_users,
            'online_users':    online_users,
            'admin_users':     admin_users,
            'total_tags':      total_tags,
            'total_cves':      total_cves,
            'total_comments':  total_comments,
            'total_votes':     total_votes,
            'total_proposals': total_proposals,
            'total_activity':  total_activity,
        },
        'charts': {
            'rules_over_time':    {'title': 'Rules Added', 'subtitle': 'Last 12 months', 'categories': rule_cats,     'series': [{'name': 'Rules',    'values': rule_vals}]},
            'users_over_time':    {'title': 'New Users',   'subtitle': 'Last 12 months', 'categories': user_cats,     'series': [{'name': 'Users',    'values': user_vals}]},
            'bundles_over_time':  {'title': 'Bundles Created', 'subtitle': 'Last 12 months', 'categories': bundle_cats,   'series': [{'name': 'Bundles',  'values': bundle_vals}]},
            'activity_over_time': {'title': 'Platform Events', 'subtitle': 'Last 12 months', 'categories': activity_cats, 'series': [{'name': 'Events',   'values': activity_vals}]},
            'formats':    chart('Rules by Format',    fmt_cats,     fmt_vals),
            'top_tags':   chart('Top Tags',           tag_cats,     tag_vals,     'by rule count'),
            'top_contribs': chart('Top Contributors', contrib_cats, contrib_vals, 'by active rules'),
            'proposals':  {'title': 'Edit Proposals', 'categories': prop_cats, 'series': [{'name': 'Proposals', 'values': prop_vals}]},
            'rule_health':  {'title': 'Rule Health',  'categories': ['Active', 'Deleted'], 'series': [{'name': 'Rules', 'values': [total_rules, total_deleted]}]},
            'user_roles':   {'title': 'User Roles',   'categories': ['Regular', 'Admins'],  'series': [{'name': 'Users', 'values': [total_users - admin_users, admin_users]}]},
            'heatmap': {'title': 'Activity Heatmap', 'subtitle': 'Last 90 days — hour × day', 'categories': heatmap_cats, 'series': heatmap_series},
            'attack_top_techniques': attack_charts.get('top_techniques', {}),
            'attack_tactic_coverage': attack_charts.get('tactic_coverage', {}),
            'attack_tactic_rules': attack_charts.get('tactic_rules', {}),
            'attack_covered_donut': attack_charts.get('covered_donut', {}),
        },
        'attack_kpi': attack_kpi,
    })


@home_blueprint.route('/admin/logs/set_visibility', methods=['POST'])
@login_required
def set_logs_visibility():
    """Bulk-set is_public on a list of activity log entries."""
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    from app.core.db_class.db import ActivityLog
    from app import db

    data      = request.get_json() or {}
    ids       = data.get('ids', [])
    is_public = bool(data.get('is_public', False))

    if not ids:
        return jsonify({"success": False, "message": "No IDs provided"}), 400

    updated = ActivityLog.query.filter(ActivityLog.id.in_(ids)).update(
        {"is_public": is_public}, synchronize_session=False
    )
    db.session.commit()
    return jsonify({"success": True, "updated": updated}), 200