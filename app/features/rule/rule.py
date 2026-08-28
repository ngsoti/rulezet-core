import base64
import io
import json
import zipfile
import os
import tempfile
from threading import Thread
from flask import  request, send_file, current_app
from math import ceil
from urllib.parse import urlparse
from datetime import datetime,  timezone

from app.features.misp.rule.misp_object import content_convert_to_misp_object, get_rule_misp_event, get_rule_misp_event, get_rule_misp_object
from .rule_form import AddNewRuleForm, CreateFormatRuleForm, EditRuleForm
from app.core.utils.utils import  bump_version, form_to_dict, generate_side_by_side_diff_html, safe_referrer

from app.features.account.account_core import add_favorite, remove_favorite, is_rule_favorited_by_user
from app.features.misp.misp_core import  convert_misp_to_stix
from app.features.rule.rule_format.main_format import  parse_rule_by_format, process_and_import_fixed_rule, verify_syntax_rule_by_format
from app.features.rule.rule_format.utils_format.utils_import_update import clone_or_access_repo, fill_all_void_field, get_github_branches, get_licst_license, git_pull_repo, github_repo_metadata, valider_repo_github

from app import db
from . import rule_core as RuleModel
from ..bundle import bundle_core as BundleModel
from .rule_from_github.import_rule import session_class as SessionModel
from app.core.utils.activity_log import log_activity
from .rule_from_github.update_rule import update_class as UpdateModel
from .utils.similar_rules import similarity_class as SimilarityModel
from ..account import account_core as AccountModel
from .exporters.velociraptor_exporter import generate_velociraptor_artifact, SUPPORTED_FORMATS as VELOCIRAPTOR_SUPPORTED_FORMATS
from .exporters.sigma_convert_exporter import convert_sigma_rule, SIGMA_CONVERT_TARGETS


################################################################################################### 
# Rules_core

from .rules_core import bad_rule_core as BadRuleModel

################################################################################################### 

from flask import Blueprint, Response, jsonify, redirect, request, render_template, flash, url_for, stream_with_context
from flask_login import current_user, login_required

rule_blueprint = Blueprint(
    'rule',
    __name__,
    template_folder='templates',    
    static_folder='static'
)

#####################
#   Rule List       #
#####################

@rule_blueprint.route("/create_rule", methods=['GET', 'POST'])
@login_required
def rule() -> render_template:
    """Create a new rule"""
    # init form

    form = AddNewRuleForm()
    licenses = get_licst_license()
    form.license.choices = [(lic, lic) for lic in licenses]

    # form send to treatment

    if form.validate_on_submit():
        form_dict = form_to_dict(form)
        rule_dict = fill_all_void_field(form_dict)
        
        # try to compile or verify the syntax of the rule (in the format choose)
        valide , error = verify_syntax_rule_by_format(rule_dict)

        if valide == False:
                return render_template("rule/rule.html", error=error, form=form)

        v_data = request.form.get('vulnerabilities')
        form_dict['vulnerabilities'] = v_data

        t_data = request.form.get('tags')
        try:
            rule_dict['tags'] = json.loads(t_data) if t_data else []
        except json.JSONDecodeError:
            rule_dict['tags'] = []

        new_rule, message = RuleModel.add_rule_core(rule_dict, current_user)
        if new_rule:
            profil_game_user = AccountModel.get_or_create_gamification_profile(current_user.id)
            if profil_game_user:
                AccountModel.update_rules_owned_gamification(profil_game_user.id, current_user.id)

            a_data = request.form.get('attacks')
            if a_data:
                try:
                    from app.features.attack.attack_core import add_technique_to_rule as _add_atk
                    for atk in json.loads(a_data):
                        tid = atk.get('technique_id') or atk.get('id')
                        if tid:
                            _add_atk(new_rule.id, tid, current_user.id, source='manual')
                except Exception:
                    pass

            flash('Rule added !', 'success')
            return redirect(url_for('rule.detail_rule', rule_id=new_rule.id))
        elif isinstance(message, str) and message.startswith("TRASH_CONFLICT:"):
            # Rule exists in the trash — offer to restore it
            parts   = message.split(":", 3)
            t_uuid  = parts[1] if len(parts) > 1 else ''
            t_id    = parts[2] if len(parts) > 2 else ''
            t_title = parts[3] if len(parts) > 3 else 'deleted rule'
            flash(f'TRASH_CONFLICT:{t_uuid}:{t_id}:{t_title}', 'warning')
            return render_template("rule/rule.html", form=form)
        else:
            flash(message, 'danger')
            return render_template("rule/rule.html", form=form)
    return render_template("rule/rule.html", form=form )


@rule_blueprint.route("/rules_list", methods=['GET'])
def rules_list() -> render_template:   
    """Redirect to rules list"""     

    # filter by search in the url
    url_filters = request.args.to_dict()


    return render_template("rule/rules_list.html", url_filters=url_filters)

# without search
@rule_blueprint.route("/get_rules_page", methods=['GET'])
def get_rules_page() -> jsonify:
    """Get all the rules on a page"""
    page = request.args.get('page', 1, type=int)
    rules = RuleModel.get_rules_page(page)
    total_rules = RuleModel.get_total_rules_count()  

    if rules:
        rules_list = list()
        for rule in rules:
            u = rule.to_json()
            rules_list.append(u)

        return {"rule": rules_list, "total_pages": rules.pages, "total_rules": total_rules}
    
    return {"message": "No Rule"}


# @rule_blueprint.route("/get_similar_rule", methods=["GET"])
# def get_similar_rules() -> jsonify:
#     """
#     Return similar rules with similarity index
#     """

#     rule_id = request.args.get("rule_id", type=int)

#     if not rule_id:
#         return jsonify({
#             "message": "Missing rule_id",
#             "similar_rules": []
#         }), 400

#     similar_rules = RuleModel.get_similar_rule(rule_id)

#     if not similar_rules:
#         return jsonify({
#             "message": "No similar rules found",
#             "similar_rules": []
#         }), 200

#     return jsonify({
#         "message": "Success",
#         "similar_rules": similar_rules
#     }), 200


@rule_blueprint.route("/get_rules_page_filter_with_id", methods=['GET'])
def get_rules_page_with_user_id() -> jsonify:
    """Get all the rules on a page"""
    page = request.args.get('page', 1, type=int)
    user_id = request.args.get('userId', 1, type=int)

    sort_by = request.args.get("sort_by", "newest")
    search = request.args.get("search", None)
    rule_type = request.args.get("rule_type", None)
    

    rules = RuleModel.get_rules_of_user_with_id_page(user_id, page, search, sort_by, rule_type)

    if rules and rules.items:  
        rules_list = [rule.to_json() for rule in rules.items]

        return {
            "success": True,
            "rule": rules_list,
            "total_pages": rules.pages,
            "total_rules": rules.total
        }, 200

    return {"message": "No Rule"}, 200

# get page with filter
@rule_blueprint.route("/get_rules_page_filter", methods=['GET'])
def get_rules_page_filter() -> jsonify:
    """Get all the rules with filter"""
    page = int(request.args.get("page", 1))
    per_page = 10
    
    search = request.args.get("search", None)
    search_field = request.args.get("search_field", "all") # 'all', 'title', 'content'
    exact_match = request.args.get("exact_match", False)
    if exact_match == "true":
        exact_match = True
    
    sort_by = request.args.get("sort_by", "newest")
    rule_type = request.args.get("rule_type", None)
    source = request.args.get("sources", None)
    user_id = request.args.get("user_id", None)
    license = request.args.get("licenses", None)

    vuln_raw = request.args.get("vulnerabilities", type=str)
    vuln_list = [v.strip() for v in vuln_raw.split(',') if v.strip()] if vuln_raw else []

    tag_raw = request.args.get("tags", type=str)
    tag_list = [t.strip() for t in tag_raw.split(',') if t.strip()] if tag_raw else []

    authors_raw = request.args.get("authors", type=str)
    authors_list = [v.strip() for v in authors_raw.split(',') if v.strip()] if authors_raw else None
    single_author = request.args.get("author", None)
    author_filter = authors_list or ([single_author] if single_author else None)

    editors_raw = request.args.get("editors", type=str)
    editor_names = [v.strip() for v in editors_raw.split(',') if v.strip()] if editors_raw else None

    query = RuleModel.filter_rules(
        search=search,
        search_field=search_field,
        author=author_filter,
        sort_by=sort_by,
        rule_type=rule_type,
        vulnerabilities=vuln_list,
        source=source,
        user_id=user_id,
        license=license,
        tags=tag_list,
        exact_match=exact_match,
        editor_names=editor_names,
    )
    
    total_rules = query.count()
    rules = query.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "rule": [r.to_json() for r in rules],
        "total_rules": total_rules,
        "total_pages": ceil(total_rules / per_page)
    }), 200


#####################
#   Action on Rule  # 
#####################

@rule_blueprint.route("/delete_rule", methods=['POST'])
@login_required
def delete_rule() -> jsonify:
    """Delete a rule"""
    data = request.get_json() or {}
    rule_id  = data.get("id")
    user_id = RuleModel.get_rule_user_id(rule_id)

    if current_user.id == user_id or current_user.is_admin():
        rule_obj = RuleModel.get_rule(rule_id)
        rule_title = rule_obj.title if rule_obj else str(rule_id)
        success = RuleModel.soft_delete_rule(rule_id, current_user.id)
        if not success:
            return jsonify({"success": False, "message": "Failed to delete the rule!",
                            "toast_class" : "danger"}), 400

        profil_game_user = AccountModel.get_or_create_gamification_profile(user_id)
        if profil_game_user:
            _ = AccountModel.update_rules_owned_gamification(profil_game_user.id, user_id)
        log_activity("rule.delete", f"Deleted rule '{rule_title}' (id={rule_id})",
                     extra={"rule_id": rule_id})
        return {"success": True, "message": "Rule moved to trash!" , "toast_class" : "success"}, 200
    
    return render_template("access_denied.html")

@rule_blueprint.route("/get_current_user", methods=['GET'])
def get_current_user() -> jsonify:
    """Is the current user admin or not for vue js"""
    return jsonify({'user': current_user.is_admin()})

@rule_blueprint.route('/vote_rule', methods=['POST'])
@login_required
def vote_rule() -> jsonify:
    """Update the vote up or down"""
    data = request.get_json() or {}
    rule_id   = int(data.get('id', 0))
    vote_type = str(data.get('vote_type', ''))

    if vote_type not in ('up', 'down'):
        return jsonify({"message": "Invalid vote type"}), 400

    result = RuleModel.process_vote(rule_id, current_user.id, vote_type)
    if result is None:
        return jsonify({"message": "Rule not found"}), 404

    vote_up, vote_down, like_delta, dislike_delta = result

    voter_gamif = AccountModel.get_or_create_gamification_profile(current_user.id)
    rule = RuleModel.get_rule(rule_id)
    if voter_gamif and rule:
        AccountModel.apply_vote_gamification(voter_gamif.id, rule.user_id, like_delta, dislike_delta)

    log_activity(f"rule.vote_{vote_type}", f"Voted {vote_type} on rule id={rule_id}",
                 target_type="rule", target_id=rule_id,
                 target_uuid=rule.uuid if rule else None)

    from app.core.db_class.db import RuleVote as _RuleVote
    new_vote = _RuleVote.query.filter_by(rule_id=rule_id, user_id=current_user.id).first()
    user_vote = new_vote.vote_type if new_vote else None

    return jsonify({
        'vote_up': vote_up,
        'vote_down': vote_down,
        'user_vote': user_vote,
        'message': 'Vote updated successfully',
        'toast_class': 'success-subtle'
    }), 200


VOTERS_PREVIEW_CAP = 50

@rule_blueprint.route('/voters/<int:rule_id>', methods=['GET'])
def rule_voters(rule_id):
    """List the users who voted up/down on a rule (hover popover)."""
    vote_type = request.args.get('type', 'up')
    if vote_type not in ('up', 'down'):
        return jsonify({"message": "Invalid vote type"}), 400

    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return jsonify({"message": "Rule not found"}), 404

    from app.core.db_class.db import RuleVote as _RuleVote
    q = (_RuleVote.query.filter_by(rule_id=rule_id, vote_type=vote_type)
         .order_by(_RuleVote.created_at.desc()))
    total = q.count()
    users = [{
        'id':       v.user.id,
        'username': v.user.get_username(),
        'avatar':   v.user.get_avatar_url(),
    } for v in q.limit(VOTERS_PREVIEW_CAP).all() if v.user]

    return jsonify({'users': users, 'total': total}), 200



@rule_blueprint.route("/edit_rule/<int:rule_id>", methods=['GET' , 'POST'])
@login_required
def edit_rule(rule_id) -> render_template:
    """Edit a rule"""
    rule = RuleModel.get_rule(rule_id)
    user_id = RuleModel.get_rule_user_id(rule_id)

    is_owner_or_admin = current_user.id == user_id or current_user.is_admin()
    # A non-owner holding rule.tag_any may still reach this page, but only to
    # touch tags/CVEs/ATT&CK — every other field is rendered disabled and,
    # more importantly, this branch below never reads title/format/license/
    # description/source/version/to_string from the request at all, so a
    # crafted POST bypassing the disabled fields client-side still can't
    # touch anything outside that scope.
    restricted_edit = not is_owner_or_admin and current_user.has_permission('rule.tag_any')

    if restricted_edit:
        if request.method == 'POST':
            old_snapshot = RuleModel.rule_metadata_snapshot(rule)

            RuleModel.apply_restricted_metadata_edit(
                rule_id, current_user.id,
                request.form.get('tags'),
                request.form.get('vulnerabilities'),
            )
            RuleModel.add_contributor(current_user.id, rule_id)

            new_snapshot = RuleModel.rule_metadata_snapshot(rule)
            if new_snapshot != old_snapshot:
                log_activity("rule.quick_meta", f"Updated tags/vulnerabilities on rule '{rule.title}' (id={rule_id})",
                             target_type="rule", target_id=rule_id, target_uuid=rule.uuid)
                RuleModel.create_rule_history({
                    "id": rule_id,
                    "title": rule.title,
                    "success": True,
                    "manual_submit": False,
                    "message": "Tags/vulnerabilities updated",
                    "new_content": rule.to_string,
                    "old_content": rule.to_string,
                    "old_snapshot": old_snapshot,
                    "new_snapshot": new_snapshot,
                    "change_type": "metadata",
                })

            flash("Tags and vulnerabilities updated!", "success")
            return redirect(url_for('rule.detail_rule', rule_id=rule.id))

        form = EditRuleForm()
        licenses = get_licst_license()
        form.license.choices = [(lic, lic) for lic in licenses]
        form.format.data = rule.format
        form.source.data = rule.source
        form.title.data = rule.title
        form.description.data = rule.description
        form.license.data = rule.license
        form.cve_id.data = rule.cve_id
        form.version.data = rule.version
        form.to_string.data = rule.to_string
        form.original_uuid.data = rule.original_uuid
        return render_template("rule/edit_rule.html", form=form, rule=rule, restricted_edit=True)

    if is_owner_or_admin:
        form = EditRuleForm()
        licenses = get_licst_license()
        form.license.choices = [(lic, lic) for lic in licenses]


        if form.validate_on_submit():
            
            form_dict = form_to_dict(form)

            form_dict['to_string'] = form_dict['to_string'].replace('\r\n', '\n').replace('\r', '\n')
            # EditRuleForm has no author field — preserve the rule's existing
            # author instead of letting fill_all_void_field default it to
            # whoever is currently editing.
            form_dict['author'] = rule.author
            rule_dict = fill_all_void_field(form_dict)
           
            
            valide , error = verify_syntax_rule_by_format(rule_dict)
            if not valide:
                form.to_string.errors.append(f"Syntax Error: {error}")
                return render_template("rule/edit_rule.html",error=error, form=form, rule=rule)
            
            

            
            # create an history for the rule

            content_changed = rule.to_string.strip() != form_dict['to_string'].strip()
            old_snapshot = RuleModel.rule_metadata_snapshot(rule)
            history = None

            if content_changed:
                if rule_dict["version"] == rule.version:
                    rule_dict["version"] = bump_version(rule_dict["version"])
                result = {
                    "id": rule_id,
                    "title": rule.title,
                    "success": True,
                    "manual_submit": True,
                    "message": "simple edit",
                    "new_content": form_dict['to_string'],
                    "old_content": rule.to_string,
                    "old_snapshot": old_snapshot,
                }
                history_id = RuleModel.create_rule_history(result)
                history = RuleModel.get_history_rule_by_id(history_id)
                history.message = "accepted"

            v_data = request.form.get('vulnerabilities')
            form_dict['vulnerabilities'] = v_data

            t_data = request.form.get('tags')
            try:
                rule_dict['tags'] = json.loads(t_data) if t_data else []
            except json.JSONDecodeError:
                rule_dict['tags'] = []

            success , current_rule = RuleModel.edit_rule_core(rule_dict, rule_id)
            log_activity("rule.edit", f"Edited rule '{current_rule.title}' (id={rule_id})",
                         target_type="rule", target_id=rule_id, target_uuid=current_rule.uuid)

            # Someone other than the owner (an admin, typically) touched this
            # rule — credit them as a contributor.
            if current_user.id != current_rule.user_id:
                RuleModel.add_contributor(current_user.id, rule_id)

            new_snapshot = RuleModel.rule_metadata_snapshot(current_rule)
            metadata_changed = new_snapshot != old_snapshot

            if history is not None:
                # Content already tracked above — attach the metadata diff to the same version.
                history.new_snapshot = new_snapshot
                history.change_type = "mixed" if metadata_changed else "content"
                db.session.commit()
            elif metadata_changed:
                # No content change, but title/author/owner/tags/etc changed — still worth a version.
                # manual_submit=False: was_last_history_manuel() gates GitHub
                # auto-sync on this flag and a metadata-only edit shouldn't
                # block future content syncs for the rule.
                RuleModel.create_rule_history({
                    "id": rule_id,
                    "title": current_rule.title,
                    "success": True,
                    "manual_submit": False,
                    "message": "Metadata updated",
                    "new_content": current_rule.to_string,
                    "old_content": current_rule.to_string,
                    "old_snapshot": old_snapshot,
                    "new_snapshot": new_snapshot,
                    "change_type": "metadata",
                })

            flash("Rule modified with success!", "success")

            return redirect(url_for('rule.detail_rule', rule_id=current_rule.id))
        else:
            form.format.data = rule.format
            form.source.data = rule.source
            form.title.data = rule.title
            form.description.data = rule.description
            form.license.data = rule.license  # Selected value
            form.cve_id.data = rule.cve_id
            form.version.data = rule.version
            form.to_string.data = rule.to_string
            form.original_uuid.data= rule.original_uuid
            rule.last_modif = datetime.now(timezone.utc)
            
        return render_template("rule/edit_rule.html", form=form, rule=rule)
    else:
        return render_template("access_denied.html")
    

@rule_blueprint.route("/is_lock_for_update", methods=['GET'])
def is_lock_for_update()-> render_template:
    """If the rule has a history with manual submit as last update, return true to explain that the rule is locked for update"""
    rule_id = request.args.get('rule_id', type=int)
    if not rule_id:
        return jsonify({"message": "Missing rule_id", "is_locked": False}), 400
    is_locked = RuleModel.was_last_history_manuel(rule_id)
    return jsonify({"is_locked": is_locked}), 200

@rule_blueprint.route("/update_lock/<int:rule_id>", methods=['GET'])
def update_lock(rule_id):
    """Update the lock status of the rule's last history entry."""
    manuel_submit = request.args.get('manuel_submit', 'false').lower() == 'true'  # string → bool
    is_locked = RuleModel.manage_history_rule(rule_id, manuel_submit)
    return jsonify({"is_locked": is_locked, "message": "Rule lock status updated successfully", "toast_class": "success-subtle"})


#################
#   Rule info   #
#################

@rule_blueprint.route("/history/<int:rule_id>", methods=['GET'])
def rules_history(rule_id):
    return redirect(url_for('rule.detail_rule_history', rule_id=rule_id))

@rule_blueprint.route("/get_rules_page_history", methods=['GET'])
def get_rules_page_history()-> render_template:
    """Get the history of the rule"""
    page = request.args.get('page', type=int)
    rule_id = request.args.get('rule_id', type=int)
    rules = RuleModel.get_history_rule(page, rule_id)
    if rules:
        return {"success": True,
                "rule": [rule.to_json() for rule in rules],
                "total_pages": rules.pages
            }, 200
    return {"message": "No Rule"}, 404

#################
#   Rule owner  #
#################

@rule_blueprint.route("/get_rules_page_owner", methods=['GET'])
def get_rules_page_owner() -> jsonify:
    """Get all the rule of the user"""
    page = request.args.get('page', 1, type=int)
    rules = RuleModel.get_rules_page_owner(page)    
    total_rules = RuleModel.get_total_rules_count_owner()  

    if rules:
        rules_list = list()
        for rule in rules:
            u = rule.to_json()
            rules_list.append(u)
        return {"owner_rules": rules_list, "owner_total_page": rules.pages, "total_rules": total_rules} , 200
    
    return {"message": "No Rule"}, 400

@rule_blueprint.route("/get_my_rules_page_filter", methods=['GET'])
def get_rules_page_filter_owner() -> jsonify:
    """Get all the rules of the current user with filter"""
    page = int(request.args.get("page", 1))
    per_page = 10
    search = request.args.get("search", None)
    author = request.args.get("author", None)
    sort_by = request.args.get("sort_by", "newest")
    rule_type = request.args.get("rule_type", None) 
    sourceFilter = request.args.get("source", None) 
    
   



    query = RuleModel.filter_rules_owner( search=search, author=author, sort_by=sort_by, rule_type=rule_type , source=sourceFilter)
    total_rules = query.count()
    rules = query.offset((page - 1) * per_page).limit(per_page).all()

    #all_rules = query.all()

    return jsonify({
        "rule": [r.to_json() for r in rules],
        "total_rules": total_rules,
        "total_pages": ceil(total_rules / per_page),
       # "list": [r.to_json() for r in all_rules]
    }), 200

@rule_blueprint.route("/get_my_rules_page_filter_github", methods=['GET'])
def get_my_rules_page_filter_github() -> jsonify:
    """Get all the rules of the current user with filter"""
    page = int(request.args.get("page", 1))
    per_page = 40
    search = request.args.get("search", None)
    author = request.args.get("author", None)
    sort_by = request.args.get("sort_by", "newest")
    rule_type = request.args.get("rule_type", None) 
    sourceFilter = request.args.get("source", None) 

    query = RuleModel.filter_rules_owner_github( search=search, author=author, sort_by=sort_by, rule_type=rule_type , source=sourceFilter)
    total_rules = query.count()
    rules = query.offset((page - 1) * per_page).limit(per_page).all()


    return jsonify({
        "rule": [r.to_json() for r in rules],
        "total_rules": total_rules,
        "total_pages": ceil(total_rules / per_page),
        # "list": [r.to_json() for r in all_rules]
    })

@rule_blueprint.route("/delete_rule_list", methods=['POST'])
@login_required
def delete_selected_rules() -> jsonify:
    """Delete all the selected rule"""
    data = request.get_json()
    rule_ids = data.get('ids', [])
    if not rule_ids:
        return jsonify({"success": False, "message": "No rules selected.", "toast_class": "danger"}), 400

    # Permission check
    for rule_id in rule_ids:
        user_id = RuleModel.get_rule_user_id(rule_id)
        if current_user.id != user_id and not current_user.is_admin():
            return render_template("access_denied.html")

    import uuid as _uuid
    batch_uuid = str(_uuid.uuid4())
    count = RuleModel.soft_delete_rule_list(rule_ids, current_user.id, batch_uuid=batch_uuid)

    for rule_id in rule_ids:
        user_id = RuleModel.get_rule_user_id(rule_id)
        profil = AccountModel.get_or_create_gamification_profile(user_id)
        if profil:
            AccountModel.update_rules_owned_gamification(profil.id, user_id)

    log_activity("rule.bulk_delete", f"Moved {count} rule(s) to trash",
                 extra={"rule_ids": rule_ids, "batch_uuid": batch_uuid})
    return jsonify({"success": True,
                    "message": f"{count} rule(s) moved to trash!",
                    "toast_class": "success"}), 200


@rule_blueprint.route("/owner_rules", methods=['GET'])
@login_required
def owner_rules() -> render_template:
    """Redirect to the rules_owner"""
    return render_template("rule/rules_owner.html")

###########################
#   Detail rule section   #
###########################

@rule_blueprint.route("/get_current_rule", methods=['GET'])
def get_current_rule() -> jsonify:
    """Get the current rule for detail"""
    rule_id = request.args.get('rule_id', 1, type=int)
    rule = RuleModel.get_rule(rule_id)
    if rule:
        return {"rule": rule.to_json()}
    return {"message": "No Rule"}, 404

@rule_blueprint.route("/get_related_rules", methods=['GET'])
def get_related_rules() -> jsonify:
    """Check whether this rule has other rules sharing its source (or author), for
    the detail page's Related Rules widget — the widget itself fetches the actual
    paginated rule data via /rule/data_table?sources=... / ?authors=..."""
    rule_id = request.args.get('rule_id', type=int)
    if not rule_id:
        return {"message": "No rule id provided"}, 400
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return {"message": "No Rule"}, 404
    matched_field, matched_value, total_count = RuleModel.get_related_rules_meta(rule)
    return {
        "matched_field": matched_field,
        "matched_value": matched_value,
        "total_count": total_count,
    }, 200

@rule_blueprint.route("/detail_rule/<string:rule_uuid>", methods=['GET'])
def detail_rule_by_uuid(rule_uuid):
    """Get the detail of a rule by its UUID"""
    # remove invalide space
    rule_uuid = rule_uuid.replace(" ", "")

    rule = RuleModel.get_rule_by_uuid(rule_uuid)
    if not rule:
        return render_template("404.html")
    if rule.is_deleted:
        return render_template("rule/rule_in_trash.html", rule=rule)


    rule_misp_object = get_rule_misp_object(rule.id)

    if not rule_misp_object:
        rule_misp_object = None

    rule_misp_event = get_rule_misp_event(rule.id)
    if not rule_misp_event:
        rule_misp_event = None

    rule_velociraptor_artifact = None
    if (rule.format or '').lower() in VELOCIRAPTOR_SUPPORTED_FORMATS:
        try:
            rule_velociraptor_artifact = generate_velociraptor_artifact(rule, base_url=request.host_url)
        except Exception as e:
            # Format was already confirmed supported above, so any exception here
            # is a real generator bug, not an expected "unsupported format" case —
            # don't let it disappear silently.
            print(f"[rule] Velociraptor artifact generation failed for rule {rule.id}: {e}")
            rule_velociraptor_artifact = None

    rule_to_json = json.dumps(rule.to_json_detail(), indent=4)

    if not rule_to_json:
        rule_to_json = "No json format for this rule"
    active_tab = request.args.get('tab', 'detail')
    current_user_vote = None
    if current_user.is_authenticated:
        from app.core.db_class.db import RuleVote as _RV
        _rv = _RV.query.filter_by(rule_id=rule.id, user_id=current_user.id).first()
        current_user_vote = _rv.vote_type if _rv else None
    if rule:
        rule_risk = RuleModel.get_rule_risk_flags(rule)
        return render_template("rule/detail_rule/detail_rule.html", rule=rule, rule_content=rule.to_string,
                               rule_misp_object=rule_misp_object, rule_misp_event=rule_misp_event,
                               rule_velociraptor_artifact=rule_velociraptor_artifact,
                               rule_to_json=rule_to_json, active_tab=active_tab,
                               current_user_vote=current_user_vote, rule_risk=rule_risk,
                               **_nav_counts(rule.id))
    return render_template("404.html")

    # rule_misp = content_convert_to_misp_object(rule.id)
    # if not rule_misp:
    #     return 

    # rule_to_json = json.dumps(rule.to_json_detail(), indent=4)

    # if not rule_to_json:
    #     rule_to_json = "No json format for this rule"

    # current_user_vote = None
    # if current_user.is_authenticated:
    #     from app.core.db_class.db import RuleVote as _RV
    #     _rv = _RV.query.filter_by(rule_id=rule.id, user_id=current_user.id).first()
    #     current_user_vote = _rv.vote_type if _rv else None

    # if rule:
    #     return render_template("rule/detail_rule/detail_rule.html", rule=rule, rule_content=rule.to_string, rule_misp=rule_misp, rule_to_json=rule_to_json, current_user_vote=current_user_vote, **_nav_counts(rule.id))
    # return render_template("404.html")



def _rule_similarity_count(rule_id):
    from app.core.db_class.db import RuleSimilarity
    return RuleSimilarity.query.filter_by(rule_id=rule_id).count()


def _rule_history_count(rule_id):
    from app.core.db_class.db import RuleUpdateHistory
    return RuleUpdateHistory.query.filter_by(rule_id=rule_id).count()


def _rule_proposal_count(rule_id):
    from app.core.db_class.db import RuleEditProposal
    return RuleEditProposal.query.filter_by(rule_id=rule_id).count()


def _rule_scope_count(rule_id):
    from app.core.db_class.db import RuleScope
    return RuleScope.query.filter_by(rule_id=rule_id).count()


def _rule_test_count(rule_id):
    from flask_login import current_user
    from app.features.rule_tester import rule_tester_core as TesterModel
    return TesterModel.count_visible_tests_for_rule(rule_id, current_user)


def _rule_ai_analysis_count(rule_id):
    from app.core.db_class.db import AIGeneration
    q = AIGeneration.query.filter_by(agent_key='rule_analysis', rule_id=rule_id)
    if not (current_user.is_authenticated and current_user.is_admin()):
        q = q.filter_by(is_public=True)
    return q.count()


def _nav_counts(rule_id):
    return {
        'similarity_count':  _rule_similarity_count(rule_id),
        'history_count':     _rule_history_count(rule_id),
        'proposal_count':    _rule_proposal_count(rule_id),
        'scope_count':       _rule_scope_count(rule_id),
        'test_count':        _rule_test_count(rule_id),
        'ai_analysis_count': _rule_ai_analysis_count(rule_id),
    }


@rule_blueprint.route("/detail_rule/<int:rule_id>", methods=['GET'])
def detail_rule(rule_id)-> render_template:
    """Get the detail of the current rule"""
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return render_template("404.html")
    if rule.is_deleted:
        return render_template("rule/rule_in_trash.html", rule=rule)
    
    rule_misp_object = get_rule_misp_object(rule_id)

    if not rule_misp_object:
        rule_misp_object = None

    rule_misp_event = get_rule_misp_event(rule_id)
    if not rule_misp_event:
        rule_misp_event = None

    rule_velociraptor_artifact = None
    if (rule.format or '').lower() in VELOCIRAPTOR_SUPPORTED_FORMATS:
        try:
            rule_velociraptor_artifact = generate_velociraptor_artifact(rule, base_url=request.host_url)
        except Exception as e:
            # Format was already confirmed supported above, so any exception here
            # is a real generator bug, not an expected "unsupported format" case —
            # don't let it disappear silently.
            print(f"[rule] Velociraptor artifact generation failed for rule {rule.id}: {e}")
            rule_velociraptor_artifact = None

    rule_to_json = json.dumps(rule.to_json_detail(), indent=4)

    if not rule_to_json:
        rule_to_json = "No json format for this rule"
    active_tab = request.args.get('tab', 'detail')
    current_user_vote = None
    if current_user.is_authenticated:
        from app.core.db_class.db import RuleVote as _RV
        _rv = _RV.query.filter_by(rule_id=rule.id, user_id=current_user.id).first()
        current_user_vote = _rv.vote_type if _rv else None
    if rule:
        rule_risk = RuleModel.get_rule_risk_flags(rule)
        return render_template("rule/detail_rule/detail_rule.html", rule=rule, rule_content=rule.to_string,
                               rule_misp_object=rule_misp_object, rule_misp_event=rule_misp_event,
                               rule_velociraptor_artifact=rule_velociraptor_artifact,
                               rule_to_json=rule_to_json, active_tab=active_tab,
                               current_user_vote=current_user_vote, rule_risk=rule_risk,
                               **_nav_counts(rule.id))
    return render_template("404.html")


@rule_blueprint.route("/detail_rule/<int:rule_id>/history", methods=['GET'])
def detail_rule_history(rule_id):
    """History sub-page for a rule."""
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return render_template("404.html")
    if rule.is_deleted:
        return render_template("rule/rule_in_trash.html", rule=rule)
    return render_template("rule/detail_rule/detail_rule_history.html", rule=rule,
                           **_nav_counts(rule.id))


@rule_blueprint.route("/detail_rule/<int:rule_id>/propose_edit", methods=['GET'])
def detail_rule_propose_edit(rule_id):
    """Suggest an Edit sub-page for a rule."""
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return render_template("404.html")
    if rule.is_deleted:
        return render_template("rule/rule_in_trash.html", rule=rule)
    return render_template("rule/detail_rule/detail_rule_propose_edit.html", rule=rule,
                           **_nav_counts(rule.id))


@rule_blueprint.route("/detail_rule/<int:rule_id>/pull_request", methods=['GET'])
def detail_rule_pull_request(rule_id):
    """Edit Proposals sub-page for a rule."""
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return render_template("404.html")
    if rule.is_deleted:
        return render_template("rule/rule_in_trash.html", rule=rule)
    return render_template("rule/detail_rule/detail_rule_pull_request.html", rule=rule,
                           **_nav_counts(rule.id))


@rule_blueprint.route("/detail_rule/<int:rule_id>/scope", methods=['GET'])
def detail_rule_scope(rule_id):
    """Scope declarations sub-page for a rule."""
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return render_template("404.html")
    if rule.is_deleted:
        return render_template("rule/rule_in_trash.html", rule=rule)
    return render_template("rule/detail_rule/detail_rule_scope.html", rule=rule,
                           **_nav_counts(rule.id))


@rule_blueprint.route("/detail_rule/<int:rule_id>/similarity", methods=['GET'])
def detail_rule_similarity(rule_id):
    """Similarity sub-page for a rule."""
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return render_template("404.html")
    if rule.is_deleted:
        return render_template("rule/rule_in_trash.html", rule=rule)
    return render_template("rule/detail_rule/detail_rule_similarity.html", rule=rule,
                           **_nav_counts(rule.id))


@rule_blueprint.route("/detail_rule/<int:rule_id>/ai_analysis", methods=['GET'])
def detail_rule_ai_analysis(rule_id):
    """AI Analysis sub-page for a rule — see AI_02_RULE_ANALYSIS.md."""
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return render_template("404.html"), 404
    if rule.is_deleted:
        return render_template("rule/rule_in_trash.html", rule=rule)
    return render_template("rule/detail_rule/detail_rule_ai_analysis.html", rule=rule,
                           **_nav_counts(rule.id))


@rule_blueprint.route("/detail_rule/<int:rule_id>/ai_analysis/list", methods=['GET'])
def detail_rule_ai_analysis_list(rule_id):
    """History of AI analyses for one rule, newest first. Regular users only
    ever see is_public=True entries; admins see everything (including
    private ones, so they can review/toggle/delete them)."""
    from app.core.db_class.db import AIGeneration
    q = AIGeneration.query.filter_by(agent_key='rule_analysis', rule_id=rule_id)
    if not (current_user.is_authenticated and current_user.is_admin()):
        q = q.filter_by(is_public=True)
    items = q.order_by(AIGeneration.created_at.desc()).limit(50).all()
    out = []
    for a in items:
        row = a.to_json()
        row['username'] = (f"{a.user.first_name} {a.user.last_name}".strip() or a.user.email) if a.user else None
        out.append(row)
    return jsonify({'items': out})


@rule_blueprint.route("/ai_analysis/models", methods=['GET'])
@login_required
def ai_analysis_models():
    """Model allowlist for the launch card — queries Ollama directly rather
    than a separate admin-curated table, since none exists yet. Admin-only:
    the launch card itself is admin-only in the template, this is just
    defense in depth."""
    from app.core.db_class.db import AIAgentConfig
    from app.features.ai.ai_core import AgentConnectionError, OllamaClient

    if not current_user.is_admin():
        return jsonify({"error": "Forbidden."}), 403

    cfg = AIAgentConfig.query.filter_by(agent_key='rule_analysis').first()
    enabled = cfg.enabled if cfg else True
    default_model = cfg.default_model if cfg else None

    models = []
    try:
        client = OllamaClient(
            base_url=current_app.config.get('OLLAMA_URL') or 'http://localhost:11434',
            model='', timeout=5,
        )
        models = client.list_models()
    except AgentConnectionError:
        pass

    return jsonify({'enabled': enabled, 'models': models, 'default_model': default_model})


def _get_visible_ai_generation_or_none(rule_id, analysis_id):
    """A private analysis is only visible to an admin — same rule as
    detail_rule_ai_analysis_list above."""
    from app.core.db_class.db import AIGeneration
    analysis = AIGeneration.query.filter_by(
        id=analysis_id, rule_id=rule_id, agent_key='rule_analysis',
    ).first()
    if not analysis:
        return None
    if not analysis.is_public and not (current_user.is_authenticated and current_user.is_admin()):
        return None
    return analysis


def _ai_analysis_download_filename(rule, ext):
    import re as _re
    slug = _re.sub(r'[^a-z0-9]+', '-', (rule.title or 'rule').lower()).strip('-')[:40]
    return f'ai-analysis-{slug}-{rule.id}.{ext}'


@rule_blueprint.route("/detail_rule/<int:rule_id>/ai_analysis/<int:analysis_id>/download/markdown", methods=['GET'])
def detail_rule_ai_analysis_download_markdown(rule_id, analysis_id):
    """Download a single AI analysis as a Markdown file with YAML front-matter
    — same front-matter convention as blog post Markdown downloads."""
    rule = RuleModel.get_rule(rule_id)
    if not rule or rule.is_deleted:
        return render_template("404.html"), 404

    analysis = _get_visible_ai_generation_or_none(rule_id, analysis_id)
    if not analysis:
        return render_template("404.html"), 404

    requester = (f"{analysis.user.first_name} {analysis.user.last_name}".strip()) if analysis.user else 'unknown'
    source_url = f'{request.url_root.rstrip("/")}/rule/detail_rule/{rule.id}/ai_analysis'

    lines = [
        '---',
        f'title: "AI Analysis — {rule.title}"',
        f'rule_title: "{rule.title}"',
        f'rule_format: "{rule.format}"',
        f'model: "{analysis.model or "unknown"}"',
        f'requested_by: "{requester}"',
        f'generated_at: {analysis.created_at.strftime("%Y-%m-%dT%H:%M:%SZ")}',
        f'source: "{source_url}"',
        f'exported_at: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}',
        '---',
        '',
        analysis.content or '',
    ]

    response = current_app.response_class('\n'.join(lines), mimetype='text/markdown')
    response.headers['Content-Disposition'] = (
        f'attachment; filename="{_ai_analysis_download_filename(rule, "md")}"'
    )
    log_activity('rule.ai_analysis_download', f'Downloaded AI analysis (Markdown) for "{rule.title[:80]}"',
                 target_type='rule', target_id=rule.id, is_public=False)
    return response


@rule_blueprint.route("/detail_rule/<int:rule_id>/ai_analysis/<int:analysis_id>/download/pdf", methods=['GET'])
def detail_rule_ai_analysis_download_pdf(rule_id, analysis_id):
    """Generate a PDF of a single AI analysis — same WeasyPrint pipeline as
    blog post PDF downloads (see blog.download_post_pdf)."""
    import markdown as _md
    from weasyprint import HTML as WeasyprintHTML

    rule = RuleModel.get_rule(rule_id)
    if not rule or rule.is_deleted:
        return render_template("404.html"), 404

    analysis = _get_visible_ai_generation_or_none(rule_id, analysis_id)
    if not analysis:
        return render_template("404.html"), 404

    requester = (f"{analysis.user.first_name} {analysis.user.last_name}".strip()) if analysis.user else None
    base_url = request.url_root.rstrip('/')
    content_html = _md.markdown(analysis.content or '', extensions=['extra', 'codehilite', 'toc', 'nl2br'])

    html_str = render_template(
        'rule/detail_rule/ai_analysis_print.html',
        rule=rule, analysis=analysis, requester=requester, content_html=content_html,
        source_url=f'{base_url}/rule/detail_rule/{rule.id}/ai_analysis',
        generated_at=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
    )
    pdf_bytes = WeasyprintHTML(string=html_str, base_url=base_url).write_pdf()

    response = current_app.response_class(pdf_bytes, mimetype='application/pdf')
    response.headers['Content-Disposition'] = (
        f'attachment; filename="{_ai_analysis_download_filename(rule, "pdf")}"'
    )
    log_activity('rule.ai_analysis_download', f'Downloaded AI analysis (PDF) for "{rule.title[:80]}"',
                 target_type='rule', target_id=rule.id, is_public=False)
    return response


@rule_blueprint.route("/detail_rule/<int:rule_id>/ai_analysis/<int:analysis_id>/visibility", methods=['POST'])
@login_required
def detail_rule_ai_analysis_visibility(rule_id, analysis_id):
    """Admin-only moderation lever: an AI-generated report can be wrong on a
    given rule — hide it without losing it."""
    from app.core.db_class.db import AIGeneration

    if not current_user.is_admin():
        return jsonify({"success": False, "message": "Forbidden."}), 403

    analysis = AIGeneration.query.filter_by(
        id=analysis_id, rule_id=rule_id, agent_key='rule_analysis',
    ).first()
    if not analysis:
        return jsonify({"success": False, "message": "Not found."}), 404

    data = request.get_json(force=True) or {}
    analysis.is_public = bool(data.get('is_public'))
    db.session.commit()
    log_activity('rule.ai_analysis_visibility',
                 f'Set AI analysis visibility to {"public" if analysis.is_public else "private"} '
                 f'on rule #{rule_id}', target_type='rule', target_id=rule_id, is_public=False)
    return jsonify({"success": True, "analysis": analysis.to_json()})


@rule_blueprint.route("/detail_rule/<int:rule_id>/ai_analysis/<int:analysis_id>", methods=['DELETE'])
@login_required
def detail_rule_ai_analysis_delete(rule_id, analysis_id):
    """Admin-only delete of a single AI analysis entry."""
    from app.core.db_class.db import AIGeneration

    if not current_user.is_admin():
        return jsonify({"success": False, "message": "Forbidden."}), 403

    analysis = AIGeneration.query.filter_by(
        id=analysis_id, rule_id=rule_id, agent_key='rule_analysis',
    ).first()
    if not analysis:
        return jsonify({"success": False, "message": "Not found."}), 404

    db.session.delete(analysis)
    db.session.commit()
    log_activity('rule.ai_analysis_delete', f'Deleted an AI analysis on rule #{rule_id}',
                 target_type='rule', target_id=rule_id, is_public=False)
    return jsonify({"success": True})


@rule_blueprint.route("/history_activity_delete/<string:log_uuid>", methods=['DELETE'])
@login_required
def history_activity_delete(log_uuid):
    """Delete a single ActivityLog entry — rule creator or admin only."""
    from app.core.db_class.db import ActivityLog
    log = ActivityLog.query.filter_by(uuid=log_uuid).first()
    if not log:
        return jsonify({"success": False, "message": "Entry not found."}), 404

    rule = RuleModel.get_rule(log.target_id) if log.target_id else None
    is_owner = rule and rule.user_id == current_user.id
    if not (current_user.is_admin() or is_owner):
        return jsonify({"success": False, "message": "Permission denied."}), 403

    db.session.delete(log)
    db.session.commit()
    return jsonify({"success": True, "message": "Activity deleted."}), 200


@rule_blueprint.route("/history_update_delete/<int:update_id>", methods=['DELETE'])
@login_required
def history_update_delete(update_id):
    """Delete a RuleUpdateHistory entry — rule creator or admin only."""
    from app.core.db_class.db import RuleUpdateHistory
    entry = RuleUpdateHistory.query.get(update_id)
    if not entry:
        return jsonify({"success": False, "message": "Entry not found."}), 404

    rule = RuleModel.get_rule(entry.rule_id)
    is_owner = rule and rule.user_id == current_user.id
    if not (current_user.is_admin() or is_owner):
        return jsonify({"success": False, "message": "Permission denied."}), 403

    db.session.delete(entry)
    db.session.commit()
    return jsonify({"success": True, "message": "Version entry deleted."}), 200


@rule_blueprint.route("/history_data/<int:rule_id>", methods=['GET'])
@login_required
def rule_history_data(rule_id):
    """Combined timeline: ActivityLog entries + RuleUpdateHistory for a rule."""
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return jsonify({"items": []})

    from app.core.db_class.db import ActivityLog, RuleUpdateHistory, User
    events = []

    # ── Activity logs targeting this rule ────────────────────────────────────
    logs = ActivityLog.query.filter(
        ActivityLog.target_type == 'rule',
        ActivityLog.target_id == rule_id,
    ).order_by(ActivityLog.created_at.desc()).limit(200).all()

    # 'rule.create'/'rule.edit'/'rule.quick_meta'/'rule.ownership_transfer' are
    # logged as ActivityLog entries too (for the global admin logs / notifications),
    # but each one has a matching, richer RuleUpdateHistory entry (with the
    # content/metadata diff) — showing both here would duplicate every event.
    EXCLUDED_ACTIONS = {
        'rule.vote_up', 'rule.vote_down', 'rule.favorite', 'rule.unfavorite',
        'rule.create', 'rule.edit', 'rule.quick_meta', 'rule.ownership_transfer',
    }

    action_labels = {
        'rule.create':            ('Rule created',       'success', 'fa-solid fa-file-shield'),
        'rule.edit':              ('Rule edited',        'info',    'fa-solid fa-pen-to-square'),
        'rule.delete':            ('Rule deleted',       'error',   'fa-solid fa-trash'),
        'rule.restore':           ('Rule restored',      'success', 'fa-solid fa-rotate-left'),
        'rule.scope_add':         ('Scope declared',     'info',    'fa-solid fa-globe'),
        'rule.scope_update':      ('Scope updated',      'info',    'fa-solid fa-globe'),
        'rule.scope_delete':      ('Scope removed',      'warning', 'fa-solid fa-globe'),
        'comment.add':            ('Comment added',      'info',    'fa-solid fa-comment'),
        'rule.propose_edit':      ('Proposal submitted', 'info',    'fa-solid fa-code-pull-request'),
        'rule.proposal_approved': ('Proposal approved',  'success', 'fa-solid fa-circle-check'),
        'rule.proposal_rejected': ('Proposal rejected',  'warning', 'fa-solid fa-circle-xmark'),
        'rule.version_bump':      ('Content updated',    'success', 'fa-solid fa-tag'),
        'rule.quick_meta':        ('Tags/vulnerabilities updated', 'info', 'fa-solid fa-tags'),
        'rule.ownership_transfer': ('Ownership changed', 'warning', 'fa-solid fa-user-shield'),
    }

    for log in logs:
        if log.action in EXCLUDED_ACTIONS:
            continue
        label, level, icon = action_labels.get(log.action, (log.action, 'info', log.icon or 'fa-solid fa-circle'))
        actor = log.user.first_name if log.user else 'System'
        extra = log.extra or {}
        proposal_id = extra.get('proposal_id')
        # For version_bump, enrich the title with version numbers
        if log.action == 'rule.version_bump' and extra.get('to_version'):
            label = f"Content updated — v{extra.get('from_version', '?')} → v{extra['to_version']}"
        events.append({
            'uuid':        log.uuid,
            'type':        'activity',
            'action':      log.action,
            'title':       label,
            'description': log.description or '',
            'level':       level,
            'category':    'rule',
            'icon':        icon,
            'actor_name':  actor,
            'actor_id':    log.user_id,
            'created_at':  log.created_at.isoformat(),
            'proposal_id': proposal_id,
        })

    # ── RuleUpdateHistory ─────────────────────────────────────────────────────
    updates = RuleUpdateHistory.query.filter_by(rule_id=rule_id) \
        .order_by(RuleUpdateHistory.analyzed_at.desc()).all()

    for upd in updates:
        has_diff = bool(upd.new_content and upd.old_content and upd.new_content != upd.old_content)
        metadata_changes = RuleModel.diff_rule_snapshots(upd.old_snapshot, upd.new_snapshot)

        if upd.change_type == 'created':
            title, icon, level = 'Rule created', 'fa-solid fa-sparkles', 'success'
        elif upd.change_type == 'ownership':
            title, icon, level = 'Ownership changed', 'fa-solid fa-user-shield', 'warning'
        elif has_diff and metadata_changes:
            title, icon, level = 'Content & metadata updated', 'fa-solid fa-code-compare', ('success' if upd.success else 'error')
        elif has_diff:
            title, icon, level = 'Content updated', 'fa-solid fa-code-compare', ('success' if upd.success else 'error')
        elif metadata_changes:
            title, icon, level = 'Metadata updated', 'fa-solid fa-pen-to-square', 'info'
        else:
            title  = 'Checked — no change' if upd.success else 'Update failed'
            icon   = 'fa-solid fa-check' if upd.success else 'fa-solid fa-xmark'
            level  = 'info' if upd.success else 'error'

        events.append({
            'uuid':             f'upd-{upd.id}',
            'type':             'update',
            'action':           'rule.update',
            'title':            title,
            'description':      RuleModel.humanize_history_message(upd.message) or '',
            'level':            level,
            'category':         'system',
            'icon':             icon,
            'actor_name':       upd.analyzed_by.first_name if upd.analyzed_by else 'System',
            'actor_id':         upd.analyzed_by_user_id,
            'created_at':       upd.analyzed_at.isoformat() if upd.analyzed_at else None,
            'old_content':      upd.old_content if has_diff else None,
            'new_content':      upd.new_content if has_diff else None,
            'rule_format':      upd.get_rule_format(),
            'manual':           bool(upd.manuel_submit),
            'change_type':      upd.change_type,
            'metadata_changes': metadata_changes,
        })

    # Sort all events by date desc
    events.sort(key=lambda e: e['created_at'] or '', reverse=True)
    return jsonify({"items": events})


@rule_blueprint.route("/get_stix/<int:rule_id>")
def get_stix(rule_id):
    rule_misp = get_rule_misp_event(rule_id)
    if not rule_misp:
        return jsonify({"stix": None})
    
    # rule_misp_json = json.loads(rule_misp) 
    rule_stix = convert_misp_to_stix(rule_misp)
    return jsonify({"stix": json.dumps(rule_stix, indent=4) if rule_stix else None})

@rule_blueprint.route("/get_sigma_convert/<int:rule_id>")
def get_sigma_convert(rule_id):
    target = request.args.get('target', '')
    rule = RuleModel.get_rule(rule_id)
    if not rule or (rule.format or '').lower() != 'sigma' or target not in SIGMA_CONVERT_TARGETS:
        return jsonify({"success": False, "content": None})
    try:
        content = convert_sigma_rule(rule, target)
        return jsonify({"success": True, "content": content})
    except Exception as e:
        return jsonify({"success": False, "content": None, "error": str(e)})

@rule_blueprint.route("/download_rule", methods=['GET'])
def download_rule_unified() -> Response:
    rule_id = request.args.get('rule_id', type=int)
    fmt = request.args.get('format', default='txt')
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return jsonify({
            "message": f"No rule found with id={rule_id}",
            "success": False,
            "toast_class": "danger-subtle",
        })
    error_mesg = ""
    try:
        if fmt == 'txt':
            content = rule.to_string
            extention = rule.get_extension()
            filename = f"{rule.title}.{extention}"

        elif fmt == 'json':
            content = json.dumps(rule.to_json_detail(), indent=2)
            filename = f"{rule.title}.json"

        elif fmt == 'misp':
            object_json = get_rule_misp_object(rule_id)
            if not object_json:
                error_mesg = f"Format {rule.format} not found on MISP"
            else:
                content = json.dumps(object_json, indent=2)
                filename = f"{rule.title}_misp_object.json"

        elif fmt == 'misp_event':
            object_json = get_rule_misp_event(rule_id)
            if not object_json:
                error_mesg = f"Format {rule.format} not found on MISP"
            else:
                content = json.dumps(object_json, indent=2)
                filename = f"{rule.title}_misp_event.json"

        elif fmt == 'stix':
            misp_raw = get_rule_misp_object(rule_id)
            object_json = convert_misp_to_stix(misp_raw)
            if not object_json:
                error_mesg = f"Format {rule.format} not found on STIX"
            else:
                stix_data = json.loads(object_json) if isinstance(object_json, str) else object_json
                content = json.dumps(stix_data, indent=2)
                filename = f"{rule.title}_stix_object.json"

        elif fmt == 'velociraptor':
            if (rule.format or '').lower() not in VELOCIRAPTOR_SUPPORTED_FORMATS:
                error_mesg = f"Velociraptor export is not supported for format {rule.format}"
            else:
                content = generate_velociraptor_artifact(rule, base_url=request.host_url)
                filename = f"{rule.title}_velociraptor_artifact.yaml"

        elif fmt in SIGMA_CONVERT_TARGETS:
            target_meta = SIGMA_CONVERT_TARGETS[fmt]
            if (rule.format or '').lower() != 'sigma':
                error_mesg = f"{target_meta['label']} export is only supported for Sigma rules"
            else:
                content = convert_sigma_rule(rule, fmt)
                filename = f"{rule.title}_{fmt}.{target_meta['extension']}"

        elif fmt == 'all':
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                try:
                    zip_file.writestr(f"{rule.title}.txt", rule.to_string)
                except Exception as e:
                    zip_file.writestr("errors.txt", f"TXT error: {str(e)}\n")

                try:
                    zip_file.writestr(f"{rule.title}.json", json.dumps(rule.to_json_detail(), indent=2))
                except Exception as e:
                    zip_file.writestr("errors.txt", f"JSON error: {str(e)}\n")

                try:
                    misp_object_raw = get_rule_misp_object(rule_id)
                    if misp_object_raw:
                        zip_file.writestr(f"{rule.title}_misp_object.json", json.dumps(misp_object_raw, indent=2))
                except Exception:
                    pass

                try:
                    misp_event_raw = get_rule_misp_event(rule_id)
                    if misp_event_raw:
                        zip_file.writestr(f"{rule.title}_misp_event.json", json.dumps(misp_event_raw, indent=2))
                except Exception:
                    pass

                try:
                    misp_raw = get_rule_misp_object(rule_id)
                    if misp_raw:
                        stix_raw = convert_misp_to_stix(misp_raw)
                        if stix_raw:
                            stix_data = json.loads(stix_raw) if isinstance(stix_raw, str) else stix_raw
                            zip_file.writestr(f"{rule.title}_stix_object.json", json.dumps(stix_data, indent=2))
                except Exception:
                    pass

                try:
                    if (rule.format or '').lower() in VELOCIRAPTOR_SUPPORTED_FORMATS:
                        artifact_yaml = generate_velociraptor_artifact(rule, base_url=request.host_url)
                        zip_file.writestr(f"{rule.title}_velociraptor_artifact.yaml", artifact_yaml)
                except Exception:
                    pass

                if (rule.format or '').lower() == 'sigma':
                    for sigma_target, sigma_meta in SIGMA_CONVERT_TARGETS.items():
                        try:
                            converted = convert_sigma_rule(rule, sigma_target)
                            zip_file.writestr(f"{rule.title}_{sigma_target}.{sigma_meta['extension']}", converted)
                        except Exception:
                            pass

            zip_buffer.seek(0)
            content = base64.b64encode(zip_buffer.read()).decode('utf-8')
            filename = f"{rule.title}_all_formats.zip"

        else:
            error_mesg = f"Unknown format: {fmt}"

    except Exception as e:
        error_mesg = f"Failed to prepare download: {str(e)}"

    if error_mesg:
        return jsonify({
            "message": error_mesg,
            "success": False,
            "toast_class": "danger-subtle",
        })

    log_activity("rule.download", f"Downloaded rule '{rule.title}' (format={fmt})",
                 target_type="rule", target_id=rule.id, target_uuid=rule.uuid,
                 extra={"format": fmt})
    return jsonify({
        "message": f"Rule {rule.title} ready for download",
        "success": True,
        "toast_class": "success-subtle",
        "filename": filename,
        "content": content,
        "encoding": "base64" if fmt == 'all' else "plain",
    })


#########################
#   Favorite section    #
#########################

@rule_blueprint.route('/favorite/<int:rule_id>', methods=['POST'])
@login_required
def add_favorite_rule(rule_id) -> redirect:
    """Add a rule to user's favorites via link."""
    existing = AccountModel.is_rule_favorited_by_user(user_id=current_user.id, rule_id=rule_id)
    if existing:
        remove_favorite(user_id=current_user.id, rule_id=rule_id)
        log_activity("rule.unfavorite", f"Removed rule id={rule_id} from favorites",
                     target_type="rule", target_id=rule_id)
        return jsonify({
            "is_favorited": False,
            "toast_class": 'success-subtle',
            "message": "rule remove from favorite"
        }), 200
    else:
        add_favorite(user_id=current_user.id, rule_id=rule_id)
        log_activity("rule.favorite", f"Added rule id={rule_id} to favorites",
                     target_type="rule", target_id=rule_id)
        return jsonify({
            "is_favorited": True,
            "toast_class": 'success-subtle',
            "message": "rule add to favorite"
        }), 200
    
    # return redirect(request.referrer or url_for('rule.rules_list'))

#########################
#   Comment section     #
#########################

@rule_blueprint.route("/detail_rule/get_comments_page", methods=['GET'])
def comment_rule() -> jsonify:
    """Get all the comment of the rule"""
    page = request.args.get('page', 1, type=int)
    rule_id = request.args.get('rule_id', type=int)
    comments = RuleModel.get_comment_page(page , rule_id)
    total_comments = RuleModel.get_total_comments_count()
    if comments:
        comments_list = [c.to_json() for c in comments]
        return {"comments_list": comments_list, "total_comments": total_comments}
    return {"message": "No Comments"}, 404

@rule_blueprint.route("/get_comments", methods=["GET"])
def get_comments():
    rule_id = request.args.get('rule_id', type=int)
    page    = request.args.get('page', 1, type=int)
    if not rule_id:
        return jsonify({"message": "Missing rule_id"}), 400
    uid = current_user.id if current_user.is_authenticated else None
    pagination, comments = RuleModel.get_comments_for_rule(rule_id, page, user_id=uid)
    return jsonify({
        "comments":       comments,
        "total_pages":    pagination.pages,
        "total_comments": pagination.total,
    }), 200


@rule_blueprint.route("/comment_add", methods=["GET"])
@login_required
def add_comment():
    content           = request.args.get('content', '', type=str) or request.args.get('new_content', '', type=str)
    rule_id           = request.args.get('rule_id', type=int)
    parent_comment_id = request.args.get('parent_comment_id', type=int, default=None)
    if not rule_id or not content.strip():
        return jsonify({"message": "Missing rule_id or content", "toast_class": "danger-subtle"}), 400
    success, message = RuleModel.add_comment_core(rule_id, content, current_user, parent_comment_id)
    if not success:
        return jsonify({"message": message, "toast_class": "danger-subtle"}), 500
    new_comment = RuleModel.get_latest_comment_for_user_and_rule(current_user.id, rule_id)
    rule_obj = RuleModel.get_rule(rule_id)
    log_activity("comment.add",
                 f"Added comment on rule '{rule_obj.title if rule_obj else rule_id}'",
                 target_type="comment", target_id=new_comment.id,
                 extra={"rule_id": rule_id, "rule_uuid": rule_obj.uuid if rule_obj else None})
    return jsonify({"message": message, "toast_class": "success-subtle"}), 200


@rule_blueprint.route("/edit_comment", methods=["GET"])
@login_required
def edit_comment():
    comment_id  = request.args.get('comment_id', type=int) or request.args.get('commentID', type=int)
    new_content = request.args.get('content', '', type=str) or request.args.get('newContent', '', type=str)
    comment = RuleModel.get_comment_by_id(comment_id)
    if not comment:
        return jsonify({"message": "Comment not found", "toast_class": "danger-subtle"}), 404
    if comment.user_id != current_user.id and not current_user.is_admin():
        return jsonify({"message": "Not authorized", "toast_class": "danger-subtle"}), 403
    RuleModel.update_comment(comment_id, new_content)
    return jsonify({"message": "Comment edited.", "toast_class": "success-subtle"}), 200


@rule_blueprint.route("/delete_comment", methods=["GET"])
@login_required
def delete_comment_route():
    comment_id = request.args.get('comment_id', type=int)
    comment = RuleModel.get_comment_by_id(comment_id)
    if not comment:
        return jsonify({"message": "Comment not found", "toast_class": "danger-subtle"}), 404
    if comment.user_id != current_user.id and not current_user.is_admin():
        return jsonify({"message": "Not authorized", "toast_class": "danger-subtle"}), 403
    rule_obj = RuleModel.get_rule(comment.rule_id)
    success = RuleModel.delete_comment(comment_id)
    if success:
        log_activity("comment.delete",
                     f"Deleted comment id={comment_id} on rule '{rule_obj.title if rule_obj else '?'}'",
                     target_type="comment", target_id=comment_id,
                     extra={"rule_id": comment.rule_id, "rule_uuid": rule_obj.uuid if rule_obj else None})
        return jsonify({"message": "Comment deleted.", "toast_class": "success-subtle"}), 200
    return jsonify({"message": "Failed to delete", "toast_class": "danger-subtle"}), 500


@rule_blueprint.route("/add_reaction", methods=["GET"])
@login_required
def add_reaction():
    comment_id    = request.args.get('comment_id', type=int)
    reaction_type = request.args.get('reaction_type', type=str)
    if not comment_id or not reaction_type:
        return jsonify({"message": "Missing params", "toast_class": "danger-subtle"}), 400
    success, message = RuleModel.add_reaction_to_rule_comment(comment_id, current_user.id, reaction_type)
    cls = "success-subtle" if success else "danger-subtle"
    return jsonify({"message": message, "toast_class": cls}), (200 if success else 500)

#############################
#   Propose edit for rule   #
#############################

@rule_blueprint.route("/change_to_check")
def change_to_check() -> jsonify:
    """Get the number of changeto check"""
    try:
        if current_user.is_admin():
            count = RuleModel.get_total_change_to_check_admin()
        else:
            count = RuleModel.get_total_change_to_check()
    except:
        count = 0
    return jsonify({"count": count})

@rule_blueprint.route("/rule_propose_edit", methods=["GET"])
@login_required
def rule_propose_edit() -> render_template:
    """Redirect to propose an edit"""
    return render_template("rule/rule_propose_edit.html")

@rule_blueprint.route('/get_rules_propose_edit_page', methods=['GET'])
@login_required
def get_rules_propose_edit_page() -> jsonify:
    page = request.args.get('page', 1, type=int)
    result = RuleModel.get_rules_propose_edit_page(page, current_user.id, current_user.is_admin())
    return jsonify({
        "rules_pendings_list": [r.to_json() for r in result],
        "total_pages_pending": result.pages,
        "total_count": result.total,
    })

@rule_blueprint.route('/get_my_proposals', methods=['GET'])
@login_required
def get_my_proposals() -> jsonify:
    """Get proposals submitted by current user"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    status = request.args.get('status', '', type=str)

    result = RuleModel.get_my_proposals_page(page, current_user.id, search=search, status=status)
    return jsonify({
        "rules_list": [r.to_json() for r in result],
        "total_pages_old": result.pages,
    })

@rule_blueprint.route('/get_rules_propose_edit_history_page', methods=['GET'])
@login_required
def get_rules_propose_edit_history_page() -> jsonify:
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    status = request.args.get('status', '', type=str)

    result , total_pending = RuleModel.get_rules_propose_edit_history_page(page, search=search, status=status, user_id=current_user.id, is_admin=current_user.is_admin())
    return jsonify({
        "rules_list": [r.to_json() for r in result],
        "total_pages_old": result.pages,
        "total_count": total_pending
    })

@rule_blueprint.route("/get_rules_propose_page", methods=['GET'])
def get_rules_propose_page() -> jsonify:
    """Get all the changes propose"""
    page = request.args.get('page', 1, type=int)
    rule_id = request.args.get('rule_id', 1, type=int)
    all_rules_propose = RuleModel.get_all_rules_edit_propose_page(page , rule_id)

    if all_rules_propose:
        rules_list = [rule.to_json() for rule in all_rules_propose]
        return jsonify({
            "rules_list": rules_list,
            "total_pages_pending": all_rules_propose.pages,
        })
    return jsonify({"message": "No Rule"})

@rule_blueprint.route('/propose_edit/<int:rule_id>', methods=['POST'])
@login_required
def propose_edit(rule_id) -> redirect:
    """Create a new edit (like a change request). Returns JSON when Accept: application/json."""
    is_ajax = request.headers.get('Accept', '').startswith('application/json')

    def _err(msg, code=400):
        if is_ajax:
            return jsonify({"success": False, "message": msg, "toast_class": "danger"}), code
        flash(msg, "error")
        return redirect(url_for('rule.detail_rule_propose_edit', rule_id=rule_id))

    data = request.form
    proposed_content = data.get('rule_content')
    message = data.get('message')

    if not proposed_content:
        return _err("Proposed content cannot be empty.")

    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return _err("Rule not found.", 404)

    current_normalized  = "".join(rule.to_string.split())
    proposed_normalized = "".join(proposed_content.split())

    if current_normalized == proposed_normalized:
        return _err("Proposed content is the same as the current content (ignoring formatting).")

    rule_dict = rule.to_json()
    rule_dict['to_string'] = proposed_content
    valide, error = verify_syntax_rule_by_format(rule_dict)
    if not valide:
        return _err(f"Syntax error in proposed content: {error}")

    edit_type = data.get('edit_type', 'content_update')
    form = {
        "rule_id": rule_id,
        "proposed_content": proposed_content,
        "message": message,
        "edit_type": edit_type,
    }

    success, proposal_id = RuleModel.propose_edit_core(form, current_user.id)
    if not success:
        return _err("Failed to save proposal.", 500)

    gamification = AccountModel.get_or_create_gamification_profile(current_user.id)
    if gamification:
        AccountModel.update_propose_edit_gamification(gamification.id, "add_one_to_suggested")

    try:
        from app.features.notification.notification_core import notify_proposal_submitted
        from app.core.db_class.db import RuleEditProposal as ProposalModel
        proposal_obj = ProposalModel.query.get(proposal_id)
        if proposal_obj:
            notify_proposal_submitted(proposal_obj, rule)
    except Exception as _e:
        print(f"[rule] notify_proposal_submitted error: {_e}")

    log_activity(
        "rule.propose_edit",
        f"Submitted an edit proposal for rule '{rule.title}' (id={rule_id})",
        target_type="rule", target_id=rule_id, target_uuid=rule.uuid,
        extra={"proposal_id": proposal_id, "message": message or ""},
        is_public=False,
    )

    discuss_url = f"/rule/proposal_content_discuss?id={proposal_id}"
    if is_ajax:
        return jsonify({
            "success": True,
            "message": "Proposal submitted successfully!",
            "toast_class": "success",
            "redirect_url": discuss_url,
        })
    flash("Request sended.", "success", discuss_url)
    return redirect(url_for('rule.detail_rule', rule_id=rule_id))

@rule_blueprint.route("/validate_proposal", methods=['GET'])
@login_required
def validate_proposal() -> jsonify:
    """Validate a proposal on a rule"""
    rule_id = request.args.get('ruleId', type=int) # id of the real rule 
    decision = request.args.get('decision', type=str)
    rule_proposal_id = request.args.get('ruleproposalId', type=int) #id of the rule request
    user_id = RuleModel.get_rule_user_id(rule_id)
    if user_id == current_user.id or current_user.is_admin():
        if rule_id and decision and rule_proposal_id:
            # the rule modified
            rule_proposal = RuleModel.get_rule_proposal(rule_proposal_id)

            new_version = None
            if decision == "accepted":
                RuleModel.set_status(rule_proposal_id,"accepted")
                # change the to_string part of the rule in the db
                response , status_code = RuleModel.set_to_string_rule(rule_id, rule_proposal.proposed_content)
                message = response["message"]
                log_activity(
                    "rule.proposal_approved",
                    f"Approved edit proposal id={rule_proposal_id} for rule id={rule_id}",
                    target_type="rule", target_id=rule_id,
                    extra={"proposal_id": rule_proposal_id, "proposer_id": rule_proposal.user_id},
                    is_public=False,
                )
                try:
                    from app.features.notification.notification_core import notify_proposal_status_change
                    _rule_for_notif = RuleModel.get_rule(rule_id)
                    notify_proposal_status_change(rule_proposal, 'accepted',
                                                  _rule_for_notif.title if _rule_for_notif else '')
                except Exception as _e:
                    print(f"[rule] notify_proposal_status_change accepted error: {_e}")
                # add to contributor
                user_proposal_id = RuleModel.get_rule_proposal_user_id(rule_proposal_id)
                RuleModel.create_contribution(user_proposal_id,rule_proposal_id)
                # add to history rule
                rule = RuleModel.get_rule(rule_id)
                result = {
                    "id": rule_id,
                    "title": rule.title,
                    "success": True,
                    "message": "accepted",
                    "new_content": rule_proposal.proposed_content,
                    "old_content": rule_proposal.old_content,
                    "manual_submit": True,
                }

            
                history_id = RuleModel.create_rule_history(result)
                if not history_id:
                    return jsonify({"message": "Error during the creation of the history." ,
                        "success": False,
                        "toast_class" : "danger"
                        }),500
                
                # update gamification
                gamification = AccountModel.get_or_create_gamification_profile(rule_proposal.user_id)
                if gamification == None:
                    return jsonify({"message": "Error during the update of the gamification." ,
                        "success": False,
                        "toast_class" : "danger"
                        }),500
                _ = AccountModel.update_propose_edit_gamification(gamification.id , "add_one_to_accepted")

                # Increment community version
                current_v = rule.version or "1.0"
                try:
                    new_version = bump_version(current_v) or current_v
                except Exception:
                    new_version = current_v
                rule.version = new_version
                db.session.commit()
                log_activity(
                    "rule.version_bump",
                    f"Content updated — rule bumped from v{current_v} to v{new_version} (proposal #{rule_proposal_id})",
                    target_type="rule", target_id=rule_id, target_uuid=rule.uuid,
                    extra={"from_version": current_v, "to_version": new_version, "proposal_id": rule_proposal_id},
                    is_public=False,
                )

            elif decision == "rejected":
                RuleModel.set_status(rule_proposal_id,"rejected")
                message = "Proposal rejected."
                log_activity(
                    "rule.proposal_rejected",
                    f"Rejected edit proposal id={rule_proposal_id} for rule id={rule_id}",
                    target_type="rule", target_id=rule_id,
                    extra={"proposal_id": rule_proposal_id, "proposer_id": rule_proposal.user_id},
                    is_public=False,
                )
                try:
                    from app.features.notification.notification_core import notify_proposal_status_change
                    _rule_for_notif = RuleModel.get_rule(rule_id)
                    notify_proposal_status_change(rule_proposal, 'rejected',
                                                  _rule_for_notif.title if _rule_for_notif else '')
                except Exception as _e:
                    print(f"[rule] notify_proposal_status_change rejected error: {_e}")
                # update gamification
                gamification = AccountModel.get_or_create_gamification_profile(rule_proposal.user_id)
                if gamification == None:
                    return jsonify({"message": "Error during the update of the gamification." ,
                        "success": False,
                        "toast_class" : "danger"
                        }),500
                _ = AccountModel.update_propose_edit_gamification(gamification.id , "add_one_to_rejected")
            else:
                return jsonify({"message": "Invalid decision",
                                "success": False,
                                "toast_class" : "danger"}), 400
        resp = {"message": message, "success": True, "toast_class": "success"}
        if new_version:
            resp["new_version"] = new_version
        return jsonify(resp), 200
    else:
        return render_template("access_denied.html")

# manage_proposals
@rule_blueprint.route("/manage_proposals", methods=['POST'])
@login_required
def manage_proposals() -> jsonify:
    """Bulk accept or reject proposals"""
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid request.", "success": False, "toast_class": "danger-subtle"}), 400

    action = data.get("action")  # "accept" or "reject"
    mode = data.get("mode")      # "all" or "partial"
    selected_ids = data.get("selected_ids", [])
    excluded_ids = data.get("excluded_ids", [])

    if action not in ("accept", "reject"):
        return jsonify({"message": "Invalid action.", "success": False, "toast_class": "danger-subtle"}), 400

    result = RuleModel.bulk_manage_proposals(
        action=action,
        mode=mode,
        selected_ids=selected_ids,
        excluded_ids=excluded_ids,
        reviewed_by_id=current_user.id,
        is_admin=current_user.is_admin(),
    )

    if result["success"]:
        log_activity(
            "rule.proposal_approved" if action == "accept" else "rule.proposal_rejected",
            f"Bulk {action}ed proposals (mode={mode}, count={result.get('count', '?')})",
            extra={"action": action, "mode": mode, "selected_ids": selected_ids,
                   "excluded_ids": excluded_ids},
            is_public=False,
        )
        return jsonify({
            "message": result["message"],
            "success": True,
            "toast_class": "success-subtle"
        }), 200
    return jsonify({
        "message": result["message"],
        "success": False,
        "toast_class": "danger-subtle"
    }), 500

@rule_blueprint.route('/proposal_content_discuss', methods=['GET'])
@login_required
def proposal_content_discuss() -> render_template:
    """Redirect to porposal content discuss"""
    rule_edit_id = request.args.get('id', type=int)
    proposal = RuleModel.get_rule_proposal(rule_edit_id)
    if not proposal:
        return render_template("404.html")
    rule = RuleModel.get_rule(proposal.rule_id)
    if not rule:
        return render_template("404.html")
    can_decide = current_user.id == rule.user_id or current_user.is_admin()
    return render_template("rule/proposal_content_discuss.html",
                           rule_edit_id=rule_edit_id,
                           rule=rule,
                           can_decide=can_decide,
                           **_nav_counts(rule.id))

@rule_blueprint.route('/get_contributor', methods=['GET'])
def get_contributor() -> render_template:
    """Get all the contributor"""
    rule_id = request.args.get('rule_id', type=int)

    contributor = RuleModel.get_all_contributions_with_rule_id(rule_id)
   
    contributor = [contributors.to_json() for contributors in contributor]
    return jsonify({
            "contributors": contributor,
            "message": "success",
        })
    

@rule_blueprint.route('/discuss', methods=['GET'])
@login_required
def get_rule_edit_comments() -> jsonify:
    """Get all the discuss"""
    proposal_id = request.args.get('id', type=int)
    comments = RuleModel.get_comments_by_proposal_id(proposal_id)
    return jsonify([comment.to_json() for comment in comments])

@rule_blueprint.route('/add_comment_discuss', methods=['GET'])
@login_required
def post_rule_edit_comment() -> jsonify:
    """Create a comment in the discuss section"""
    proposal_id = request.args.get('id', type=int)
    content = request.args.get('content')

    if not content:
        return jsonify({'error': 'Content is required'}), 400

    try:
        new_comment = RuleModel.create_comment_discuss(proposal_id, current_user.id, content)
        try:
            from app.features.notification.notification_core import notify_proposal_comment
            from app.core.db_class.db import RuleEditProposal as ProposalModel
            proposal_obj = ProposalModel.query.get(proposal_id)
            if proposal_obj:
                rule_for_notif = RuleModel.get_rule(proposal_obj.rule_id)
                notify_proposal_comment(
                    proposal_id,
                    proposal_obj.user_id,
                    current_user.id,
                    rule_for_notif.title if rule_for_notif else '',
                )
        except Exception as _e:
            print(f"[rule] notify_proposal_comment error: {_e}")
        return jsonify(new_comment.to_json()), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@rule_blueprint.route('/delete_comment', methods=['GET'])
@login_required
def delete_comment_discuss() -> jsonify:
    """Delete a comment in the discuss section"""
    comment_id = request.args.get('id', type=int)
    success = RuleModel.delete_comment_discuss(comment_id, current_user.id)
    if success:
        return jsonify({"message": "Comment deleted."}), 200
    else:
        return jsonify({"error": "Not authorized or comment not found."}), 403



@rule_blueprint.route('/get_discuss_part_from', methods=['GET'])
@login_required
def get_discuss_part_from() -> jsonify:
    """Get all the discuss where the current user speak"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    status = request.args.get('status', '', type=str)

    all_discuss_proposal = RuleModel.get_all_rules_edit_propose_user_part_from_page(
        page, current_user.id, search=search, status=status
    )
    if all_discuss_proposal:
        return jsonify({
            "rules_list": [rule.to_json() for rule in all_discuss_proposal],
            "total_pages_old": all_discuss_proposal.pages,
        })
    return jsonify({"rules_list": [], "total_pages_old": 1})

#########################
#   Import from Github  #
#########################

@rule_blueprint.route("/update/get_auto_component", methods=["GET"])
@login_required
def get_auto_component():
    page = request.args.get("page", default=1, type=int)
    search = request.args.get("search", default="", type=str).strip()

    data = RuleModel.get_auto_update_page( page=page, search=search)

    if data:
        return jsonify({
            "auto_component":  [item.to_json() for item in data],
            "auto_component_total_page": data.pages,
            "success": True
        }), 200
    return jsonify({
            "auto_component":  [],
            "auto_component_total_page": 0,
            "success": False
        }), 500

@rule_blueprint.route("/get_rule_history_count", methods=['GET'])
# @login_required
def get_rule_history_count():
    rule_history_id = request.args.get('rule_id', type=int)
    count = RuleModel.get_rule_history_count(rule_history_id)
    if count is not None:
        return jsonify({"count": count}), 200
    else:
        return jsonify({"error": "Rule history not found"}), 404




@rule_blueprint.route("/get_history_rule", methods=['GET'])
@login_required
def get_history_rule():
    history_id = request.args.get('rule_id', type=int)

    if not history_id:
        return jsonify({"message": "Missing rule_id"}), 400

    history_rule = RuleModel.get_history_rule_by_id(history_id)

    if not history_rule:
        # 404 page
        # return render_template("404.html")
        return jsonify({"message": "Rule history not found"}), 404

    old_content = history_rule.old_content or ""
    new_content = history_rule.new_content or ""

    old_html, new_html = generate_side_by_side_diff_html(old_content, new_content)

    d = history_rule.to_json()
    d['old_diff_html'] = old_html
    d['new_diff_html'] = new_html

    return {
        "history_rule": d
    }

@rule_blueprint.route('/get_proposal', methods=['GET'])
@login_required
def get_proposal() -> jsonify:
    """Get the detail porposal"""
    proposalId = request.args.get('id', type=int)
    proposal = RuleModel.get_rule_proposal(proposalId)

    old_content = proposal.old_content or ""
    new_content = proposal.proposed_content or ""

    old_html, new_html = generate_side_by_side_diff_html(old_content, new_content)

    d = proposal.to_json()
    d['old_diff_html'] = old_html
    d['new_diff_html'] = new_html
    d['is_favorited'] = is_rule_favorited_by_user(user_id=current_user.id, rule_id=proposal.rule_id)

    # Include current rule version so accepted proposals can show the resulting version
    rule_obj = RuleModel.get_rule(proposal.rule_id)
    d['rule_version'] = rule_obj.version if rule_obj else None

    return {
        "proposal": d,
    }



@rule_blueprint.route("/update_github/history_json/<int:history_id>", methods=['GET'])
@login_required
def history_diff_json(history_id):
    """Return old_content / new_content for inline diff display."""
    history = RuleModel.get_history_rule_by_id(history_id)
    if not history:
        return {'message': 'Not found'}, 404
    return history.to_json(), 200


@rule_blueprint.route("/update_github/choose_changes", methods=['GET'])
@login_required
def choose_changes() -> render_template:
    """Redirect to updating interface for choose"""
    history_id = request.args.get('id', 1, type=int)
    return render_template("rule/update_github/updates_choose_changes.html" , history_id=history_id)

#################################################
# Accept_all_changes in update pannel 3 section #
#################################################
@rule_blueprint.route("/accept_all_changes", methods=['GET'])
@login_required
def accept_all_changes() -> jsonify:
    """Accept all pending changes"""
    rep = RuleModel.get_all_pending_changes()
    if rep:
        for rule_change in rep:
            if rule_change.analyzed_by_user_id != current_user.id and not current_user.is_admin():
                return jsonify({"success": False, "message": "Access denied", "toast_class": "danger-subtle"}), 403

            success = RuleModel.accept_rule_change(rule_change.id)
            if not success:
                return jsonify({"success": False, "message": "Failled to accept changes", "toast_class": "danger-subtle"}), 500
            
            # change in all the updater the statue of the concerned rule

            s = RuleModel.update_all_updater_status(rule_change.id, "accepted")
            if not s:
                return jsonify({"success": False, "message": "Failled to update updater status", "toast_class": "danger-subtle"}), 500



        return jsonify({"success": True, "message": "All changes accepted!", "toast_class": "success-subtle"}), 200
    return jsonify({"success": False, "message": "No pending changes", "toast_class": "danger-subtle"}), 404

###############################################
# Changes_decision in update pannel 3 section #
###############################################
@rule_blueprint.route("/changes_decision", methods=['GET'])
@login_required
def changes_decision() -> jsonify:
    """Update a rule from github"""
    history_id = request.args.get('history_id')
    decision = request.args.get('decision')


    history = RuleModel.get_history_rule_by_id(history_id)
    rule_ = RuleModel.get_rule(history.rule_id)
    if not rule_:
        return jsonify({"success": False, "message": "Rule not found", "toast_class": "danger-subtle"}), 404

    if current_user.is_admin() or rule_.user_id == current_user.id:
        # change all the RuleStatue from Update with this same rule_id
        succ = RuleModel.update_all_updater_status(history_id, history.message)
        if not succ:
            return jsonify({"success": False, "message": "Failled to update updater status", "toast_class": "danger-subtle"}), 500
        if decision == 'accepted':
            rule = RuleModel.get_rule(history.rule_id)

            # verify if the rule has a good syntaxe
            if not rule:
                return jsonify({"success": False, "message": "Rule not found", "toast_class": "danger-subtle"}), 404
            
            if rule:
                # is the rule with a good syntaxe ?
                valide = RuleModel.verify_rule_syntaxe(rule , history.new_content)
                if not valide.ok:
                    history.message = "rejected"
                    return jsonify({"success": True, "message": "Rule content rejected because Invalide syntax !", "toast_class": "warning-subtle"}), 200
                else:
                    rule.to_string = history.new_content
                    history.message = "accepted"
                    try:
                        from app.features.rule.rule_quality.quality_score_core import recompute_rule_quality_score
                        recompute_rule_quality_score(rule)
                    except Exception:
                        pass
                    return jsonify({"success": True, "message": "Rule content modified !", "toast_class": "success-subtle"}), 200

            return jsonify({"success": False, "message": "Rule not found", "toast_class": "danger-subtle"}), 404
        if decision == 'rejected':
            rule = RuleModel.get_rule(history.rule_id)
            if rule:
                history.message = "rejected"
        return jsonify({"success": True, "message": "No change for the rule !", "toast_class": "success-subtle"}), 200
    else:
       return jsonify({"success": False, "message": "Access denied", "toast_class": "danger-subtle"}), 403

##################################
#   CHoose changes in diff page  #
##################################
@rule_blueprint.route("/update_github_rule", methods=['GET'])
@login_required
def update_github_rule() -> render_template:
    """Update a rule from github"""
    history_id = request.args.get('rule_id')
    decision = request.args.get('decision')


    history = RuleModel.get_history_rule_by_id(history_id)
    rule_ = RuleModel.get_rule(history.rule_id)
    if not rule_:
        flash('Rule not found', 'danger')
        return redirect(safe_referrer())

    if current_user.is_admin() or rule_.user_id == current_user.id:
        if decision == 'accepted':
            rule = RuleModel.get_rule(history.rule_id)
            # verify if the rule has a good syntaxe
            if not rule:
                flash('Rule not found', 'danger')
                return redirect(safe_referrer())

            # is the rule with a good syntaxe ?
            valide = RuleModel.verify_rule_syntaxe(rule , history.new_content)
            if not valide.ok:
                history.message = "rejected"
                flash('Rule content rejected because Invalide syntax !', 'warning')
                return redirect(f"/rule/detail_rule/{rule.id}")


            if rule:
                rule.to_string = history.new_content
                history.message = "accepted"
                db.session.commit()
                flash('Rule content modified !', 'success')
                return redirect(f"/rule/detail_rule/{rule.id}")

            flash('Error , no rule found !', 'danger')
            return redirect(safe_referrer())
        if decision == 'rejected':
            rule = RuleModel.get_rule(history.rule_id)
            if rule:
                history.message = "rejected"
                db.session.commit()
        flash('No change for the rule !', 'success')
        return redirect('/rule/update_github/update_rules_from_github')
    else:
        return render_template("access_denied.html")

#########################################
#    Choose change in updater UUID page #
#########################################
@rule_blueprint.route("/update_github_rule/decision_rule", methods=['GET'])
@login_required
def decision_rule() -> jsonify:
    """Update a rule from github"""
    history_id = request.args.get('rule_id')
    decision = request.args.get('decision')
    sid = request.args.get('sid')
    
    updater = RuleModel.get_updater_result(sid)
    if not updater:
        return {"message": "Session Not found", 'toast_class': "danger-subtle"}, 404

    history = RuleModel.get_history_rule_by_id(history_id)
    if not history:
        return {"message": "History Not found", 'toast_class': "danger-subtle"}, 404
    rule_ = RuleModel.get_rule(history.rule_id)
    if not rule_:
        return {"message": "Rule Not found", 'toast_class': "danger-subtle"}, 404

    if current_user.is_admin() or rule_.user_id == current_user.id:
        if decision == 'accepted':
            mess= "Updated successfully"
        elif decision == 'rejected':
            mess= "Rejected successfully"
        else:
            return {"message": "Decision not found", 'toast_class': "danger-subtle"}, 404
        # get the rule associated to the rule statue by rule_id and change the update = false
        success_ , message_ = RuleModel.get_rule_update_from_updater_by_rule_id_and_change_statue(rule_.id, updater.id, mess, updater)

        if not success_:
            return {"message": message_, 'toast_class': "danger-subtle"}, 500

        if message_ == 'Rejected':
            decision = 'rejected'

        if decision == 'accepted':
            rule = RuleModel.get_rule(history.rule_id)
            if rule:
                rule.to_string = history.new_content
                history.message = "accepted"
                db.session.commit()
                return jsonify({
                    "message": "Rule content modified !",
                    "success": True,
                    "toast_class": "success-subtle"
                }), 200

            return jsonify({
                "message": "Error , no rule found !",
                "success": False,
                "toast_class": "danger-subtle"
            }), 500
        if decision == 'rejected':
            rule = RuleModel.get_rule(history.rule_id)
            if rule:
                history.message = "rejected"
                db.session.commit()

        return jsonify({
            "message": "Rule content rejected !",
            "success": True,
            "toast_class": "success-subtle"
        })
    else:
        return jsonify({
            "message": "Access denied !",
            "success": False,
            "toast_class": "danger-subtle"
        })

@rule_blueprint.route("/github/update_github/update_rules_from_github", methods=['GET'])
@login_required
def get_update_page() -> render_template:
    """Redirect to updating interface"""
    return render_template("rule/update_github/update_rules_from_github.html")


@rule_blueprint.route("/get_all_rules_owner")
@login_required
def get_all_rules_owner():
    search = request.args.get("search", None)
    rule_type = request.args.get("rule_type", None) 
    sourceFilter = request.args.get("source", None) 

    #sources = RuleModel.get_all_rule_sources_by_user()
    rules = RuleModel.get_all_rule_update(search=search , rule_type=rule_type , sourceFilter=sourceFilter)
    return jsonify([{"id": r.id, "title": r.title} for r in rules]), 200


@rule_blueprint.route('/get_all_sources_owner')
@login_required
def get_all_sources_owner():
    try:
        sources = RuleModel.get_all_rule_sources_by_user()

        def simplify_source(src):
            if not src:
                return None

            parsed = urlparse(src)
            if "github.com" not in parsed.netloc:
                return None  # ignore non-GitHub sources

            path = parsed.path
            if path:
                clean_path = path.rstrip('.git').strip('/')
                return clean_path
            return None

        # Simplify and filter out non-GitHub or invalid sources
        simplified_sources = [
            simplified for s in sources
            if (simplified := simplify_source(s)) is not None
        ]

        return jsonify(simplified_sources)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@rule_blueprint.route("/update_to_check", methods=['GET'])
def get_update_to_check():
    """Return the number of rule updates pending for validation"""
    if current_user.is_authenticated:
        count = RuleModel.get_update_pending()
    else:
        count = 0
    return jsonify({"count": count}), 200

@rule_blueprint.route("/get_license", methods=['GET'])
@login_required
def get_license() -> jsonify:
    """Import license"""
    licenses = []
    with open("app/features/rule/utils/import_licenses/licenses.txt", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                licenses.append(line)
    return jsonify({"licenses": licenses})



#################
#   Bad rule    #
#################

@rule_blueprint.route("/bad_rules_summary")
@login_required
def bad_rules_summary() -> render_template:
    """Get the bad rules page"""
    return render_template("rule/bad_rules_summary.html")

@rule_blueprint.route("/get_bad_rule")
@login_required
def get_bad_rule() -> jsonify:
    """Get all the bad rules ( rule with incorrect format)"""
    page = request.args.get('page', 1, type=int)
    bad_rules = BadRuleModel.get_bad_rules_page(page)
    total_rules = BadRuleModel.get_count_bad_rules_page()
    if bad_rules:
        rules_list = list()
        for rule in bad_rules:
            u = rule.to_json()
            rules_list.append(u)
        return {"rules": rules_list  , "user": current_user.first_name, "total_pages": bad_rules.pages, "total_rules": total_rules} 
    return {"message": "No Rule"}, 404

@rule_blueprint.route("/get_bads_rules_page_filter", methods=["GET"])
@login_required
def get_bads_rules_page_filter():
    """Get all the bad rules with filter and pagination."""
    params = request.args
    # page = request.args.get('page', 1, type=int)
    # search = request.args.get('search', '', type=str)
    # search_field = request.args.get('search_field', 'all', type=str)
    # error_messages = request.args.get('error_messages', '', type=str)
    # sources = request.args.get('sources', '', type=str)
    # rule_types = request.args.get('rule_types', '', type=str)
    # licenses = request.args.get('licenses', '', type=str)
    # user_id = request.args.get('user_id', type=int)

    paginated, total_rules = BadRuleModel.get_filtered_bad_rules_query(params=params)
   

    return jsonify({
        "rule": [r.to_json() for r in paginated.items],
        "total_rules": total_rules,
        "total_pages": paginated.pages,
        "user": current_user.first_name
    })

def _ai_fix_available_for(bad_rule) -> bool:
    """Gate for the "Try AI fix" button — off when the rule_fixer agent is
    disabled instance-wide, and restricted to YARA only for now: the prompt
    (rule_fixer_agent.py) and the fragment/length guard (bad_rule_core.py)
    have only been validated against real YARA rules so far, not the other
    formats' syntax quirks. This also transitively excludes script-based
    formats (Zeek/NSE) — a targeted edit to already-broken code would be
    exactly as dangerous as generating new code from scratch even if it
    were otherwise supported."""
    from app.core.db_class.db import AIAgentConfig

    if (bad_rule.rule_type or '').lower() != 'yara':
        return False
    cfg = AIAgentConfig.query.filter_by(agent_key='rule_fixer').first()
    return cfg.enabled if cfg else True


@rule_blueprint.route('/bad_rule/<int:rule_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_bad_rule(rule_id):
    """Edit a bad rule to correct it"""
    bad_rule = BadRuleModel.get_invalid_rule_by_id(rule_id)
    if bad_rule:
        if current_user.is_admin() or current_user.id == bad_rule.user_id:
            ai_fix_available = _ai_fix_available_for(bad_rule)
            if request.method == 'POST':
                new_content = request.form.get('raw_content')
                # success, error = RuleModel.process_and_import_fixed_rule(bad_rule, new_content )

                success, error , rule = process_and_import_fixed_rule(bad_rule, new_content )

                if success:
                    log_activity(
                        "rule.bad_rule_edited",
                        f"Fixed and imported invalid rule id={rule_id} as rule '{rule.title}' (id={rule.id})",
                        target_type="rule", target_id=rule.id, target_uuid=rule.uuid,
                        extra={"bad_rule_id": rule_id},
                        is_public=False,
                    )
                    flash("Rule fixed and imported successfully.", "success")
                    #return redirect(url_for('rule.bad_rules_summary'))
                    return redirect(url_for('rule.detail_rule', rule_id=rule.id))
                else:
                    flash(f"Error: {error}", "danger")
                    bad_rule.error_message = error
                    return render_template('rule/edit_bad_rule.html', rule=bad_rule, new_content=new_content,
                                           ai_fix_available=ai_fix_available)

            return render_template('rule/edit_bad_rule.html', rule=bad_rule, ai_fix_available=ai_fix_available)
        return render_template("access_denied.html")
    return render_template('404.html')


@rule_blueprint.route('/bad_rule/<int:rule_id>/ai_fix', methods=['POST'])
@login_required
def bad_rule_ai_fix(rule_id):
    """Runs the Rule Fixer agent against a bad rule's existing content and
    error message, proposing (never applying) a targeted fix — the human
    still has to explicitly click Save on the existing edit form above to
    commit it, same as a manual fix.

    Streams newline-delimited JSON events as the loop progresses (one
    {"type": "log", "message": "..."} line per step, then a final
    {"type": "result", ...} line) instead of one response at the end — the
    "Try AI fix" button otherwise just spins silently for the entire loop,
    which reads as hung, not working."""
    bad_rule = BadRuleModel.get_invalid_rule_by_id(rule_id)
    if not bad_rule:
        return jsonify({"ok": False, "error": "Not found."}), 404
    if not (current_user.is_admin() or current_user.id == bad_rule.user_id):
        return jsonify({"ok": False, "error": "Forbidden."}), 403
    if not _ai_fix_available_for(bad_rule):
        return jsonify({"ok": False, "error": "AI fix isn't available for this rule."}), 400

    # The generator body runs later, once werkzeug actually starts iterating
    # the streamed response — by then the request context that created
    # `bad_rule`/`current_user` has already been torn down (stream_with_context
    # pushes a fresh one just for iteration), so anything fetched via the old
    # session is detached. Re-fetch by plain id inside the generator instead
    # of carrying the ORM objects across that boundary.
    bad_rule_id = bad_rule.id
    user_id = current_user.id

    def generate():
        from app.core.db_class.db import User
        fresh_bad_rule = BadRuleModel.get_invalid_rule_by_id(bad_rule_id)
        fresh_user = User.query.get(user_id)
        for event in BadRuleModel.run_ai_fix_streaming(fresh_bad_rule, fresh_user):
            yield json.dumps(event) + "\n"

    return Response(stream_with_context(generate()), mimetype='application/x-ndjson')

@rule_blueprint.route('/bad_rule/<int:rule_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_bad_rule(rule_id) -> jsonify:
    """Delete a bad rule (error from import)"""
    bad_rule = BadRuleModel.get_invalid_rule_by_id(rule_id)
    if bad_rule:
        if current_user.is_admin() or current_user.id == bad_rule.user_id :
            if request.method == 'POST':
                success = BadRuleModel.delete_bad_rule(rule_id)
                if success:
                    log_activity(
                        "rule.bad_rule_deleted",
                        f"Deleted invalid rule id={rule_id}",
                        extra={"bad_rule_id": rule_id},
                        is_public=False,
                    )
                    return jsonify({"success": True, "message": "Rule deleted!" , "toast_class": "success-subtle"}), 200
            return render_template('rule/edit_bad_rule.html', rule=bad_rule)
        return render_template("access_denied.html")
    return render_template("404.html")
    
@rule_blueprint.route('/bad_rule/delete_all_bad_rule', methods=['GET', 'POST'])
@login_required
def delete_all_bad_rule() -> jsonify:
    """
    Delete bad rules based on the active filters provided in the request.
    If no filters are provided, it clears all bad rules for the user (or all if admin).
    """
    filters = {
        'search': request.args.get('search', '', type=str),
        'search_field': request.args.get('search_field', 'all', type=str),
        'error_messages': request.args.get('error_messages', '', type=str),
        'sources': request.args.get('sources', '', type=str),
        'rule_types': request.args.get('rule_types', '', type=str),
        'user_id': request.args.get('user_id', type=int)
    }

    try:
        deleted_count = BadRuleModel.delete_all_bad_rules(filters)

        if deleted_count is None:
            return jsonify({
                "success": False,
                "toast_class": 'danger',
                "message": "System error during deletion."
            }), 500

        if deleted_count == 0:
             return jsonify({
                "success": True,
                "toast_class": 'info',
                "message": "No rules matched the filters to delete."
            }), 200

        log_activity(
            "rule.bad_rule_deleted",
            f"Bulk deleted {deleted_count} invalid rule(s)",
            extra={"deleted_count": deleted_count, "filters": filters},
            is_public=False,
        )
        return jsonify({
            "success": True,
            "toast_class": 'success',
            "message": f"Successfully deleted {deleted_count} rules!"
        }), 200

    except Exception as e:
        return jsonify({ 
            "success": False,
            "toast_class": 'danger',
            "message": f"System error during deletion: {str(e)}"
        }), 500


@rule_blueprint.route('/bad_rule/delete_list', methods=['POST'])
@login_required
def delete_bad_rule_list() -> jsonify:
    """Bulk-delete a specific set of invalid rules by id — the selection-based
    counterpart to delete_all_bad_rule's filter-based bulk delete, used by
    BadRuleList's mode='manage' bulk bar."""
    data = request.get_json() or {}
    rule_ids = data.get('ids', [])
    if not rule_ids:
        return jsonify({"success": False, "message": "No rules selected.", "toast_class": "danger"}), 400

    deleted_count = BadRuleModel.delete_bad_rules_by_ids(rule_ids)

    log_activity(
        "rule.bad_rule_deleted",
        f"Bulk deleted {deleted_count} invalid rule(s) by selection",
        extra={"bad_rule_ids": rule_ids, "deleted_count": deleted_count},
        is_public=False,
    )
    return jsonify({
        "success": True,
        "toast_class": "success-subtle",
        "message": f"Deleted {deleted_count} rule(s)." if deleted_count else "No matching rules to delete."
    }), 200


@rule_blueprint.route('/get_bad_rules_sources_usage', methods=['GET'])
def get_bad_rules_sources_usage():
    user_id = request.args.get('user_id', type=int)
    
    sources = BadRuleModel.get_sources_usage(user_id)
    
    return sources

# /get_bad_rules_error_messages_usage
@rule_blueprint.route('/get_bad_rules_error_messages_usage', methods=['GET'])
def get_bad_rules_error_messages_usage():
    user_id = request.args.get('user_id', type=int)
    
    error_messages = BadRuleModel.get_error_messages_usage(user_id)
    
    return error_messages
@rule_blueprint.route('/get_bad_rules_licenses_usage', methods=['GET'])
def get_bad_rules_licenses_usage():
    user_id = request.args.get('user_id', type=int)

    licenses = BadRuleModel.get_licenses_usage(user_id)

    return licenses

@rule_blueprint.route('/get_bad_rules_users_usage', methods=['GET'])
@login_required
def get_bad_rules_users_usage():
    """Distinct users with an invalid rule in the given source/format scope —
    feeds BadRuleList's Editor filter dropdown. Admin-only: a non-admin is
    always scoped to their own invalid rules (see get_filtered_bad_rules_query),
    so a cross-user listing wouldn't be usable to them anyway, and it would
    otherwise leak other users' identities/activity for no reason."""
    if not current_user.is_admin():
        return jsonify([])
    source    = request.args.get('sources', None, type=str)
    rule_type = request.args.get('rule_types', None, type=str)
    return jsonify(BadRuleModel.get_users_usage(source=source, rule_type=rule_type))


#####################
#   Repport rule    #
#####################

@rule_blueprint.route('/report/<int:rule_id>', methods=['GET', 'POST'])
@login_required
def report(rule_id):
    from flask import redirect
    return redirect(f'/rule/detail_rule/{rule_id}')

@rule_blueprint.route('/get_rule', methods=['GET', 'POST'])
@login_required
def get_rule() -> jsonify:
    """Return the rule info"""
    rule_id = request.args.get('rule_id', 1, type=int)
    rule = RuleModel.get_rule(rule_id)
    if rule :
        return {"rule": rule.to_json(),"success": True}, 200 
    return {"success": False}, 500 

@rule_blueprint.route('/report_rule', methods=['POST'])
@login_required
def report_rule():
    """Legacy endpoint — forward to unified report system."""
    from app.features.report.report_core import create_report, notify_admins, VALID_REASONS
    data      = request.get_json(silent=True) or {}
    rule_id   = data.get('rule_id')
    reason    = (data.get('reason') or '').strip()
    message   = (data.get('message') or '').strip()
    if not rule_id or not reason:
        return jsonify({'success': False, 'message': 'rule_id and reason required',
                        'toast_class': 'danger-subtle'}), 400
    try:
        rpt, is_new = create_report(current_user.id, 'rule', int(rule_id), reason, message)
        if is_new:
            notify_admins(rpt, current_user)
        return jsonify({'success': True, 'message': 'Report submitted.',
                        'toast_class': 'success-subtle'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e),
                        'toast_class': 'danger-subtle'}), 500

@rule_blueprint.route('/admin/rules_reported', methods=['GET'])
@login_required
def rules_repported():
    from flask import redirect
    return redirect('/report/admin')

@rule_blueprint.route("/repport_to_check")
def repport_to_check():
    from flask import redirect
    return redirect('/report/count')
    

################
#   History    #
################

@rule_blueprint.route("/get_rules_page_history_", methods=['GET'])
def get_rules_page_history_():
    """Get the history of the rule with HTML diff for each version"""
    page = request.args.get('page', type=int)
    rule_id = request.args.get('rule_id', type=int)
    per_page = request.args.get('per_page',5 ,type=int)

    rules = RuleModel.get_history_rule_(page, rule_id, per_page)

    if not rules.items:
        return jsonify({
            "success": True,
            "rule": [],
            "total_pages": None
        }), 200


    result = []
    for rule in rules.items:
        # Safely handle None
        old_content = rule.old_content or ""
        new_content = rule.new_content or ""

        analyzed_by = rule.analyzed_by
        rule_data = {
            "id": rule.id,
            "rule_title": rule.rule_title,
            "analyzed_at": rule.analyzed_at.strftime("%Y-%m-%d %H:%M") if rule.analyzed_at else "",
            "message": RuleModel.humanize_history_message(rule.message),
            "old_content": old_content,
            "new_content": new_content,
            "rule_id": rule.rule_id,
            "success": rule.success,
            "manuel_submit": bool(rule.manuel_submit),
            "analyzed_by_user_id": analyzed_by.id if analyzed_by else None,
            "analyzed_by_name": (f"{analyzed_by.first_name} {analyzed_by.last_name}".strip() if analyzed_by else None),
            "analyzed_by_avatar": (analyzed_by.get_avatar_url() if analyzed_by else None),
            "change_type": rule.change_type,
            "metadata_changes": RuleModel.diff_rule_snapshots(rule.old_snapshot, rule.new_snapshot),
        }
        result.append(rule_data)

    return jsonify({
        "success": True,
        "rule": result,
        "total_pages": rules.pages
    }), 200


@rule_blueprint.route("/get_rule_changes", methods=['GET'])
def get_rule_changes()-> render_template:
    """Get the history of the rule"""
    page = request.args.get('page', type=int)
    search = request.args.get('search', type=str)
    rules = RuleModel.get_old_rule_choice(page, search)
    if rules:
        return {"success": True,
                "rule": [rule.to_json() for rule in rules],
                "total_pages": rules.pages,
                "total_rules": rules.total
            }, 200
    return {"message": "No Rule"}, 404




####################
#   Rule formats   #
####################

@rule_blueprint.route("/replace_format_rule", methods=["POST"])
@login_required
def replace_format_rule():
    """Replace format for multiple rules"""
    if not current_user.is_admin():
        return render_template("access_denied.html")

    current_format = request.form.get("current_format")
    new_format = request.form.get("new_format")

    if not current_format or not new_format:
        flash("Both fields are required.", "warning")
        return redirect(url_for("rule.manage_format_rule"))
    
    if current_format == new_format:
        flash("Current format and new format cannot be the same.", "warning")
        return redirect(url_for("rule.manage_format_rule"))
    

    if not RuleModel.exists_format_in_rules(current_format):
        flash(f"Current format '{current_format}' does not exist.", "warning")
        return redirect(url_for("rule.manage_format_rule"))


    # update rules
    updated_count = RuleModel.replace_rule_format(current_format, new_format)

    if updated_count is None:
        flash("Error occurred while updating formats.", "error")
    else:
        log_activity(
            "admin.replace_format",
            f"Replaced format '{current_format}' → '{new_format}' on {updated_count} rule(s)",
            extra={"old_format": current_format, "new_format": new_format, "updated_count": updated_count},
            is_public=False,
        )
        flash(f"{updated_count} rule(s) updated from '{current_format}' to '{new_format}'.", "success")
    return redirect(url_for("rule.manage_format_rule"))


@rule_blueprint.route("/formats_data_table", methods=['GET'])
def formats_data_table():
    """Paginated + searchable format list for the admin component."""
    from app.core.db_class.db import FormatRule
    page     = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    search   = (request.args.get('search', '') or '').strip()
    sort_by  = request.args.get('sort', 'creation_date')
    sort_dir = request.args.get('dir', 'desc')
    from sqlalchemy import asc, desc
    query = FormatRule.query
    if search:
        query = query.filter(FormatRule.name.ilike(f'%{search}%'))
    _sort_map = {'creation_date': FormatRule.creation_date, 'name': FormatRule.name, 'id': FormatRule.id}
    sort_col  = _sort_map.get(sort_by, FormatRule.creation_date)
    query     = query.order_by(desc(sort_col) if sort_dir == 'desc' else asc(sort_col))
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        'items': [f.to_json() for f in pagination.items],
        'total': pagination.total,
        'total_pages': pagination.pages,
    })


@rule_blueprint.route("/create_format_json", methods=['POST'])
@login_required
def create_format_json():
    """JSON endpoint to create a new rule format."""
    if not current_user.is_admin():
        return jsonify(success=False, message="Access denied"), 403
    data           = request.get_json(silent=True) or {}
    format_name    = (data.get('name') or '').strip()
    can_be_execute = bool(data.get('can_be_execute', False))
    if not format_name:
        return jsonify(success=False, message="Format name is required"), 400
    success, message = RuleModel.add_format_rule(format_name, current_user.id, can_be_execute)
    if success:
        log_activity(
            "tag.create",
            f"Created rule format '{format_name}'",
            extra={"format_name": format_name, "can_be_execute": can_be_execute},
            is_public=False,
        )
    return jsonify(success=success, message=message), (200 if success else 409)


@rule_blueprint.route("/rename_format_json", methods=['POST'])
@login_required
def rename_format_json():
    """JSON endpoint to rename a format across all rules."""
    if not current_user.is_admin():
        return jsonify(success=False, message="Access denied"), 403
    data           = request.get_json(silent=True) or {}
    current_format = (data.get('current_format') or '').strip()
    new_format     = (data.get('new_format') or '').strip()
    if not current_format or not new_format:
        return jsonify(success=False, message="Both fields are required"), 400
    if current_format == new_format:
        return jsonify(success=False, message="New name must differ from the current name"), 400
    updated = RuleModel.replace_rule_format(current_format, new_format)
    log_activity(
        "admin.replace_format",
        f"Renamed format '{current_format}' → '{new_format}' on {updated} rule(s)",
        extra={"old_format": current_format, "new_format": new_format, "updated_count": updated},
        is_public=False,
    )
    return jsonify(success=True, message=f"{updated} rule(s) updated from '{current_format}' to '{new_format}'.", updated=updated)


@rule_blueprint.route("/get_rules_formats", methods=['GET'])
def get_rules_format() -> dict:
    formats = RuleModel.get_all_rule_format()
    if formats:
        return {"success": True, "formats": formats, "length": len(formats)}, 200
    return {"message": "No formats"}, 404

@rule_blueprint.route("/get_last_cve_rules", methods=['GET'])
def get_last_cve_rules() -> dict:
    rules = RuleModel.get_last_cve_rules()
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
        from app.core.db_class.db import RuleVote as _RV2
        votes_map2 = {v.rule_id: v.vote_type for v in _RV2.query.filter(
            _RV2.rule_id.in_(rule_ids), _RV2.user_id == current_user.id
        ).all()}
        for item in serialized:
            item['user_vote'] = votes_map2.get(item['id'])
    else:
        for item in serialized:
            item['user_vote'] = None

    return {"success": True, "rules": serialized, "length": len(serialized)}, 200

@rule_blueprint.route("/admin/manage_format_rule", methods=["GET", "POST"])
@login_required
def manage_format_rule() -> render_template:
    if not current_user.is_admin():
        return render_template("access_denied.html")

    form = CreateFormatRuleForm()

    if form.validate_on_submit():
        format_name = form.name.data.strip()
        can_be_execute = form.can_be_execute.data or False

        success, message = RuleModel.add_format_rule(
            format_name=format_name,
            user_id=current_user.id,
            can_be_execute=can_be_execute
        )

        flash(message, "success" if success else "danger")

        if success:
            return render_template("admin/format.html", form=form)

    return render_template("admin/format.html", form=form)

@rule_blueprint.route("/get_rules_formats_pages", methods=['GET'])
def get_rules_formats_pages() -> dict:
    """Get the rules formats pages"""
    page = request.args.get('page', type=int, default=1)
    _formats = RuleModel.get_all_rule_format_page(page)

    if _formats.items:  
        return {
            "success": True,
            "rules_formats": [f.to_json() for f in _formats.items],
            "total_rules_formats": _formats.pages
        }, 200
    return {"message": "No formats"}, 404


@rule_blueprint.route('/delete_format_rule', methods=['GET'])
@login_required
def delete_format_rule():
    id = request.args.get('id', type=int)
    if not current_user.is_admin():
        return jsonify(success=False, message="Access denied"), 403

    format_rule = RuleModel.get_rule_format_with_id(id)
    if not format_rule:
        return jsonify(success=False, message="Format not found"), 404
    
    rule_with_this_format = RuleModel.get_all_rule_with_this_format(format_rule.name)
    if rule_with_this_format:
        for rule in rule_with_this_format:
            rule.format = "No format"
    else:
        {"message": "Failled to change format",
            "success": False,
            "toast_class": "danger-subtle"}, 500
    

    success = RuleModel.delete_format(id)
    if success:
        return {"success": True,
                "message": "Format delete",
                "toast_class": "success-subtle"
            }, 200
    return {"message": "Failled to delete format",
            "success": False,
            "toast_class": "danger-subtle"}, 500

#
#   First attempt to parse all the rule in a github project (YARA)
#
#   to add and fix :
#       - import module on the top of the rule (pe)
#       - import licence and url in the parse_meta method (use **kwargs to give them)
#       - comment bug (found a solution to not mix a rule corp and a comment section)
#       - external variable ?
#
@rule_blueprint.route("/parse_rule", methods=['GET','POST'])
@login_required
def parse_rule() -> dict:
    """Parse a single rule to test if it's valid"""
    rule_content = request.form.get('content')
    format = request.form.get('format')
    if not format:
        flash(" Format is required", "danger")
        return redirect(url_for("rule.rule", tab="parse"))

    if not rule_content:
        flash(" Content is required", "danger")
        return redirect(url_for("rule.rule", tab="parse"))
    
    success , message, object_ = parse_rule_by_format(rule_content, current_user, format, None)


    if success == False:
        if object_ is None:
            flash( message , "danger")
            return redirect(url_for("rule.bad_rules_summary"))
        else:
            flash( message , "warning")
            return redirect(url_for("rule.detail_rule", rule_id=object_.id))

    

    flash(f"Rules imported.", "success")
    return redirect(url_for("rule.detail_rule", rule_id=object_.id))


@rule_blueprint.route("/import_from_json", methods=['POST'])
@login_required
def import_rule_from_json():
    """Import a single rule from its pasted JSON export.

    Only a strict allowlist of identity fields is read out of the parsed
    JSON — everything else (id, user_id, votes, status, ...) is ignored.
    `user_id` is never taken from the pasted JSON: add_rule_core() always
    resolves it from the authenticated current_user for a live request,
    exactly like the Manual tab. Syntax validation and content-hash
    dedup reuse the same helpers as Manual/Parse; a uuid-based dedup
    check is added here since add_rule_core() only dedups by content.
    """
    raw = request.form.get('rule_json', '')

    if not raw or not raw.strip():
        flash('Paste the rule JSON first.', 'danger')
        return redirect(url_for('rule.rule', tab='json'))

    if len(raw) > 300_000:
        flash('That JSON is too large to import.', 'danger')
        return redirect(url_for('rule.rule', tab='json'))

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        flash(f'Invalid JSON: {e.msg} (line {e.lineno}, column {e.colno}).', 'danger')
        return redirect(url_for('rule.rule', tab='json'))

    if not isinstance(parsed, dict):
        flash('The pasted JSON must be a single rule object.', 'danger')
        return redirect(url_for('rule.rule', tab='json'))

    def _clean_str(value):
        return str(value).strip() if isinstance(value, (str, int, float)) else ''

    rule_dict = {
        'format':        _clean_str(parsed.get('format')),
        'title':         _clean_str(parsed.get('title')),
        'to_string':     str(parsed.get('to_string') or ''),
        'license':       _clean_str(parsed.get('license')),
        'description':   _clean_str(parsed.get('description')),
        'source':        _clean_str(parsed.get('source')),
        'author':        _clean_str(parsed.get('author')),
        'version':       _clean_str(parsed.get('version')),
        'original_uuid': _clean_str(parsed.get('uuid') or parsed.get('original_uuid')),
        'cve_id':        parsed.get('cve_id') if isinstance(parsed.get('cve_id'), (str, list)) else None,
    }

    if not rule_dict['title'] or not rule_dict['format'] or not rule_dict['to_string']:
        flash('The JSON must include at least "title", "format" and "to_string".', 'danger')
        return redirect(url_for('rule.rule', tab='json'))

    candidate_uuid = rule_dict['original_uuid']
    if candidate_uuid:
        from app.core.db_class.db import Rule
        existing = RuleModel._active().filter(
            (Rule.uuid == candidate_uuid) | (Rule.original_uuid == candidate_uuid)
        ).first()
        if existing:
            flash(f'A rule with this UUID already exists: "{existing.title}".', 'danger')
            return redirect(url_for('rule.rule', tab='json'))

    valide, error = verify_syntax_rule_by_format(rule_dict)
    if valide == False:
        flash(error, 'danger')
        return redirect(url_for('rule.rule', tab='json'))

    rule_dict = fill_all_void_field(rule_dict)

    new_rule, message = RuleModel.add_rule_core(rule_dict, current_user)
    if new_rule:
        profil_game_user = AccountModel.get_or_create_gamification_profile(current_user.id)
        if profil_game_user:
            AccountModel.update_rules_owned_gamification(profil_game_user.id, current_user.id)
        flash('Rule imported from JSON!', 'success')
        return redirect(url_for('rule.detail_rule', rule_id=new_rule.id))
    elif isinstance(message, str) and message.startswith("TRASH_CONFLICT:"):
        parts   = message.split(":", 3)
        t_uuid  = parts[1] if len(parts) > 1 else ''
        t_id    = parts[2] if len(parts) > 2 else ''
        t_title = parts[3] if len(parts) > 3 else 'deleted rule'
        flash(f'TRASH_CONFLICT:{t_uuid}:{t_id}:{t_title}', 'warning')
        return redirect(url_for('rule.rule', tab='json'))
    else:
        flash(message, 'danger')
        return redirect(url_for('rule.rule', tab='json'))


@rule_blueprint.route("/get_github_branches", methods=['GET'])
@login_required
def get_repo_branches():
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({'success': False, 'branches': [], 'error': 'No URL provided.'}), 400
    branches, error = get_github_branches(url)
    if error:
        return jsonify({'success': False, 'branches': [], 'error': error}), 200
    return jsonify({'success': True, 'branches': branches}), 200


@rule_blueprint.route("/import_rules_from_github", methods=['POST'])
@login_required
def import_rules_from_github():
    """
    Clone or access a GitHub repo, then test all YARA rules in it,
    creating rules and classifying bad rules automatically.

    The clone/scan/import all happen in a background thread — this view
    only validates the URL and returns a session_uuid right away, so the
    caller can redirect to the loading page immediately instead of being
    stuck waiting (potentially minutes, for a big repo) on this request.
    """
    if not current_user.is_admin():
        return {"message": "Admin access required. Non-admins can submit a proposal instead.", "toast_class": "danger-subtle"}, 403
    try:
        repo_url = request.json.get('url')
        selected_license = request.json.get('license')
        branch = (request.json.get('branch') or '').strip() or None

        verif = valider_repo_github(repo_url)
        if not verif:
            return {"message": "Please enter a valid URL to import rules.", "toast_class": "danger-subtle"}, 400

        info = {"origin": "github", "url": repo_url, "repo_url": repo_url}
        if branch:
            info['branch'] = branch

        session_th = SessionModel.Session_class(None, current_user, info)
        SessionModel.sessions.append(session_th)

        app_obj = current_app._get_current_object()
        user_obj = current_user._get_current_object()

        def _run_github_import():
            with app_obj.app_context():
                try:
                    # user_obj was loaded on the request's own (now-torn-down)
                    # session — re-merge it into this thread's fresh session
                    # before touching any attribute (id, username, …), same
                    # as Session_class.process() already does for its own
                    # worker thread. Skipping this raises DetachedInstanceError
                    # on first attribute access, which used to abort the whole
                    # import (surfaced to the loading page as "Import failed").
                    local_user = db.session.merge(user_obj)

                    repo_dir, _ = clone_or_access_repo(repo_url, branch=branch)
                    if not repo_dir:
                        raise Exception("Failed to clone or access the repository.")

                    full_info = github_repo_metadata(repo_url, selected_license)
                    if branch:
                        full_info['branch'] = branch
                    session_th.repo_dir = repo_dir
                    session_th.info = full_info

                    session_th.start(app_obj=app_obj, user_obj=local_user)

                    try:
                        from app.features.notification.notification_core import notify_admins_session_started
                        notify_admins_session_started(
                            user         = local_user,
                            session_type = 'github_import',
                            session_uuid = session_th.uuid,
                            label        = f'GitHub import running — {repo_url}',
                            link         = '/rule/github/manage',
                        )
                    except Exception as _e:
                        print(f"[rule] notify_admins_session_started (import) error: {_e}")

                    branch_label = f" (branch: {branch})" if branch else ""
                    log_activity("github.import_started",
                                 f"Started GitHub import from '{repo_url}'{branch_label}",
                                 target_type="github_import",
                                 target_uuid=session_th.uuid,
                                 extra={"url": repo_url, "branch": branch},
                                 is_public=True,
                                 icon="fa-brands fa-github",
                                 actor_id=local_user.id)
                except Exception as e:
                    session_th.error = str(e)
                    session_th.phase = 'error'

        Thread(target=_run_github_import, daemon=True).start()

        return {"message": "Go !", "toast_class": "success-subtle", "session_uuid": session_th.uuid}, 201
    except Exception as e:
        return {"message": f"An error occurred during import: {str(e)}", "toast_class": "danger-subtle"}, 400
    
@rule_blueprint.route("/import_rules_from_zip", methods=["POST"])
@login_required
def import_rules_from_zip():
    """
    Import and process all YARA rules inside an uploaded ZIP file.
    The ZIP is extracted into a temp folder, and processed the same way
    as GitHub repositories were.
    """
    if not current_user.is_admin():
        return {"message": "Admin access required.", "toast_class": "danger-subtle"}, 403

    try:

        if 'zipfile' not in request.files:
            return {"message": "No ZIP file provided.", "toast_class": "danger-subtle"}, 400

        zip_file = request.files['zipfile']
        selected_license = request.form.get('license')

        if not zip_file:
            return {"message": "No ZIP file provided.", "toast_class": "danger-subtle"}, 400

      
        filename = zip_file.filename
       

        temp_dir = tempfile.mkdtemp(prefix="rules_zip_")

        with zipfile.ZipFile(zip_file) as z:
            total_size = sum(m.file_size for m in z.infolist())
            if total_size > 500 * 1024 * 1024:
                return {"message": "ZIP too large when uncompressed (max 500 MB).", "toast_class": "danger"}, 400
            real_temp = os.path.realpath(temp_dir)
            for member in z.infolist():
                dest = os.path.realpath(os.path.join(real_temp, member.filename))
                if not dest.startswith(real_temp + os.sep) and dest != real_temp:
                    return {"message": "Invalid ZIP: path traversal detected.", "toast_class": "danger"}, 400
            z.extractall(temp_dir)

        repo_dir = temp_dir  
        if filename:
            source = filename + " by " + current_user.first_name + " " + current_user.last_name  
        else:
            source = " File uploaded by " + current_user.first_name + " " + current_user.last_name

        info = {
            "origin": "zip_upload",
            "name": os.path.basename(temp_dir),
            "license": selected_license or "Unknown",
            "url": "zip_upload",
            "repo_url": source
        }

        session_th = SessionModel.Session_class(repo_dir, current_user, info)
        session_th.start()
        SessionModel.sessions.append(session_th)

        log_activity("github.import_started",
                     f"Started ZIP import '{source}'",
                     target_type="github_import",
                     target_uuid=session_th.uuid,
                     extra={"source": source},
                     is_public=True,
                     icon="fa-solid fa-file-zipper")
        return {
            "message": "ZIP uploaded and processing started!",
            "toast_class": "success-subtle",
            "session_uuid": session_th.uuid
        }, 201

    except Exception as e:
        return {
            "message": f"Error while importing ZIP: {str(e)}",
            "toast_class": "danger-subtle"
        }, 400


@rule_blueprint.route("/import_loading/<sid>", methods=['GET'])
@login_required
def import_loading(sid):
    for s in SessionModel.sessions:
        if s.uuid == sid:
            return render_template("rule/url_github/import_loading.html", sid=sid)
    r = RuleModel.get_importer_result(sid)
    if r:
        return render_template("rule/url_github/import_loading.html", sid=sid)
    return render_template("404.html"), 404

@rule_blueprint.route("/import_loading_status/<sid>", methods=['GET'])
@login_required
def import_loading_status(sid):
    is_finished = request.args.get('is_finished', 'false', type=str)
    if not is_finished == 'true':
        for s in SessionModel.sessions:
            if s.uuid == sid:
                return jsonify(s.status())
        
    r = RuleModel.get_importer_result(sid)
    if r:
        loc = r.to_json()
        loc["complete"] = loc["total"]
        loc["remaining"] = 0
        
        
        # update the gamification section 
        profil_game_user_ = AccountModel.get_or_create_gamification_profile(r.user_id)
        if profil_game_user_:   
            _ = AccountModel.update_rules_owned_gamification(profil_game_user_.id, r.user_id)

        return loc
    return {"message": "Session Not found", 'toast_class': "danger-subtle"}, 404

@rule_blueprint.route("/import_get_info_session/<sid>", methods=['GET'])
@login_required
def import_get_info_session(sid):
    for s in SessionModel.sessions:
        if s.uuid == sid:
            return jsonify(s.info)
        
    r = RuleModel.get_importer_result(sid)
    if r:
        return json.loads(r.info)
    return {"message": "Session Not found", 'toast_class': "danger-subtle"}, 404

@rule_blueprint.route("/github/manage", methods=['GET'])
@login_required
def manage_github():
    return render_template("rule/url_github/manage_github.html")


@rule_blueprint.route("/github_proposal_detail/<uuid>", methods=['GET'])
@login_required
def github_proposal_detail_page(uuid):
    from app.features.rule.rule_from_github.proposal import proposal_core as ProposalModel
    proposal = ProposalModel.get_proposal_by_uuid(uuid)
    if not proposal:
        return render_template("404.html"), 404
    if current_user.id != proposal.user_id and not current_user.is_admin():
        return render_template("access_denied.html"), 403
    return render_template("rule/url_github/proposal_detail.html", proposal_uuid=uuid)


@rule_blueprint.route("/github/history_github_importer", methods=['GET'])
@login_required
def history_github_importer():
    # Old URL — kept as a permanent redirect so bookmarks/links still work.
    return redirect(url_for('rule.manage_github'), code=301)


@rule_blueprint.route("/history_github_importer/list", methods=['GET'])
@login_required
def history_github_importer_list():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '', type=str).strip()
    sort = request.args.get('sort', 'query_date', type=str)
    direction = request.args.get('dir', 'desc', type=str)
    github_importer_list = RuleModel.get_importer_list_page(page, per_page, search, sort, direction)

    return {"history": [g.to_json() for g in github_importer_list],
            "total_history": github_importer_list.total,
            "total_pages": github_importer_list.pages}, 200

@rule_blueprint.route("/history_github_importer/find_page", methods=['GET'])
@login_required
def find_history_page():
    """Return the page number where a given session UUID appears in the history."""
    from app.core.db_class.db import ImporterResult, UpdateResult
    uuid_param = request.args.get('uuid', type=str)
    kind       = request.args.get('type', 'import')   # 'import' | 'update'
    per_page   = 20

    if not uuid_param:
        return jsonify({"page": 1})

    if kind == 'import':
        target = ImporterResult.query.filter_by(uuid=uuid_param).first()
        if not target:
            return jsonify({"page": 1})
        rank = ImporterResult.query.filter(ImporterResult.id <= target.id).count()
        page = (rank - 1) // per_page + 1
    else:
        target = UpdateResult.query.filter_by(uuid=uuid_param).first()
        if not target:
            return jsonify({"page": 1})
        if current_user.is_admin():
            rank = UpdateResult.query.filter(UpdateResult.id <= target.id).count()
        else:
            rank = UpdateResult.query.filter(
                UpdateResult.id <= target.id,
                UpdateResult.user_id == str(current_user.id)
            ).count()
        page = (rank - 1) // per_page + 1

    return jsonify({"page": max(1, page)})


@rule_blueprint.route("/history_github_importer/delete", methods=['GET'])
@login_required
def history_github_importer_delete():
    if current_user.is_admin() == False:
        return {"message": "Access denied", "toast_class": "danger-subtle"}, 403
    history_github_importer_id = request.args.get('uuid', type=str)
    if not history_github_importer_id:
        return {"message": "Missing uuid", "toast_class": "danger-subtle"}, 400
    success, msg = RuleModel.delete_importer_history(history_github_importer_id)

    if success:
        return {"message": msg, "toast_class": "success-subtle"}, 200
    return {"message": msg, "toast_class": "danger-subtle"}, 500


@rule_blueprint.route("/import_get_session_running", methods=['GET'])
@login_required
def import_get_session_running():
    """Return the running sessions by uuid and info (admin or user case )"""
    
    is_admin = current_user.is_admin()
    current_user_id = current_user.id

    import_sessions = [
        {"uuid": s.uuid, "info": s.info} 
        for s in SessionModel.sessions
        if is_admin or s.current_user.id == current_user_id
    ]

    update_sessions = [
        {"uuid": s.uuid, "info": s.info} 
        for s in UpdateModel.sessions
        if is_admin or s.current_user.id == current_user_id
    ]

    return {
        "import_sessions": import_sessions,
        "update_sessions": update_sessions
    }


#############
#   Update  #
#############

@rule_blueprint.route("/history_github_updater/list", methods=['GET'])
@login_required
def history_github_updater_list():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '', type=str).strip()
    mode = request.args.get('mode', '', type=str)
    sort = request.args.get('sort', 'query_date', type=str)
    direction = request.args.get('dir', 'desc', type=str)
    github_updater_list = RuleModel.get_updater_list_page(page, per_page, search, mode, sort, direction)

    return {"history": [g.to_json_list() for g in github_updater_list], 
            "total_history": github_updater_list.total, 
            "total_pages": github_updater_list.pages}, 200

@rule_blueprint.route("/update_loading/<sid>", methods=['GET'])
@login_required
def update_loading(sid):
    for s in UpdateModel.sessions:
        if s.uuid == sid:
            return render_template("rule/update_github/update_loading.html", sid=sid)
    r = RuleModel.get_updater_result(sid)
    if r:
        return render_template("rule/update_github/update_loading.html", sid=sid)
    return render_template("404.html"), 404

@rule_blueprint.route("/update_loading_status/<sid>", methods=['GET'])
@login_required
def update_loading_status(sid):
    is_finished = request.args.get('is_finished', 'false', type=str)
    if not is_finished == 'true':
        for s in UpdateModel.sessions:
            if s.uuid == sid:
                return jsonify(s.status())
        
    r = RuleModel.get_updater_result(sid)

    if r:
        loc = r.to_json_list()
        loc["complete"] = loc["total"]
        loc["remaining"] = 0
        return loc
    return {"message": "Session Not found", 'toast_class': "danger-subtle"}, 404


@rule_blueprint.route("/update_loading_status/<sid>/get_news_rules", methods=['GET'])
@login_required
def get_news_rules(sid):
    def _tri(key):
        v = request.args.get(key, '')
        return True if v == 'true' else False if v == 'false' else None

    page = request.args.get('page', 1, type=int)
    paginated = RuleModel.get_updater_result_new_rule_page(
        sid, page=page,
        f_syntax_valid=_tri('syntax_valid'),
        f_accept=_tri('accept'),
        f_error=_tri('error'),
    )

    if not paginated:
        return {"message": "Session not found", "toast_class": "danger-subtle"}, 404
    rules = paginated.items
    rules_list = [rule.to_json() for rule in rules]
    return {
        "rules": rules_list,
        "total_pages": paginated.pages,
        "total_rules": paginated.total,
    }, 200

@rule_blueprint.route("/history_github_updater/delete", methods=['GET'])
@login_required
def history_github_updater_delete():
    if current_user.is_admin() == False:
        return {"message": "Access denied", "toast_class": "danger-subtle"}, 403
    history_github_updater_id = request.args.get('uuid', type=str)
    if not history_github_updater_id:
        return {"message": "Missing uuid", "toast_class": "danger-subtle"}, 400
    success, msg = RuleModel.delete_updater_history(history_github_updater_id)

    if success:
        return {"message": msg, "toast_class": "success-subtle"}, 200
    return {"message": msg, "toast_class": "danger-subtle"}, 500

@rule_blueprint.route("/update_loading_status/<sid>/get_rules", methods=['GET'])
@login_required
def get_rules(sid):
    def _tri(key):
        v = request.args.get(key, '')
        return True if v == 'true' else False if v == 'false' else None

    page = request.args.get('page', 1, type=int)

    paginated = RuleModel.get_updater_result_rule_page(
        sid, page=page,
        f_update_available=_tri('update_available'),
        f_found=_tri('found'),
        f_error=_tri('error'),
        f_syntax_valid=_tri('syntax_valid'),
    )
    if not paginated :
        return {"message": "Session not found", "toast_class": "danger-subtle"}, 404

    rules = paginated.items

    updates_available = RuleModel.count_updates_available(sid)
    up_to_date        = RuleModel.count_up_to_date(sid)
    not_found          = RuleModel.count_rules_not_found(sid)
    if rules:
        rules_list = [rule.to_json() for rule in rules]
        return {
            "rules": rules_list,
            "total_pages": paginated.pages,
            "total_rules": paginated.total,
            "updates_available": updates_available,
            "up_to_date": up_to_date,
            "not_found": not_found,
        }, 200
    return {
        "rules": [],
        "updates_available": updates_available,
        "up_to_date": up_to_date,
        "not_found": not_found,
    }, 200

# accetped all change associate to a sid
@rule_blueprint.route("/bulk_update_decision/<sid>", methods=['POST'])
@login_required
def bulk_update_decision(sid):
    """Dispatch accept-all or reject-all update as a background job, respecting active filters."""
    data   = request.get_json() or {}
    action = data.get('action')
    if action not in ('accept', 'reject'):
        return {'message': 'Invalid action', 'toast_class': 'danger-subtle'}, 400
    if not RuleModel.get_updater_result(sid):
        return {'message': 'Session not found', 'toast_class': 'danger-subtle'}, 404

    def _tri(k): v = data.get(k); return True if v is True else False if v is False else None

    import app.features.jobs.jobs_core as JobsModel
    verb  = 'Accept' if action == 'accept' else 'Reject'
    label = f"{verb} all pending updates ({sid[:8]}…)"

    # Count up-front so job.total is accurate from the first poll
    rules_preview, preview_count = RuleModel.get_rule_update_list_filtered(
        sid,
        f_found=_tri('f_found'),
        f_error=_tri('f_error'),
        f_syntax_valid=_tri('f_syntax_valid'),
    )
    job_total = max(preview_count, 1)

    job = JobsModel.create_job(
        job_type='bulk_update_decision',
        payload={'sid': sid, 'action': action,
                 'f_found': _tri('f_found'), 'f_error': _tri('f_error'),
                 'f_syntax_valid': _tri('f_syntax_valid')},
        label=label, created_by=current_user.id,
        total=job_total,
    )
    return {'message': f'Background job started: {label}', 'job_id': job.id, 'job_uuid': job.uuid, 'toast_class': 'success-subtle'}, 201


@rule_blueprint.route("/bulk_new_rules_decision/<sid>", methods=['POST'])
@login_required
def bulk_new_rules_decision(sid):
    """Dispatch add-all or reject-all new rules as a background job."""
    data = request.get_json() or {}
    action = data.get('action')
    if action not in ('add', 'reject'):
        return {'message': 'Invalid action', 'toast_class': 'danger-subtle'}, 400
    if not RuleModel.get_updater_result(sid):
        return {'message': 'Session not found', 'toast_class': 'danger-subtle'}, 404
    import app.features.jobs.jobs_core as JobsModel
    label = f"{'Add' if action == 'add' else 'Reject'} all new rules ({sid[:8]}…)"

    # Count up-front so job.total is accurate from the first poll
    if action == 'add':
        job_total = max(len(RuleModel.get_valid_new_rules_by_sid(sid)), 1)
    else:
        job_total = max(RuleModel.count_pending_new_rules(sid), 1)

    job = JobsModel.create_job(job_type='bulk_new_rules_decision',
                               payload={'sid': sid, 'action': action, 'user_id': current_user.id},
                               label=label, created_by=current_user.id,
                               total=job_total)
    return {'message': f'Background job started: {label}', 'job_id': job.id, 'job_uuid': job.uuid, 'toast_class': 'success-subtle'}, 201


@rule_blueprint.route("/accept_all_update/<sid>", methods=['GET'])
@login_required
def accept_all_update(sid):
    # found the session associate to the sid
    updater = RuleModel.get_updater_result(sid)
    if not updater:
        return {"message": "Session Not found", 'toast_class': "danger-subtle"}, 404
    # get all the rule with an update available with only correct syntaxe associatio to this uuid into the table rule_status
    rule_udpate_list , number = RuleModel.get_rule_update_list(sid)

    if not rule_udpate_list:
        return {"message": "No rule with update available", 'toast_class': "danger-subtle"}, 404
    if number == 0:
        return {"message": "No rule with update available", 'toast_class': "danger-subtle"}, 200
    success = RuleModel.accept_all_update(rule_udpate_list)
    if success:
        updater.updated = 0
        return {"message": "All rules updated successfully", 'toast_class': "success-subtle"}, 200
    else:
        return {"message": "Error while updating rules", 'toast_class': "danger-subtle"}, 500
    # get for each rule update the history_id and get the history associated and change the RuleUpdateHistory.message and RuleUpdateHistory.success
    


@rule_blueprint.route("/update_get_info_session/<sid>", methods=['GET'])
@login_required
def update_get_info_session(sid):
    for s in UpdateModel.sessions:
        if s.uuid == sid:
            return jsonify(s.info)
        
    r = RuleModel.get_updater_result(sid)
    if r:
        return json.loads(r.info)
    return {"message": "Session Not found", 'toast_class': "danger-subtle"}, 404


@rule_blueprint.route("/check_updates_by_url", methods=["POST"])
@login_required
def check_updates_by_url():
    """
    Check for updates across multiple GitHub URLs (repositories).
    Each repo is cloned/pulled, and rules inside are checked in parallel.
    """
    if not current_user.is_admin():
        return {"message": "Admin access required.", "toast_class": "danger-subtle"}, 403

    # try:


    # except Exception as e:
    #     return {"message": f"Error while checking updates: {str(e)}", "toast_class": "danger-subtle"}, 500
    data = request.get_json()
    urls = data.get("url", None)

    if not urls or not isinstance(urls, list):
        return {
            "message": "Invalid or missing URL list.",
            "nb_update": 0,
            "results": [],
            "success": False,
            "toast_class": "danger-subtle"
        }, 400

    valid_urls = [u.get("url") for u in urls if u.get("url") and valider_repo_github(u.get("url"))]
    if not valid_urls:
        return {"message": "No valid GitHub URLs provided.", "toast_class": "danger-subtle"}, 400

    info = {
        "mode": "by_url", 
        "count": len(valid_urls), 
        "initiated_by": current_user.first_name, 
        "repo_url": valid_urls[0], 
        "license": None, 
        "author": current_user.last_name, 
        "descriprtion": None
    }

    update_session = UpdateModel.Update_class(valid_urls, current_user, info, mode="by_url")
    update_session.start()
    UpdateModel.sessions.append(update_session)

    try:
        from app.features.notification.notification_core import notify_admins_session_started
        notify_admins_session_started(
            user         = current_user,
            session_type = 'github_update',
            session_uuid = update_session.uuid,
            label        = f'GitHub update check running — {len(valid_urls)} repo(s)',
            link         = '/rule/github/manage',
        )
    except Exception as _e:
        print(f"[rule] notify_admins_session_started (update_by_url) error: {_e}")

    log_activity("github.update_started",
                 f"Started GitHub update check on {len(valid_urls)} repo(s)",
                 target_type="github_update",
                 target_uuid=update_session.uuid,
                 extra={"urls": valid_urls},
                 is_public=False,
                 icon="fa-brands fa-github")
    return {
        "message": "Update check started successfully. Processing repositories...",
        "session_uuid": update_session.uuid,
        "toast_class": "success-subtle"
    }, 201


@rule_blueprint.route("/check_updates_by_rule", methods=["POST"])
@login_required
def check_updates_by_rule():
    """
    Check for updates on specific selected rules (by rule IDs).
    Rules are matched with their GitHub source and updated if needed.
    """
    if not current_user.is_admin():
        return {"message": "Admin access required.", "toast_class": "danger-subtle"}, 403

    # try:


    # except Exception as e:
    #     return {"message": f"Error while checking rule updates: {str(e)}", "toast_class": "danger-subtle"}, 500


    data = request.get_json()
    rule_ids = data.get("rules", [])

    if not rule_ids or not isinstance(rule_ids, list):
        return {
            "message": "No rule IDs provided or invalid format.",
            "nb_update": 0,
            "results": [],
            "success": False,
            "toast_class": "danger-subtle"
        }, 400

    info = {"mode": "by_rule", "count": len(rule_ids), "initiated_by": current_user.first_name}

    update_session = UpdateModel.Update_class(rule_ids, current_user, info, mode="by_rule")
    update_session.start()
    UpdateModel.sessions.append(update_session)

    try:
        from app.features.notification.notification_core import notify_admins_session_started
        notify_admins_session_started(
            user         = current_user,
            session_type = 'github_update',
            session_uuid = update_session.uuid,
            label        = f'GitHub update check running — {len(rule_ids)} rule(s)',
            link         = '/rule/github/manage',
        )
    except Exception as _e:
        print(f"[rule] notify_admins_session_started (update_by_rule) error: {_e}")

    log_activity("github.update_started",
                 f"Started rule update check on {len(rule_ids)} rule(s)",
                 target_type="github_update",
                 target_uuid=update_session.uuid,
                 extra={"rule_ids": rule_ids},
                 is_public=False,
                 icon="fa-solid fa-rotate")
    return {
        "message": "Rule update verification started successfully.",
        "session_uuid": update_session.uuid,
        "toast_class": "success-subtle"
    }, 201


#########################
#   Github url section  #
#########################

@rule_blueprint.route("/github/list_github_url", methods=['GET'])
def list_github_url() :
    """Go to the list of all github url"""
    return render_template("rule/url_github/list_url_github.html")
    


@rule_blueprint.route("/get_url_github", methods=['GET'])
def get_url_github():
    search = request.args.get("search", default=None, type=str)
    search_field = request.args.get("search_field", default='url', type=str)
    format_filter = request.args.get("format", default=None, type=str)
    author_filter = request.args.get("author", "")
    page = request.args.get("page", default=1, type=int)

    github_data, total_url, total_pages = RuleModel.get_optimized_github_data(
        page=page, 
        search=search, 
        search_field=search_field, 
        format_filter=format_filter,
        author_filter=author_filter
    )

    return jsonify({
        "success": True,
        "github_url": github_data,
        "total_url": total_url,
        "total_pages": total_pages
    }), 200


LARGE_DELETE_THRESHOLD = 200


@rule_blueprint.route("/delete_all_rule_github", methods=['GET', 'POST'])
@login_required
def delete_all_rule_github():
    if not current_user.is_admin():
        return jsonify({"message": "Access denied", "toast_class": "danger-subtle"}), 403

    url = request.args.get("url")
    if not url:
        return jsonify({"message": "URL is required", "toast_class": "danger-subtle"}), 400

    # count how many rules are involved
    count = RuleModel.count_rules_by_url(url)

    if count > LARGE_DELETE_THRESHOLD:
        # ── large delete → background job ────────────────────────────────────
        import app.features.jobs.jobs_core as JobsModel
        label = f"Delete {count} rule(s) from {url.split('github.com/')[-1]}"
        job = JobsModel.create_job(
            job_type='delete_github_rules',
            payload={'urls': [url.strip()]},
            label=label,
            created_by=current_user.id,
        )
        if not job:
            return jsonify({
                "message": "Failed to create background job.",
                "toast_class": "danger-subtle"
            }), 500

        log_activity("github.source_deleted",
                     f"Queued deletion of {count} rule(s) from GitHub source '{url}'",
                     extra={"url": url, "rule_count": count, "job_uuid": job.uuid},
                     icon="fa-brands fa-github")
        return jsonify({
            "status":      "job_queued",
            "message":     f"{count} rules — deletion queued as background job.",
            "job_uuid":    job.uuid,
            "rule_count":  count,
            "toast_class": "info-subtle",
        }), 202

    # ── small delete → synchronous soft delete ───────────────────────────────
    success, message, nb = RuleModel.soft_delete_all_by_url(url, current_user.id)
    if success:
        log_activity("github.source_deleted",
                     f"Moved {nb} rule(s) from '{url}' to trash",
                     extra={"url": url, "deleted_count": nb},
                     icon="fa-brands fa-github")
    return jsonify({
        "status":        "done",
        "message":       message,
        "deleted_count": nb,
        "url":           url,
        "toast_class":   "success-subtle" if success else "danger-subtle",
    }), 202

@rule_blueprint.route("/bulk_action_github", methods=['POST'])
def bulk_action_github():
    data = request.get_json()
    action = data.get('action')
    mode = data.get('mode', 'partial')
    excluded_ids = data.get('excluded_ids') or []
    

    if mode == 'all':
        target_urls = RuleModel.get_all_github_sources(exclude_urls=excluded_ids)
    else:
        target_urls = data.get('selected_ids') or []
    if action == 'delete':
        if current_user.is_admin() == False:
            return jsonify({"message": "Access denied", "toast_class": "danger-subtle"}), 403
        if not target_urls:
            return jsonify({"message": "No URLs to delete", "status": "warning-subtle"}), 400
        
        success, message, nb = RuleModel.delete_all_rule_by_url(target_urls)
        if success:
            log_activity("github.source_deleted",
                         f"Bulk-deleted {nb} rule(s) from {len(target_urls)} GitHub source(s)",
                         extra={"urls": target_urls, "deleted_count": nb},
                         icon="fa-brands fa-github")
        return jsonify({
            "status": "success" if success else "error",
            "message": message,
            "deleted_count": nb,
            "toast_class": "success-subtle" if success else "danger-subtle"
        }), 200

    elif action == 'export':
        if not target_urls:
            return jsonify({"message": "No URLs to export", "toast_class": "warning-subtle"}), 400
        
       
        try:
            return RuleModel.export_rules_by_urls_as_zip(target_urls)
        except Exception as e:
            return jsonify({"message": f"Export failed: {str(e)}", "toast_class": "danger-subtle"}), 500

    return jsonify({"message": "Action not supported"}), 400

@rule_blueprint.route("/github_detail", methods=['GET'])
def github_detail():
    """Display the detail page for a specific GitHub project URL."""
    url = request.args.get("url", type=str)

    if not url:
        flash("No GitHub URL was provided.", "warning")
        return redirect(url_for("rule.list_github_url"))

    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    return render_template(
        "rule/url_github/detail_url_github.html",
        url=url
    )

def _csv_arg(name):
    raw = request.args.get(name, '', type=str)
    return [v.strip() for v in raw.split(',') if v.strip()] if raw else None


@rule_blueprint.route("/data_table", methods=['GET'])
def rules_data_table():
    """Generic rule listing for the rule-data-table component.
    Supports the full advanced filter set (search_field, exact_match,
    rule_type, author, sources, vulnerabilities, licenses, tags) on top of
    page / per_page / search / sort / dir.
    Response shape: { items, total, total_pages }."""
    sources = _csv_arg('sources')
    source  = request.args.get('source', None, type=str)
    if source:
        sources = (sources or []) + [source]

    authors_list  = _csv_arg('authors')
    single_author = request.args.get('author', None, type=str)
    author_filter = authors_list or ([single_author] if single_author else None)

    ids_csv = _csv_arg('ids')
    ids = [int(i) for i in ids_csv if i.isdigit()] if ids_csv else None

    pagination = RuleModel.get_rules_data_table(
        page=request.args.get('page', 1, type=int),
        per_page=request.args.get('per_page', 10, type=int),
        search=request.args.get('search', None, type=str),
        sort=request.args.get('sort', None, type=str),
        direction=request.args.get('dir', 'asc', type=str),
        source=sources,
        user_id=request.args.get('user_id', None, type=int),
        search_field=request.args.get('search_field', 'all', type=str),
        exact_match=request.args.get('exact_match', 'false', type=str) == 'true',
        rule_type=request.args.get('rule_type', None, type=str),
        author=author_filter,
        vulnerabilities=_csv_arg('vulnerabilities'),
        licenses=_csv_arg('licenses'),
        tags=_csv_arg('tags'),
        editor_names=_csv_arg('editors'),
        bundle_id=request.args.get('bundle_id', None, type=int),
        attacks=_csv_arg('attacks'),
        status=request.args.get('status', None, type=str),
        workspace_uuid=request.args.get('workspace_uuid', None, type=str),
        exclude_workspace_uuid=request.args.get('exclude_workspace_uuid', None, type=str),
        ids=ids,
        has_cve=request.args.get('has_cve', 'false', type=str) == 'true',
        quality_score_min=request.args.get('quality_score_min', None, type=float),
        quality_score_max=request.args.get('quality_score_max', None, type=float),
    )

    rule_ids = [r.id for r in pagination.items]
    tags_by_rule = RuleModel.get_tags_for_rules_batch(rule_ids)

    # Batch-fetch ATT&CK associations for this page
    from app.core.db_class.db import RuleAttackAssociation, AttackTechnique as _AT
    attacks_by_rule: dict = {}
    if rule_ids:
        atk_rows = (
            db.session.query(
                RuleAttackAssociation.rule_id,
                _AT.technique_id, _AT.name, _AT.tactic_keys,
            )
            .join(_AT, RuleAttackAssociation.technique_id == _AT.technique_id)
            .filter(RuleAttackAssociation.rule_id.in_(rule_ids))
            .all()
        )
        for rid, tid, tname, tkeys in atk_rows:
            attacks_by_rule.setdefault(rid, []).append(
                {'technique_id': tid, 'name': tname, 'tactic_keys': tkeys or []}
            )

    from app.core.db_class.db import RuleVote as _RV
    votes_map = {}
    if rule_ids and current_user.is_authenticated:
        rows = _RV.query.filter(
            _RV.rule_id.in_(rule_ids),
            _RV.user_id == current_user.id
        ).all()
        votes_map = {v.rule_id: v.vote_type for v in rows}

    items = []
    for r in pagination.items:
        d = r.to_json()
        d['tags'] = [t.to_json() for t in tags_by_rule.get(r.id, [])]
        try:
            cves = json.loads(r.cve_id) if r.cve_id else []
            d['cves'] = cves if isinstance(cves, list) else []
        except (ValueError, TypeError):
            d['cves'] = []
        d['attacks'] = attacks_by_rule.get(r.id, [])
        d['user_vote'] = votes_map.get(r.id)
        items.append(d)

    return jsonify({
        "items":       items,
        "total":       pagination.total,
        "total_pages": pagination.pages,
    }), 200


@rule_blueprint.route("/<int:rule_id>/status", methods=['PATCH'])
@login_required
def update_rule_status(rule_id):
    from app.core.db_class.db import Rule
    rule = RuleModel._active().filter(Rule.id == rule_id).first()
    if not rule:
        return jsonify({'success': False, 'message': 'Rule not found'}), 404
    if rule.user_id != current_user.id and not current_user.is_admin():
        return jsonify({'success': False}), 403
    data = request.get_json(force=True)
    status = data.get('status')
    if status not in ('draft', 'testing', 'production', 'deprecated'):
        return jsonify({'success': False, 'message': 'Invalid status'}), 400
    rule.status = status
    db.session.commit()
    log_activity('rule.status_change', f"Status changed to {status}", target_type='rule', target_id=rule.id, extra={'status': status})
    return jsonify({'success': True, 'status': status})


@rule_blueprint.route("/<int:rule_id>/quick_meta", methods=['PATCH'])
@login_required
def quick_meta(rule_id):
    """Patch tags, CVEs, and ATT&CK techniques on a rule from workspace quick-edit."""
    from app.core.db_class.db import Rule, RuleTagAssociation, Tag
    rule = RuleModel._active().filter(Rule.id == rule_id).first()
    if not rule:
        return jsonify({'success': False}), 404

    data = request.get_json(force=True)

    # Allow edit if owner, admin, or the rule is in one of the user's workspaces
    if rule.user_id != current_user.id and not current_user.is_admin():
        from app.core.db_class.db import WorkspaceRule, Workspace
        in_own_ws = (db.session.query(WorkspaceRule)
                     .join(Workspace, WorkspaceRule.workspace_id == Workspace.id)
                     .filter(WorkspaceRule.rule_id == rule_id, Workspace.user_id == current_user.id)
                     .first())
        if not in_own_ws:
            # A user with rule.tag_any may still patch this rule, but ONLY
            # its tag_ids — granting that permission must never also open
            # up CVEs/ATT&CK on a rule this user doesn't own.
            tag_only_patch = set(data.keys()) <= {'tag_ids'}
            if not (tag_only_patch and current_user.has_permission('rule.tag_any')):
                return jsonify({'success': False}), 403
    old_snapshot = RuleModel.rule_metadata_snapshot(rule)

    # Tags
    if 'tag_ids' in data:
        import uuid as _uuid
        tag_ids = [int(t) for t in data['tag_ids'] if str(t).isdigit()]
        current_tag_ids = {a.tag_id for a in RuleTagAssociation.query.filter_by(rule_id=rule.id).all()}
        for tid in tag_ids:
            if tid not in current_tag_ids:
                tag = Tag.query.get(tid)
                if tag:
                    db.session.add(RuleTagAssociation(
                        uuid=str(_uuid.uuid4()),
                        rule_id=rule.id, tag_id=tid, user_id=current_user.id))

    # CVEs
    if 'cve_ids' in data:
        import json as _json
        rule.cve_id = _json.dumps(data['cve_ids']) if data['cve_ids'] else None

    # ATT&CK techniques
    if 'technique_ids' in data:
        from app.features.attack.attack_core import add_technique_to_rule
        for technique_id in data['technique_ids']:
            try:
                add_technique_to_rule(rule.id, technique_id, current_user.id, 'manual')
            except Exception:
                pass

    db.session.commit()

    try:
        from app.features.rule.rule_quality.quality_score_core import recompute_rule_quality_score
        recompute_rule_quality_score(rule)
    except Exception:
        pass

    new_snapshot = RuleModel.rule_metadata_snapshot(rule)
    if current_user.id != rule.user_id:
        RuleModel.add_contributor(current_user.id, rule.id)

    if new_snapshot != old_snapshot:
        log_activity("rule.quick_meta", f"Updated tags/vulnerabilities on rule '{rule.title}' (id={rule.id})",
                     target_type="rule", target_id=rule.id, target_uuid=rule.uuid)
        RuleModel.create_rule_history({
            "id": rule.id,
            "title": rule.title,
            "success": True,
            "manual_submit": False,
            "message": "Tags/vulnerabilities updated",
            "new_content": rule.to_string,
            "old_content": rule.to_string,
            "old_snapshot": old_snapshot,
            "new_snapshot": new_snapshot,
            "change_type": "metadata",
        })

    return jsonify({'success': True})


@rule_blueprint.route("/data_table_favorites", methods=['GET'])
@login_required
def rules_data_table_favorites():
    """Favorite rules listing in RuleList format."""
    per_page   = request.args.get('per_page', 12, type=int)
    page       = request.args.get('page', 1, type=int)
    search     = request.args.get('search', None, type=str)
    pagination = RuleModel.get_rules_page_favorite(
        page, current_user.id,
        search=search,
        per_page=per_page,
    )
    rule_ids     = [r.id for r in pagination.items]
    tags_by_rule = RuleModel.get_tags_for_rules_batch(rule_ids)
    items = []
    for r in pagination.items:
        d = r.to_json()
        d['tags']        = [t.to_json() for t in tags_by_rule.get(r.id, [])]
        d['is_favorited'] = True
        try:
            cves = json.loads(r.cve_id) if r.cve_id else []
            d['cves'] = cves if isinstance(cves, list) else []
        except (ValueError, TypeError):
            d['cves'] = []
        items.append(d)
    return jsonify({
        "items":       items,
        "total":       pagination.total,
        "total_pages": pagination.pages,
    }), 200


@rule_blueprint.route("/data_table_votes", methods=['GET'])
@login_required
def rules_data_table_votes():
    """Liked/disliked rules listing in RuleList format."""
    per_page   = request.args.get('per_page', 12, type=int)
    page       = request.args.get('page', 1, type=int)
    search     = request.args.get('search', None, type=str)
    vote_type  = request.args.get('vote_type', None, type=str)  # 'up' | 'down' | None (both)
    pagination = RuleModel.get_rules_page_voted(
        page, current_user.id,
        vote_type=vote_type,
        search=search,
        per_page=per_page,
    )
    rule_ids     = [r.id for r in pagination.items]
    tags_by_rule = RuleModel.get_tags_for_rules_batch(rule_ids)

    from app.core.db_class.db import RuleVote as _RV
    votes_map = {}
    if rule_ids:
        rows = _RV.query.filter(
            _RV.rule_id.in_(rule_ids),
            _RV.user_id == current_user.id
        ).all()
        votes_map = {v.rule_id: v.vote_type for v in rows}

    items = []
    for r in pagination.items:
        d = r.to_json()
        d['tags'] = [t.to_json() for t in tags_by_rule.get(r.id, [])]
        try:
            cves = json.loads(r.cve_id) if r.cve_id else []
            d['cves'] = cves if isinstance(cves, list) else []
        except (ValueError, TypeError):
            d['cves'] = []
        d['user_vote'] = votes_map.get(r.id)
        items.append(d)
    return jsonify({
        "items":       items,
        "total":       pagination.total,
        "total_pages": pagination.pages,
    }), 200


@rule_blueprint.route("/github_source_stats", methods=['GET'])
def github_source_stats():
    """Aggregate stats for one GitHub source URL (GitHub dashboard header)."""
    url = request.args.get('url', None, type=str)
    if not url:
        return jsonify({"message": "url is required"}), 400
    return jsonify(RuleModel.get_github_source_stats(url)), 200


@rule_blueprint.route("/get_rule_url_github", methods=['GET'])
def get_rule_url_github():
    """List all the rule from GitHub URLs"""
    search = request.args.get("search", default=None, type=str)
    page = request.args.get("page", default=1, type=int)
    url = request.args.get("url", default=None, type=str)

    pagination, total = RuleModel.get_all_rule_by_url_github_page(page, search, url)
    return jsonify({
        "success": True,
        "rule_github_url": [rule.to_json() for rule in pagination.items],
        "total_rule": pagination.total,
        "total_pages": pagination.pages,
    }), 200


@rule_blueprint.route("/get_rules_with_github_url", methods=["GET"])
def get_rules_with_github_url():
    """Get all rules associated with a specific GitHub URL."""
    search = request.args.get("search", type=str, default=None)
    page = request.args.get("page", type=int, default=1)

    pagination , total = RuleModel.get_all_rule_by_github_url_page(search=search, page=page)

    return jsonify({
        "success": True,
        "github_rules": [rule.to_json() for rule in pagination.items],
        "total_rule": total,
        "total_pages": pagination.pages
    }), 200

@rule_blueprint.route('/fix_new_rule/<int:new_rule_id>', methods=['GET'])
@login_required
def fix_new_rule(new_rule_id: int):
    """
    Moves an invalid rule from the temporary NewRule table to InvalidRuleModel 
    for manual correction by the user, relying entirely on the RuleModel service layer.
    """
    
    temp_rule = RuleModel.get_new_rule(new_rule_id) 

    if not temp_rule:
        flash(f"Temporary rule ID {new_rule_id} not found.", "danger")
        return redirect(url_for('rule.rules_summary')) 

    if temp_rule.rule_syntax_valid:
        flash("This rule is already marked as valid. Use 'Add Rule' instead.", "info")
        return redirect(safe_referrer(url_for('rule.rules_summary')))

    result_obj, error_message = BadRuleModel.save_invalid_rule_from_new_rule(
        new_rule_obj=temp_rule, 
        user=current_user,
        github_path=temp_rule.github_path
    )

    if error_message:
        flash(f"Error saving rule for correction: {error_message}", "danger")
        return redirect(url_for('rule.rules_summary'))

    flash(f"Rule '{temp_rule.name_rule}' moved to manual correction.", "warning")
    
    return redirect(url_for('rule.edit_bad_rule', rule_id=result_obj.id))


@rule_blueprint.route('/add_new_rule', methods=['GET'])
@login_required
def add_new_rule():
    """
    Retrieves the valid rule content and imports it using the full parsing logic.
    """
    new_rule_id = request.args.get('new_rule_id', type=int, default=None)
    if not new_rule_id:
        return jsonify({"success": False, "message": "No new rule ID provided.", "toast_class": "danger-subtle"}), 400

    temp_rule = RuleModel.get_new_rule(new_rule_id) 
    
    if not temp_rule:
        return jsonify({"success": False, "message": f"Temporary rule ID {new_rule_id} not found.", "toast_class": "danger-subtle"}), 404

    if not temp_rule.rule_syntax_valid:
        return jsonify({"success": False, "message": f"Temporary rule ID {new_rule_id} is not valid.", "toast_class": "danger-subtle"}), 404

    content = temp_rule.rule_content
    format = temp_rule.format or "no format"

    # get the url 
    updater = RuleModel.get_updater_result_by_id(temp_rule.update_result_id)
    if not updater:
        return jsonify({"success": False, "message": "Updater not found", "toast_class": "danger-subtle"}), 404

    try:
        updater_info = json.loads(updater.info)
        repo_url = updater_info.get('repo_url')
        
        source_info = repo_url
        
    except (json.JSONDecodeError, AttributeError):
        source_info = "Unknown Source from Updater" 
        



    s = RuleModel.change_message_new_rule(new_rule_id, "imported")
    
    if not s:
        return jsonify({"success": False, "message": "Error while updating rule", "toast_class": "danger-subtle"}), 500
        
    success, message, imported_object = parse_rule_by_format(content, current_user, format, source_info, github_path=temp_rule.github_path) 
    
    if success:
        profil_game_user_ = AccountModel.get_or_create_gamification_profile(imported_object.user_id)
        if profil_game_user_ :
     
            _ = AccountModel.update_rules_owned_gamification(profil_game_user_.id, imported_object.user_id)

        return jsonify({"success": True, "message": message, "toast_class": "success-subtle"}), 200
    elif imported_object:

        return jsonify({"success": False, "message": message, "toast_class": "warning-subtle"}), 200
    else:
        return jsonify({"success": False, "message": message, "toast_class": "danger-subtle"}), 500
    

# get_popular_rules

@rule_blueprint.route('/get_popular_rules', methods=['GET'])
def get_popular_rules():
    popular_rules = RuleModel.get_popular_rules()
    return jsonify({"success": True, "rules": [rule.to_json() for rule in popular_rules]}), 200


# get_total_rules

@rule_blueprint.route('/get_total_rules', methods=['GET'])
def get_total_rules():
    total_rules = RuleModel.get_total_rules()
    return jsonify({"success": True, "total_rules": total_rules}), 200

# get_total_formats

@rule_blueprint.route('/get_total_formats', methods=['GET'])
def get_total_formats():
    total_formats = RuleModel.get_total_formats()
    return jsonify({"success": True, "total_formats": total_formats}), 200



@rule_blueprint.route('/similar_rules_detail/<int:rule_id>', methods=['GET'])
@login_required
def similar_rules_detail(rule_id):
    if not rule_id:
        flash("No rule ID provided.", "danger")
        return redirect(url_for('rule.rules_summary'))
    
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        flash("Rule not found.", "danger")
        return redirect(url_for('rule.rules_summary'))

    return render_template("/rule/compare_rules/similar_rule.html", rule=rule)


@rule_blueprint.route('/get_similar_rule_page', methods=['GET'])
@login_required
def get_similar_rule_page():
    rule_id = request.args.get("rule_id", type=int)
    limit = request.args.get("limit", type=int, default=10)
    page = request.args.get("page", type=int, default=1)
    search = request.args.get("search", type=str, default=None)
    sort_by = request.args.get("sort_by", type=str, default="highest_match")
    pourcent = request.args.get("pourcent", type=int, default=111)

    if not rule_id:
        return jsonify({
            "message": "Missing rule_id",
            "similar_rules": []
        }), 400

    paginated_items, total_count, total_pages = RuleModel.get_similar_rules_paginated(
        rule_id=rule_id,
        page=page,
        per_page=limit,
        search=search,
        sort_by=sort_by,
        pourcent=pourcent
    )

    return jsonify({
        "similar_rules": paginated_items,  
        "total_count": total_count,
        "total_pages": total_pages,
        "current_page": page,
        "per_page": limit,
        "success": True,
        "toast_class": "success-subtle"
    }), 200



# delete_all_rule

@rule_blueprint.route('/delete_all_rule', methods=['GET'])
@login_required
def delete_all_rule():
    if current_user.is_admin() == False:
        return jsonify({"success": False, "message": "Access denied", "toast_class": "danger-subtle"}), 403
    url = request.args.get("url", type=str)
    if not url:
        return jsonify({"success": False, "message": "No url provided", "toast_class": "danger-subtle"}), 400

    success  = RuleModel.delete_all_rule_by_url(url)
    return jsonify({"success": True, "message": "All rules deleted", "toast_class": "success-subtle"}), 200
    


@rule_blueprint.route("/get_rules_page_filter_bundle", methods=['GET'])
def get_rules_page_filter_bundle() -> jsonify:
    """Get all the rules with filter"""
    page = int(request.args.get("page", 1))
    bundle_id = request.args.get("bundle_id", None)
    search = request.args.get("search", None)
    author = request.args.get("author", None)
    sort_by = request.args.get("sort_by", "newest")
    rule_type = request.args.get("rule_type", None) 

    if not bundle_id:
        return jsonify({"success": False, "message": "No bundle id provided", "toast_class": "danger-subtle"}), 400

    rules, total_rules = RuleModel.get_rules_page_filter_bundle_page(search, author, sort_by, rule_type ,page, bundle_id, 10)

    return jsonify({
        "rule": [r.to_json() for r in rules],
        "total_rules": total_rules,
        "total_pages": rules.pages
    }),200


@rule_blueprint.route("/get_all_rules_vulnerabilities_usage", methods=['GET'])
def get_all_rules_vulnerabilities_usage():
    try:
        filters = RuleModel.parse_facet_filters(request.args, exclude=['vulnerabilities'])
        vulnerabilities = RuleModel.get_rules_vulnerabilities_usage(filters=filters)
        return jsonify({
            "success": True,
            "vulnerabilities": vulnerabilities
        })
    except Exception as e:

        return jsonify({"success": False, "message": str(e)}), 500
    


@rule_blueprint.route('/get_rule_vulnerabilities_display/<int:rule_id>')
def get_rule_vulnerabilities_display(rule_id):
    """Returns the list of vulnerability identifier strings."""
    try:
        v_list = RuleModel.get_vulnerabilities_for_rule(rule_id)
        
        return jsonify({
            "success": True, 
            "vulnerabilities": v_list, 
            "total_vulnerabilities": len(v_list)
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500



@rule_blueprint.route('/test')
def test():
    return render_template('rule/test.html')


@rule_blueprint.route('/get_rules_sources_usage')
def get_rules_sources_usage():
    """Returns the list of sources, scoped to rules matching every other active filter."""
    search_query = request.args.get('q', '').strip()
    filters = RuleModel.parse_facet_filters(request.args, exclude=['source'])

    sources = RuleModel.get_sources_usage_with_filter(search_query, filters=filters)

    return jsonify([{"name": s.source, "count": s.count} for s in sources])

@rule_blueprint.route('/get_rules_licenses_usage')
def get_rules_licenses_usage():
    """Returns the list of licenses, scoped to rules matching every other active filter."""
    search_query = request.args.get('q', '').strip()
    filters = RuleModel.parse_facet_filters(request.args, exclude=['license'])

    licenses = RuleModel.get_licenses_usage_with_filter(search_query, filters=filters)

    return jsonify([{"name": s.license, "count": s.count} for s in licenses])


@rule_blueprint.route('/get_rules_authors_usage')
def get_rules_authors_usage():
    """Returns distinct rule authors with their rule count, scoped to rules
    matching every other active filter."""
    search_query = request.args.get('q', '').strip()
    filters = RuleModel.parse_facet_filters(request.args, exclude=['author'])

    authors = RuleModel.get_authors_usage_with_filter(search_query=search_query, filters=filters)
    return jsonify([{"name": a.author, "count": a.count} for a in authors])


@rule_blueprint.route('/get_rules_editors_usage')
def get_rules_editors_usage():
    """Returns distinct Rulezet editors (uploaders) with their rule count,
    scoped to rules matching every other active filter."""
    search_query = request.args.get('q', '').strip()
    filters = RuleModel.parse_facet_filters(request.args, exclude=['editor_names'])

    editors = RuleModel.get_editors_usage_with_filter(search_query=search_query, filters=filters)
    return jsonify([{"name": e.name, "count": e.count} for e in editors])



@rule_blueprint.route('/get_tags/<int:rule_id>')
def get_tags(rule_id):
    """Returns full tag objects associated with a rule for display purposes."""
    try:
        tags = RuleModel.get_tags_for_rule(rule_id)
        
        return jsonify({
            "success": True, 
            "tags": [t.to_json() for t in tags],
            "total_tags": len(tags)

        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    
@rule_blueprint.route('/get_all_tags_usage')
def get_all_tags_usage():
    try:
        filters = RuleModel.parse_facet_filters(request.args, exclude=['tags'])
        tags = RuleModel.get_all_used_tags_with_counts(filters=filters)
        return jsonify({
            "success": True,
            "tags": tags
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    
@rule_blueprint.route('/get_rule_tags_display/<int:rule_id>')
def get_rule_tags_display(rule_id):
    """Returns full tag objects associated with a rule for display purposes."""
    try:
        tags = RuleModel.get_tags_for_rule(rule_id)
        
        return jsonify({
            "success": True, 
            "tags": [t.to_json() for t in tags],
            "total_tags": len(tags)

        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    




@rule_blueprint.route('/export/download', methods=['GET'])
def download_rules_export():
    filters = {
        "search": request.args.get("search"),
        "search_field": request.args.get("search_field", "all"),
        "author": request.args.get("author"),
        "sort_by": request.args.get("sort_by", "newest"),
        "rule_type": request.args.get("rule_type"),
        "sources": request.args.get("sources"),
        "user_id": request.args.get("user_id"),
        "licenses": request.args.get("licenses"),
        "export_format": request.args.get("export_format", "json_each")
    }

    vuln_raw = request.args.get("vulnerabilities", "")
    vuln_list = [v.strip() for v in vuln_raw.split(',') if v.strip()] if vuln_raw else []

    tag_raw = request.args.get("tags", "")
    tag_list = [t.strip() for t in tag_raw.split(',') if t.strip()] if tag_raw else []

    # Explicit selection takes precedence over filters (rule-data-table export)
    ids_raw = request.args.get("ids", "")
    ids = [int(i) for i in ids_raw.split(',') if i.strip().isdigit()] if ids_raw else []

    if ids:
        filters["ids"] = ids
        rules = RuleModel.get_active_rules_by_ids(ids)
    else:
        query = RuleModel.filter_rules(
            search=filters["search"],
            search_field=filters["search_field"],
            author=filters["author"],
            sort_by=filters["sort_by"],
            rule_type=filters["rule_type"],
            vulnerabilities=vuln_list,
            source=filters["sources"],
            user_id=filters["user_id"],
            license=filters["licenses"],
            tags=tag_list
        )
        rules = query.all()

    if not rules:
        return "No rules found to export", 404

    memory_file = io.BytesIO()
    
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        metadata = {
            "export_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_rules": len(rules),
            "applied_filters": filters
        }
        zf.writestr("rules_export/metadata.json", json.dumps(metadata, indent=4))

        merged_contents = {}

        for rule in rules:
            rtype = rule.format.upper() if rule.format else "UNKNOWN"
            safe_title = "".join([c if c.isalnum() else "_" for c in rule.title]) if rule.title else f"rule_{rule.id}"
            
            if filters["export_format"] == 'json_each':
                path = f"rules_export/{rtype}/{safe_title}_{rule.id}.json"
                zf.writestr(path, json.dumps(rule.to_json(), indent=4))

            elif filters["export_format"] == 'ext_each':
                ext = rule.get_extension()
                path = f"rules_export/{rtype}/{safe_title}.{ext}"
                content = rule.to_string() if callable(rule.to_string) else rule.to_string
                zf.writestr(path, str(content))

            elif filters["export_format"] == 'merged_by_type':
                if rtype not in merged_contents:
                    merged_contents[rtype] = [] 
                content = rule.to_string() if callable(rule.to_string) else rule.to_string
                merged_contents[rtype].append(f"\n// --- Rule: {rule.title} ({rule.id}) ---\n{content}\n")

        if filters["export_format"] == 'merged_by_type':
            for rtype, contents in merged_contents.items():
                sample_rule = next((r for r in rules if (r.format.upper() if r.format else "UNKNOWN") == rtype), None)
                sample_ext = sample_rule.get_extension() if sample_rule else "txt"
                zf.writestr(f"rules_export/{rtype}/{rtype}_merged.{sample_ext}", "".join(contents))

    memory_file.seek(0)
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'rules_export_{datetime.now().strftime("%Y%m%d")}.zip'
    )
########################
#  Bundle from Filter  #
########################
@rule_blueprint.route('/bundle/create-from-filters', methods=['POST'])
@login_required
def bundle_from_filters():
    MAX_BUNDLE_RULES = 200
    data = request.json

    # Explicit ID selection takes priority over filters
    explicit_ids = data.get('ids')
    if explicit_ids:
        if len(explicit_ids) > MAX_BUNDLE_RULES:
            return jsonify({"message": f"Selection too large — maximum {MAX_BUNDLE_RULES} rules per bundle."}), 400
        rules_objects = RuleModel.get_active_rules_by_ids(explicit_ids)
    else:
        filters = data.get('filters') or {}
        if not any([
            filters.get("search"), filters.get("rule_type"), filters.get("author"),
            filters.get("sources"), filters.get("tags"), filters.get("vulnerabilities"),
            filters.get("licenses"), filters.get("user_id"),
        ]):
            return jsonify({"message": "At least one filter must be active to create a bundle."}), 400

        query = RuleModel.filter_rules(
            search=filters.get("search"),
            search_field=filters.get("search_field", "all"),
            author=filters.get("author"),
            sort_by=filters.get("sort_by"),
            rule_type=filters.get("rule_type"),
            vulnerabilities=filters.get("vulnerabilities", []),
            source=filters.get("sources", []),
            user_id=filters.get("user_id"),
            license=filters.get("licenses", []),
            tags=filters.get("tags", []),
            exact_match=filters.get("exact_match", False)
        )
        rules_objects = query.limit(MAX_BUNDLE_RULES + 1).all()
        if len(rules_objects) > MAX_BUNDLE_RULES:
            return jsonify({"message": f"Too many rules match these filters — maximum {MAX_BUNDLE_RULES}. Please refine your filters."}), 400

    if not rules_objects:
        return jsonify({"message": "No rules found to bundle"}), 404

    rule_ids = [r.id for r in rules_objects]

    # This only resolves/creates the target bundle — it deliberately does NOT
    # add the matched rules to it. The user places them manually (drag or
    # "Add") from the rule library in the structure editor; auto-adding used
    # to dump everything into an "Unsorted" folder the user never asked for.
    try:
        existing_id = data.get('existing_bundle_id')

        if existing_id:
            bundle = BundleModel.get_bundle_by_id(existing_id)
            if not bundle:
                return jsonify({"message": "Bundle not found"}), 404
            if bundle.user_id != current_user.id and not current_user.is_admin():
                return jsonify({"message": "You don't have permission to edit this bundle"}), 403
        else:
            dict_form = {
                "name": data.get('new_bundle_name'),
                "description": data.get('new_bundle_description'),
                "public": data.get('is_public', True)
            }
            bundle = BundleModel.create_bundle(dict_form, current_user)
            if not bundle:
                return jsonify({"message": "Failed to create bundle"}), 500

        return jsonify({
            "success": True,
            "message": "Bundle processed successfully",
            "uuid": bundle.uuid,
            "id": bundle.id,
            "rule_ids": rule_ids
        }), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500
    

#####################
#   Similar rules   #
#####################

@rule_blueprint.route("/similar_get_info_session/<sid>", methods=['GET'])
@login_required
def similar_get_info_session(sid):
    for s in SimilarityModel.sessions:
        if s.uuid == sid:
            return jsonify(s.info)

    r = RuleModel.get_similarity_result(sid)
    if r:
        if not r.info:
            return jsonify({"message": "No details available"}), 200
        
        try:
           
            return jsonify(json.loads(r.info))
        except (json.JSONDecodeError, TypeError):
            return jsonify({"info": r.info, "status": "completed"})

    return jsonify({"message": "Session Not found", 'toast_class': "danger-subtle"}), 404


@rule_blueprint.route("/similar_loading_status/<sid>", methods=['GET'])
@login_required
def similar_loading_status(sid):
    is_finished = request.args.get('is_finished', 'false', type=str)
    if not is_finished == 'true':
        for s in SimilarityModel.sessions:
            if s.uuid == sid:
                s.watched = True
                return jsonify(s.status())
        
    r = RuleModel.get_similarity_result(sid)
    if r:
        loc = r.to_json()
        if not loc:
            return {"error": "Session not found"}, 404

        if "total" not in loc:
            loc["total"] = 100

        loc["remaining"] = 0
        

        return loc
    return {"message": "Session Not found", 'toast_class': "danger-subtle"}, 404


@rule_blueprint.route("/similar_rules/update", methods=['GET' ,'POST'])
@login_required
def similar_update():
    def _notify_similarity(session):
        try:
            from app.features.notification.notification_core import notify_admins_session_started
            notify_admins_session_started(
                user         = current_user,
                session_type = 'similarity',
                session_uuid = session.uuid,
                label        = 'Similarity analysis running',
                link         = f'/rule/similar_loading/{session.uuid}',
            )
        except Exception as _e:
            print(f"[rule] notify_admins_session_started (similarity) error: {_e}")

    if request.method == "POST":
        data = request.json
        similar_session = SimilarityModel.Similarity_class(current_user, "Update similar rules", mode="filter", params=data)
        similar_session.start()
        SimilarityModel.sessions.append(similar_session)
        _notify_similarity(similar_session)

        return {
            "message": "Update check started successfully. Processing repositories...",
            "session_uuid": similar_session.uuid,
            "toast_class": "success-subtle"
        }, 201
    else:
        similar_session = SimilarityModel.Similarity_class(current_user, "Update similar rules", mode="global")
        similar_session.start()
        SimilarityModel.sessions.append(similar_session)
        _notify_similarity(similar_session)

        return {
            "message": "Update check started successfully. Processing repositories...",
            "session_uuid": similar_session.uuid,
            "toast_class": "success-subtle"
        }, 201


@rule_blueprint.route("/similar_loading/<sid>", methods=['GET'])
@login_required
def similar_loading(sid):
    
    for s in SimilarityModel.sessions:
        if s.uuid == sid:
            return render_template("rule/compare_rules/similar_rule.html", sid=sid)
    r = RuleModel.get_similarity_result(sid)
    if r:
        return render_template("rule/compare_rules/similar_rule.html", sid=sid)
    return render_template("404.html"), 404

@rule_blueprint.route("/similar_detail/<int:rule_id>")
@login_required
def similar_detail(rule_id):
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 50)

    pagination = RuleModel.get_similar_rules_query(rule_id).paginate(page=page, per_page=per_page)

    result = []
    for sim, rule_source, rule_target in pagination.items:
        result.append({
            "rule_id": rule_target.id, 
            "score": sim.score,
            "rule_a_data": {
                "id": rule_source.id,
                "title": rule_source.title,
                "content": rule_source.to_string if hasattr(rule_source, 'to_string') else "",
                **rule_source.to_json() 
            },
            "rule_b_data": {
                "id": rule_target.id,
                "title": rule_target.title,
                "content": rule_target.to_string if hasattr(rule_target, 'to_string') else "",
                **rule_target.to_json()
            }
        })
        
    return jsonify({
        "items": result,
        "has_next": pagination.has_next,
        "total": pagination.total,
        "total_pages": pagination.pages,
        "current_page": pagination.page
    })

@rule_blueprint.route("/similar_global_duplicates")
@login_required
def similar_global_duplicates():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 50)
    min_score = request.args.get('min_score', 0.80, type=float)
    search = (request.args.get('search', '') or '').strip()

    filters = {
        "format": request.args.get('format'),
        "source_mode": request.args.get('source_mode', 'all'),
        "author_mode": request.args.get('author_mode', 'all')
    }

    pagination = RuleModel.get_top_global_duplicates_query(
        min_score=min_score,
        filters=filters,
        search=search
    ).paginate(page=page, per_page=per_page)

    result = []
    for sim, rule_a, rule_b in pagination.items:
        result.append({
            "score": sim.score,
            # Objet Rule A
            "rule_a_data": {
                "id": rule_a.id,
                "title": rule_a.title or f"Rule #{rule_a.id}",
                "content": rule_a.to_string if hasattr(rule_a, 'to_string') else "",
                **rule_a.to_json()
            },
            # Objet Rule B
            "rule_b_data": {
                "id": rule_b.id,
                "title": rule_b.title or f"Rule #{rule_b.id}",
                "content": rule_b.to_string if hasattr(rule_b, 'to_string') else "",
                **rule_b.to_json()
            }
        })
        
    return jsonify({
        "items": result,
        "has_next": pagination.has_next,
        "total": pagination.total,
        "total_pages": pagination.pages,
        "current_page": pagination.page
    })
@rule_blueprint.route("/similar_detail_page/<int:rule_id>")
@login_required
def similar_detail_page(rule_id):
    return redirect(url_for('rule.detail_rule_similarity', rule_id=rule_id))

@rule_blueprint.route("/history_updater/list", methods=['GET'])
@login_required
def history_updater_list():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 50)
    running_uuids = {s.uuid for s in SimilarityModel.sessions}
    github_importer_list = RuleModel.get_similarity_list_page(page, per_page=per_page, exclude_uuids=running_uuids)

    return {"history": [g.to_json() for g in github_importer_list], 
            "total_history": github_importer_list.total, 
            "total_pages": github_importer_list.pages}, 200

@rule_blueprint.route("/history_updater/list_in_progress", methods=['GET'])
@login_required
def history_updater_list_in_progress():
    is_admin = current_user.is_admin()
    current_user_id = current_user.id
    unique_sessions = {
        s.uuid: {"uuid": s.uuid, "info": s.info, "date_time": s.start_time, "mode" : s.mode, "step" : s.status_message, "percentage" : s.indexing_progress} 
        for s in SimilarityModel.sessions
        if is_admin or s.current_user.id == current_user_id
    }

    return {"history": list(unique_sessions.values())}, 200

@rule_blueprint.route("/history_updater/delete/<uuid>", methods=['GET'])
@login_required
def history_updater_delete(uuid):
    if current_user.is_admin() == False:
        return {"message": "Access denied", 'toast_class': "danger-subtle", "success": False}, 403
    success = RuleModel.delete_similarity_history(uuid)
    if not success:
        return {"message": "Failled to delete history", 'toast_class': "danger-subtle","success": False}, 500
    return {"message": "History deleted", 'toast_class': "success-subtle", "success": True}, 200



@rule_blueprint.route("/similarity", methods=['GET'])
def similarity():
    rule_id = request.args.get('rule_id', None, type=int)
    number = request.args.get('number', None, type=int)
    
    results = RuleModel.get_similar_rule(rule_id, number)
    
    if not results:
        return {"success": False, "rules": []}, 200

    formatted_rules = []
    for similarity_entry, rule_info in results:
        formatted_rules.append({
            "id": rule_info.id,          
            "name": rule_info.title,    
            "format": rule_info.format,  
            "score": similarity_entry.score,
            "description": rule_info.description,
            "uuid": rule_info.uuid,
            "author": rule_info.author
        })

    return {"success": True, "rules": formatted_rules}, 200


@rule_blueprint.route('/bulk_tag', methods=['GET'])
@login_required
def bulk_tag():
    if current_user.is_admin() or current_user.has_permission('rule.tag_any'):
        return render_template('jobs/bulk_tag.html')
    else:
        return render_template('access_denied.html')


# ── Rule Scope (environment / "works for me") ─────────────────────────────────

@rule_blueprint.route('/get_scopes/<int:rule_id>', methods=['GET'])
def get_scope_list(rule_id):
    current_user_id = current_user.id if current_user.is_authenticated else None
    scopes, works_count, nworks_count, my_scope = RuleModel.get_scopes(rule_id, current_user_id)
    return jsonify({
        'success':      True,
        'scopes':       scopes,
        'works_count':  works_count,
        'nworks_count': nworks_count,
        'my_scope':     my_scope,
    }), 200


@rule_blueprint.route('/scope/<int:rule_id>', methods=['POST'])
@login_required
def scope_upsert(rule_id):
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return jsonify({'success': False, 'message': 'Rule not found'}), 404
    data    = request.get_json() or {}
    works   = bool(data.get('works', True))
    entries = data.get('entries', [])
    comment = (data.get('comment') or '').strip()[:500]
    if not isinstance(entries, list):
        return jsonify({'success': False, 'message': 'entries must be a list'}), 400
    scope_json, is_new = RuleModel.upsert_scope(rule_id, current_user.id, works, entries, comment)
    action = 'rule.scope_add' if is_new else 'rule.scope_update'
    label  = 'Declared' if is_new else 'Updated'
    log_activity(action, f"{label} scope for rule '{rule.title}' — works={works}",
                 target_type='rule', target_id=rule_id, target_uuid=rule.uuid)
    return jsonify({'success': True, 'scope': scope_json}), 200


@rule_blueprint.route('/scope/<int:rule_id>', methods=['DELETE'])
@login_required
def scope_delete(rule_id):
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return jsonify({'success': False, 'message': 'Rule not found'}), 404
    deleted = RuleModel.delete_scope(rule_id, current_user.id)
    if not deleted:
        return jsonify({'success': False, 'message': 'No declaration found'}), 404
    log_activity('rule.scope_delete', f"Removed scope declaration for rule '{rule.title}'",
                 target_type='rule', target_id=rule_id, target_uuid=rule.uuid)
    return jsonify({'success': True}), 200


# ── Trash (soft delete management) ────────────────────────────────────────────

@rule_blueprint.route('/trash', methods=['GET'])
@login_required
def trash():
    if not current_user.is_admin():
        return render_template('access_denied.html')
    return render_template('rule/trash.html')


@rule_blueprint.route('/get_trash_rules', methods=['GET'])
@login_required
def get_trash_rules():
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    from app.core.db_class.db import User as UserModel
    page         = request.args.get('page', 1, type=int)
    search       = request.args.get('search', '').strip() or None
    source       = request.args.get('source', '').strip() or None
    batch_uuid   = request.args.get('batch_uuid', '').strip() or None
    fmt          = request.args.get('format', '').strip() or None
    deleted_from = request.args.get('deleted_from', '').strip() or None
    deleted_to   = request.args.get('deleted_to', '').strip() or None

    pagination = RuleModel.get_deleted_rules(
        page=page, search=search, source=source,
        batch_uuid=batch_uuid, fmt=fmt,
        deleted_from=deleted_from, deleted_to=deleted_to,
    )

    _user_cache = {}
    def _username(uid):
        if not uid:
            return None
        if uid not in _user_cache:
            u = UserModel.query.get(uid)
            _user_cache[uid] = (u.first_name + ' ' + u.last_name).strip() if u else None
        return _user_cache[uid]

    def rule_json(r):
        return {
            'id':                r.id,
            'uuid':              r.uuid,
            'title':             r.title,
            'format':            r.format,
            'source':            r.source,
            'author':            r.author,
            'description':       r.description,
            'to_string':         r.to_string,
            'deleted_at':        r.deleted_at.strftime('%Y-%m-%d %H:%M') if r.deleted_at else None,
            'deleted_by':        _username(r.deleted_by_id),
            'delete_batch_uuid': r.delete_batch_uuid,
        }

    return jsonify({
        'success':     True,
        'rules':       [rule_json(r) for r in pagination.items],
        'total':       pagination.total,
        'total_pages': pagination.pages,
        'page':        pagination.page,
        'batches':     RuleModel.get_deleted_batches(),
        'count':       RuleModel.count_deleted_rules(),
    }), 200


@rule_blueprint.route('/restore/<int:rule_id>', methods=['POST'])
@login_required
def restore_rule_route(rule_id):
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    rule = RuleModel.get_rule(rule_id)
    result = RuleModel.restore_rule(rule_id)

    if result is True:
        if rule:
            log_activity('rule.restore', f"Restored rule '{rule.title}' (id={rule_id})",
                         target_type='rule', target_id=rule_id, target_uuid=rule.uuid)
        return jsonify({'success': True}), 200

    if isinstance(result, tuple) and result[0] == "CONFLICT":
        active_rule = result[1]
        return jsonify({
            'success':    False,
            'conflict':   True,
            'trash_id':   rule_id,
            'trash_title': rule.title if rule else '',
            'active_id':   active_rule.id,
            'active_title': active_rule.title,
            'active_uuid':  active_rule.uuid,
            'active_created': active_rule.creation_date.strftime('%Y-%m-%d %H:%M') if active_rule.creation_date else '',
        }), 409

    return jsonify({'success': False}), 404


@rule_blueprint.route('/resolve_conflict', methods=['POST'])
@login_required
def resolve_conflict():
    """Admin chooses which rule to keep when a restore conflict occurs."""
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    data       = request.get_json() or {}
    action     = data.get('action')          # 'keep_active' | 'keep_trash'
    trash_id   = data.get('trash_id')
    active_id  = data.get('active_id')

    if action == 'keep_active':
        # Just permanently delete the trashed copy
        ok = RuleModel.permanent_delete_rule(trash_id)
        log_activity('rule.conflict_resolved', f"Conflict resolved — kept active rule id={active_id}, discarded trash id={trash_id}")
        return jsonify({'success': ok}), 200

    if action == 'keep_trash':
        # Soft-delete the active rule, then restore the trashed one
        RuleModel.soft_delete_rule(active_id, current_user.id)
        RuleModel.permanent_delete_rule(active_id)   # hard-delete the active duplicate
        # Force restore ignoring content conflict
        trashed = Rule.query.get(trash_id)
        if trashed:
            trashed.is_deleted = False
            trashed.deleted_at = None
            trashed.deleted_by_id = None
            trashed.delete_batch_uuid = None
            from app import db as _db
            _db.session.commit()
        log_activity('rule.conflict_resolved', f"Conflict resolved — restored trash id={trash_id}, removed active id={active_id}")
        return jsonify({'success': True}), 200

    return jsonify({'success': False, 'message': 'Unknown action'}), 400


TRASH_JOB_THRESHOLD = 50   # above this count → background job


def _create_trash_job(job_type: str, label: str, payload: dict):
    """Helper to create a background job for trash operations."""
    import app.features.jobs.jobs_core as JobsModel
    return JobsModel.create_job(job_type=job_type, payload=payload,
                                label=label, created_by=current_user.id)


@rule_blueprint.route('/restore_bulk', methods=['POST'])
@login_required
def restore_rules_bulk():
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    data        = request.get_json() or {}
    rule_ids    = data.get('ids', [])
    restore_all = data.get('restore_all', False)
    batch_uuid  = data.get('batch_uuid')
    count       = len(rule_ids) if rule_ids else RuleModel.count_deleted_rules()

    if count > TRASH_JOB_THRESHOLD:
        payload = {'ids': rule_ids, 'restore_all': restore_all, 'batch_uuid': batch_uuid}
        label   = f"Restore {count} rule(s) from trash"
        job     = _create_trash_job('trash_restore_bulk', label, payload)
        log_activity('rule.restore_bulk', f"Queued restore of {count} rule(s) via job",
                     extra={'job_uuid': job.uuid if job else None})
        return jsonify({'success': True, 'job': True, 'job_uuid': job.uuid if job else None,
                        'message': f'{count} rules — restore queued as background job.'}), 202

    restored = RuleModel.restore_rules_bulk(rule_ids) if rule_ids else \
               RuleModel.restore_rules_bulk([r.id for r in RuleModel.get_deleted_rules(page=1, per_page=10000).items])
    log_activity('rule.restore_bulk', f"Restored {restored} rule(s)", extra={'rule_ids': rule_ids})
    return jsonify({'success': True, 'restored': restored}), 200


@rule_blueprint.route('/restore_batch/<batch_uuid>', methods=['POST'])
@login_required
def restore_batch(batch_uuid):
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    from app.core.db_class.db import Rule as _Rule
    count = _Rule.query.filter(_Rule.is_deleted == True, _Rule.delete_batch_uuid == batch_uuid).count()

    if count > TRASH_JOB_THRESHOLD:
        payload = {'batch_uuid': batch_uuid}
        label   = f"Restore batch of {count} rule(s)"
        job     = _create_trash_job('trash_restore_bulk', label, payload)
        log_activity('rule.restore_bulk', f"Queued batch restore of {count} rule(s)",
                     extra={'batch_uuid': batch_uuid, 'job_uuid': job.uuid if job else None})
        return jsonify({'success': True, 'job': True, 'job_uuid': job.uuid if job else None,
                        'message': f'{count} rules — restore queued as background job.'}), 202

    restored = RuleModel.restore_batch(batch_uuid)
    log_activity('rule.restore_bulk', f"Restored batch of {restored} rule(s)",
                 extra={'batch_uuid': batch_uuid})
    return jsonify({'success': True, 'restored': restored}), 200


@rule_blueprint.route('/permanent_delete/<int:rule_id>', methods=['POST'])
@login_required
def permanent_delete_rule(rule_id):
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    rule = RuleModel.get_rule(rule_id)
    ok   = RuleModel.permanent_delete_rule(rule_id)
    if ok:
        log_activity('rule.permanent_delete',
                     f"Permanently deleted rule '{rule.title if rule else rule_id}' (id={rule_id})",
                     target_type='rule', target_id=rule_id, target_uuid=rule.uuid if rule else None)
    return jsonify({'success': ok}), 200 if ok else 404


@rule_blueprint.route('/permanent_delete_bulk', methods=['POST'])
@login_required
def permanent_delete_bulk():
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    data       = request.get_json() or {}
    ids        = data.get('ids', [])
    delete_all = data.get('delete_all', False)
    batch_uuid = data.get('batch_uuid')
    count      = len(ids) if ids else RuleModel.count_deleted_rules()

    if count > TRASH_JOB_THRESHOLD:
        payload = {'ids': ids, 'delete_all': delete_all, 'batch_uuid': batch_uuid}
        label   = f"Permanently delete {count} rule(s) from trash"
        job     = _create_trash_job('trash_permanent_delete_bulk', label, payload)
        log_activity('rule.permanent_delete_bulk', f"Queued permanent delete of {count} rule(s) via job",
                     extra={'job_uuid': job.uuid if job else None})
        return jsonify({'success': True, 'job': True, 'job_uuid': job.uuid if job else None,
                        'message': f'{count} rules — deletion queued as background job.'}), 202

    if delete_all:
        ids = [r.id for r in RuleModel.get_deleted_rules(page=1, per_page=10000).items]
    deleted = RuleModel.permanent_delete_bulk(ids)
    log_activity('rule.permanent_delete_bulk', f"Permanently deleted {deleted} rule(s)",
                 extra={'count': deleted})
    return jsonify({'success': True, 'deleted': deleted}), 200


@rule_blueprint.route('/rulelist_test', methods=['GET'])
def rulelist_test():
    """Dev/test page for the RuleList component — showcases all modes."""
    return render_template('rule/rulelist_test.html')
