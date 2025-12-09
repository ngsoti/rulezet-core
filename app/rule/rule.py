import json
from math import ceil
from urllib.parse import urlparse
from datetime import datetime,  timezone
from .rule_form import AddNewRuleForm, CreateFormatRuleForm, EditRuleForm
from ..utils.utils import  bump_version, form_to_dict, generate_side_by_side_diff_html

from app.account.account_core import add_favorite, remove_favorite
from app.misp.misp_core import content_convert_to_misp_object
from app.rule_format.main_format import  parse_rule_by_format, process_and_import_fixed_rule, verify_syntax_rule_by_format
from app.rule_format.utils_format.utils_import_update import clone_or_access_repo, fill_all_void_field, get_licst_license, git_pull_repo, github_repo_metadata, valider_repo_github

from . import rule_core as RuleModel
from ..rule_from_github.import_rule import session_class as SessionModel
from ..rule_from_github.update_rule import update_class as UpdateModel
from ..account import account_core as AccountModel

from flask import Blueprint, Response, jsonify, redirect, request, render_template, flash, url_for
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
                return render_template("rule/rule.html",error=error, form=form, rule=rule)

        new_rule = RuleModel.add_rule_core(rule_dict , current_user)
        if new_rule:
            flash('Rule added !', 'success')
            return redirect(url_for('rule.detail_rule', rule_id=new_rule.id))
        else:
            flash('Error during the creation of the rule !', 'danger')
            return render_template("rule/rule.html", form=form, tab="manuel" )
    return render_template("rule/rule.html", form=form )


@rule_blueprint.route("/rules_list", methods=['GET'])
def rules_list() -> render_template:   
    """Redirect to rules list"""     
    return render_template("rule/rules_list.html")

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


@rule_blueprint.route("/get_similar_rule", methods=['GET'])
def get_similar_rules() -> jsonify:
    """Get all the rules on a page"""
    rule_id = request.args.get('rule_id',  type=int)
    rules_list_similar = RuleModel.get_similar_rule(rule_id)
    if rules_list_similar:
        return {"similar_rules": rules_list_similar}
    
    return {"message": "No Rule",
            "similar_rules": []
        }


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
    author = request.args.get("author", None)
    sort_by = request.args.get("sort_by", "newest")
    rule_type = request.args.get("rule_type", None) 

    query = RuleModel.filter_rules( search=search, author=author, sort_by=sort_by, rule_type=rule_type)
    total_rules = query.count()
    rules = query.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "rule": [r.to_json() for r in rules],
        "total_rules": total_rules,
        "total_pages": ceil(total_rules / per_page)
    }),200


#####################
#   Action on Rule  # 
#####################

@rule_blueprint.route("/delete_rule", methods=['GET'])
@login_required
def delete_rule() -> jsonify:
    """Delete a rule"""
   
    rule_id  = request.args.get("id")
    user_id = RuleModel.get_rule_user_id(rule_id)

    if current_user.id == user_id or current_user.is_admin():
        RuleModel.delete_rule_core(rule_id)
        return {"success": True, "message": "Rule deleted!" , "toast_class" : "success"}, 200
    
    return render_template("access_denied.html")

@rule_blueprint.route("/get_current_user", methods=['GET'])
def get_current_user() -> jsonify:
    """Is the current user admin or not for vue js"""
    return jsonify({'user': current_user.is_admin()})

@rule_blueprint.route('/vote_rule', methods=['GET'])
@login_required
def vote_rule() -> jsonify:
    """Update the vote up or down"""
    rule_id = request.args.get('id', 1 , int)
    vote_type = request.args.get('vote_type', 2 , str)
    rule = RuleModel.get_rule(rule_id)
    if rule:
        alreadyVote , already_vote_type= RuleModel.has_already_vote(rule_id, current_user.id)
        if vote_type == 'up':  
            if alreadyVote == False:
                RuleModel.increment_up(rule_id)
                RuleModel.has_voted('up',rule_id, current_user.id)
            elif already_vote_type == 'up':
                RuleModel.remove_one_to_increment_up(rule_id)
                RuleModel.remove_has_voted('up',rule_id, current_user.id)
            elif already_vote_type == 'down':
                RuleModel.increment_up(rule_id) # +1 to up
                RuleModel.remove_one_to_decrement_up(rule_id) # -1 to down
                RuleModel.remove_has_voted('down',rule_id, current_user.id)
                RuleModel.has_voted('up',rule_id, current_user.id)

        elif vote_type == 'down':
            if alreadyVote == False:
                RuleModel.decrement_up(rule_id)
                RuleModel.has_voted('down',rule_id, current_user.id)
            elif already_vote_type == 'down':
                RuleModel.remove_one_to_decrement_up(rule_id)
                RuleModel.remove_has_voted('down',rule_id, current_user.id)
            elif already_vote_type == 'up':
                RuleModel.decrement_up(rule_id) # +1 to down
                RuleModel.remove_one_to_increment_up(rule_id) # -1 to up
                RuleModel.remove_has_voted('up',rule_id , current_user.id)
                RuleModel.has_voted('down',rule_id, current_user.id)
        return jsonify({
            'vote_up': rule.vote_up,
            'vote_down': rule.vote_down
        }), 200
    return jsonify({"message": "Rule not found"}), 404



@rule_blueprint.route("/edit_rule/<int:rule_id>", methods=['GET' , 'POST'])
@login_required
def edit_rule(rule_id) -> render_template:
    """Edit a rule"""
    rule = RuleModel.get_rule(rule_id)
    user_id = RuleModel.get_rule_user_id(rule_id)

    if current_user.id == user_id or current_user.is_admin():
        form = EditRuleForm()
        licenses = get_licst_license()
        form.license.choices = [(lic, lic) for lic in licenses]

        # form send to treatment

        if form.validate_on_submit():
            form_dict = form_to_dict(form)
            rule_dict = fill_all_void_field(form_dict)
            
            # try to compile or verify the syntax of the rule (in the format choose)
            valide , error = verify_syntax_rule_by_format(rule_dict)
            if not valide:
                return render_template("rule/edit_rule.html",error=error, form=form, rule=rule)
            
            if rule_dict["version"] == rule.version:
                rule_dict["version"] = bump_version(rule_dict["version"])


            # create an history for the rule
            if rule.to_string != form_dict['to_string']:
                result = {
                    "id": rule_id,
                    "title": rule.title,
                    "success": True,
                    "message": "simple edit",
                    "new_content": form_dict['to_string'],
                    "old_content": rule.to_string 
                }
                history_id = RuleModel.create_rule_history(result)
                history = RuleModel.get_history_rule_by_id(history_id)
                history.message = "accepted"
            
            success , current_rule = RuleModel.edit_rule_core(rule_dict, rule_id)
            flash("Rule modified with success!", "success")
            return redirect(url_for('rule.detail_rule', rule_id=current_rule.id))
            # return redirect(request.referrer or '/')
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
    
#################
#   Rule info   #
#################

@rule_blueprint.route("/history/<int:rule_id>", methods=['GET'])
def rules_history(rule_id)-> render_template:
    """Redirect to rule history"""    
    return render_template("rule/rule_history_.html" , rule_id=rule_id)

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
    errorDEL = 0
    for rule_id in data['ids']:
        user_id = RuleModel.get_rule_user_id(rule_id)  # Get the user who created the rule
        #Check if the current user is either the owner or an admin
        if current_user.id == user_id or current_user.is_admin():
            success = RuleModel.delete_rule_core(rule_id)
            if not success:
                errorDEL += 1
        else:
            return render_template("access_denied.html") 
    if errorDEL >= 1:
        return jsonify({"success": False, "message": "Failed to delete the rules!",
                        "toast_class" : "danger"}), 400
    else:
        return jsonify({"success": True, 
                        "message": f"{len(data['ids'])} Rule(s) deleted!",
                        "toast_class" : "success"}), 200


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

@rule_blueprint.route("/detail_rule/<int:rule_id>", methods=['GET'])
def detail_rule(rule_id)-> render_template:
    """Get the detail of the current rule"""
    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return render_template("404.html")
    rule_misp = content_convert_to_misp_object(rule_id)
    if not rule_misp:
        rule_misp = "No misp format for this rule"
    rule_to_json = json.dumps(rule.to_dict(), indent=4)
    if not rule_to_json:
        rule_to_json = "No json format for this rule"
    if rule:
        return render_template("rule/detail_rule.html", rule=rule, rule_content=rule.to_string, rule_misp=rule_misp, rule_to_json=rule_to_json)
    return render_template("404.html")
    

@rule_blueprint.route("/download_rule", methods=['GET'])
def download_rule_unified() -> Response:
    rule_id = request.args.get('rule_id', type=int)
    fmt = request.args.get('format', default='txt')

    rule = RuleModel.get_rule(rule_id)
    if not rule:
        return jsonify({
            "message": f"No rule found with id={rule_id}",
            "success": False,
            "toast_class": "danger",
        })

    error_mesg = ""
    try:
        if fmt == 'txt':
            content = rule.to_string 
            filename = f"{rule.title}.txt"

        elif fmt == 'json':
            content = json.dumps(rule.to_json(), indent=2)
            filename = f"rule_{rule.id}.json"

        elif fmt == 'misp':
            object_json = content_convert_to_misp_object(rule_id)
            if not object_json:
                error_mesg = f"Format {rule.format} not found on MISP"
            content = json.dumps(object_json, indent=2)
            filename = f"rule_{rule.id}_misp_object.json"

        else:
            error_mesg = f"Unknown format: {fmt}"

    except Exception as e:
        error_mesg = f"Failed to prepare download: {str(e)}"
    
    if error_mesg:
        return jsonify({
            "message": error_mesg,
            "success": False,
            "toast_class": "danger",
        })
    
    return jsonify({
        "message": f"Rule {rule.title} ready for download",
        "success": True,
        "toast_class": "success",
        "filename": filename,
        "content": content,
    })



@rule_blueprint.route("/get_rule_each_format", methods=["GET"])
def get_rule_each_format():
    """Return a rule in multiple export formats (Normal, JSON, MISP)."""

    rule_id = request.args.get("rule_id", type=int)
    rule = RuleModel.get_rule(rule_id)

    if not rule:
        return jsonify({
            "message": f"No rule found with id={rule_id}",
            "success": False
        }), 404

    rule_json = rule.to_json()
    rule_misp_object = content_convert_to_misp_object(rule_id)

    return_dict = {
        "success": True,
        "rule_id": rule_id,
        "formats": {
            "normal": rule.to_string,
            "json": rule_json,
        }
    }

    if rule_misp_object and rule_json:
        return_dict["formats"]["misp"] = rule_misp_object
    elif rule_json:
        return_dict["formats"]["misp"] = "No MISP object for the format"
    else:
        return_dict["success"] = False
        return_dict["formats"]["misp"] = "No MISP object for the format"
    
    return jsonify(return_dict)

#########################
#   Favorite section    #
#########################

@rule_blueprint.route('/favorite/<int:rule_id>', methods=['GET'])
@login_required
def add_favorite_rule(rule_id) -> redirect:
    """Add a rule to user's favorites via link."""
    existing = AccountModel.is_rule_favorited_by_user(user_id=current_user.id, rule_id=rule_id)
    if existing:
        remove_favorite(user_id=current_user.id, rule_id=rule_id)
        return jsonify({
            "is_favorited": False,
            "toast_class": 'success-subtle',
            "message": "rule remove from favorite"
        }), 200
    else:
        add_favorite(user_id=current_user.id, rule_id=rule_id)
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

@rule_blueprint.route("/comment_add", methods=["GET"])
@login_required
def add_comment() -> jsonify:
    """Add a comment"""
    new_content = request.args.get('new_content', '', type=str)
    rule_id = request.args.get('rule_id', 1, type=int)
    success, message = RuleModel.add_comment_core(rule_id, new_content, current_user)
    flash(message, "success" if success else "danger")
    new_comment = RuleModel.get_latest_comment_for_user_and_rule(current_user.id, rule_id)
    return {
        "comment": {
            "id": new_comment.id,
            "content": new_comment.content,
            "user_name": new_comment.user_name,  
            "user_id": new_comment.user.id,
            "created_at": new_comment.created_at.strftime("%Y-%m-%d %H:%M")
        }
    }

@rule_blueprint.route("/edit_comment", methods=["GET"])
@login_required
def edit_comment() -> jsonify:
    """Edit a comment"""
    comment_id = request.args.get('commentID', 1, type=int)
    new_content = request.args.get('newContent', '', type=str)

    comment = RuleModel.get_comment_by_id(comment_id)
    if  comment.user_id == current_user.id or current_user.is_admin():
        update_content = RuleModel.update_comment(comment_id, new_content)
        if update_content:
            return jsonify({"updatedComment": update_content.to_json(),
                            "success": True,
                            "toast_class": 'success',
                            "message": "Comment edited with success"}), 200
        else:
            return jsonify({ 
            "success": False,
            "toast_class": 'false',
            "message": "failed to edit the comment"
        }), 500
    else:
        return render_template("access_denied.html")
    
@rule_blueprint.route("/comment_delete/<int:comment_id>", methods=["GET"])
@login_required
def delete_comment_route(comment_id) -> render_template:
    """Delete a comment"""
    comment = RuleModel.get_comment_by_id(comment_id)
    if  comment.user_id == current_user.id or current_user.is_admin():
        success = RuleModel.delete_comment(comment_id)
        if success:
            return jsonify({ 
                "success": True,
                "toast_class": 'success',
                "message": "Comment deleted with success"
            }), 200
        else:
            return jsonify({ 
            "success": False,
            "toast_class": 'false',
            "message": "failed to delete the comment"
        }), 500
        #return redirect(url_for("rule.detail_rule", rule_id=rule_id))
    else:
        return render_template("access_denied.html")

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

@rule_blueprint.route("/get_rules_propose_edit_page", methods=['GET'])
def get_rules_propose_edit_page() -> jsonify:
    """Get all the changes propose"""
    page = request.args.get('page', 1, type=int)
    if current_user.is_admin():
        rules_pendings = RuleModel.get_rules_edit_propose_page_pending_admin(page)
    else:
        rules_pendings = RuleModel.get_rules_edit_propose_page_pending(page)
    if rules_pendings:
        rules_pendings_list = [rule_pending.to_json() for rule_pending in rules_pendings]
        return jsonify({
            "total_pages_pending": rules_pendings.pages,
            "rules_pendings_list": rules_pendings_list
        })
    return jsonify({"message": "No Rule"})


@rule_blueprint.route("/get_rules_propose_edit_history_page", methods=['GET'])
@login_required
def get_rules_propose_edit_history_page() -> jsonify:
    """Get all proposed edit changes (paginated history)"""
    page = request.args.get('page', 1, type=int)

    if current_user.is_admin():
        rules_propose_paginated = RuleModel.get_rules_edit_propose_page_admin(page)
    else:
        rules_propose_paginated = RuleModel.get_rules_edit_propose_page(page)

    rules_list = []
    for rule in rules_propose_paginated.items:
        old_content = rule.old_content or ""
        new_content = rule.proposed_content or ""

        old_html, new_html = generate_side_by_side_diff_html(old_content, new_content)

        d = rule.to_dict()
        d['old_diff_html'] = old_html
        d['new_diff_html'] = new_html

        rules_list.append(d)

    if rules_list:
        return jsonify({
            "rules_list": rules_list,
            "total_pages_old": rules_propose_paginated.pages
        })
    return jsonify({"message": "No Rule"})

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
    """Create a new edit (like a change request)"""
    data = request.form
    proposed_content = data.get('rule_content')
    message = data.get('message')
    if not proposed_content:
        flash("Proposed content cannot be empty.", "error")
        # return redirect(url_for('rule.detail_rule', rule_id=rule_id))
        return redirect(url_for('rule.detail_rule', rule_id=rule_id) + "#chap2-pane")
    
    # verify if the proposed content is different from the current content and verify the syntax

    rule = RuleModel.get_rule(rule_id)

    if rule.to_string == proposed_content:
        flash("Proposed content is the same as the current content.", "warning")
        return redirect(url_for('rule.detail_rule', rule_id=rule_id) + "#chap2-pane")
    
    rule_dict = rule.to_json()
    rule_dict['to_string'] = proposed_content
    valide , error = verify_syntax_rule_by_format(rule_dict)
    if not valide:
        flash(f"Syntax error in proposed content: {error}", "error")
        return redirect(url_for('rule.detail_rule', rule_id=rule_id) + "#chap2-pane")

    success = RuleModel.propose_edit_core(rule_id, proposed_content, message)
    if success:
        flash("Request sended.", "success")
    else:
        flash("Request sended but fail.", "error")
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

            if decision == "accepted":
                RuleModel.set_status(rule_proposal_id,"accepted")
                # change the to_string part of the rule in the db 
                response , status_code = RuleModel.set_to_string_rule(rule_id, rule_proposal.proposed_content)
                message = response["message"]
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
                    "new_content": rule.to_string if rule else "Error to charge the rule",
                    "old_content": rule_proposal.old_content
                }

            
                history_id = RuleModel.create_rule_history(result)
                if not history_id:
                    return jsonify({"message": "Error during the creation of the history." ,
                        "success": False,
                        "toast_class" : "danger"
                        }),500

            elif decision == "rejected":
                RuleModel.set_status(rule_proposal_id,"rejected")
                message = "Proposal rejected."
            else:
                return jsonify({"message": "Invalid decision",
                                "success": False,
                                "toast_class" : "danger"}), 400
        return jsonify({"message": message,
                        "success": True,
                        "toast_class" : "success"
                        }),200
    else:
        return render_template("access_denied.html")


@rule_blueprint.route('/proposal_content_discuss', methods=['GET'])
@login_required
def proposal_content_discuss() -> render_template:
    """Redirect to porposal content discuss"""
    rule_edit_id = request.args.get('id', type=int)
    return render_template("rule/proposal_content_discuss.html" , rule_edit_id = rule_edit_id)

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
    """Get all the discuss  where the current user speak"""
    page = request.args.get('page', type=int)
    all_discuss_proposal = RuleModel.get_all_rules_edit_propose_user_part_from_page(page , current_user.id)

    if all_discuss_proposal:
        discuss_list = [rule.to_json() for rule in all_discuss_proposal]
        return jsonify({
            "discuss_list": discuss_list,
            "total_page_discuss": all_discuss_proposal.pages,
        })
    return jsonify({"message": "No Discuss"})

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
    history_rule = RuleModel.get_history_rule_by_id(history_id)

    old_content = history_rule.old_content or ""
    new_content = history_rule.new_content or ""

    old_html, new_html = generate_side_by_side_diff_html(old_content, new_content)

    d = history_rule.to_dict()
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

    d = proposal.to_dict()
    d['old_diff_html'] = old_html
    d['new_diff_html'] = new_html

    return {
        "proposal": d,
    }



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

    if current_user.is_admin() or rule_.user_id == current_user.id:
        if decision == 'accepted':
            rule = RuleModel.get_rule(history.rule_id)
            if rule:
                rule.to_string = history.new_content
                history.message = "accepted"
                flash('Rule content modified !', 'success')
                return redirect(f"/rule/detail_rule/{rule.id}")

            flash('Error , no rule found !', 'danger')
            return redirect(request.referrer or '/')
        if decision == 'rejected':
            rule = RuleModel.get_rule(history.rule_id)
            if rule:
                history.message = "rejected"
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

@rule_blueprint.route("/update_github/update_rules_from_github", methods=['GET'])
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
    with open("app/rule/import_licenses/licenses.txt", "r", encoding="utf-8") as f:
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
    bad_rules = RuleModel.get_bad_rules_page(page)
    total_rules = RuleModel.get_count_bad_rules_page()
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
    page = int(request.args.get("page", 1))
    per_page = 10
    search = request.args.get("search", "")

    query = RuleModel.get_filtered_bad_rules_query(search)
    total_rules = query.count()
    paginated = query.paginate(page=page, per_page=per_page)

    return jsonify({
        "rule": [r.to_json() for r in paginated.items],
        "total_rules": total_rules,
        "total_pages": ceil(total_rules / per_page),
        "user": current_user.first_name
    })

@rule_blueprint.route('/bad_rule/<int:rule_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_bad_rule(rule_id):
    """Edit a bad rule to correct it"""
    bad_rule = RuleModel.get_invalid_rule_by_id(rule_id)
    if bad_rule:
        if current_user.is_admin() or current_user.id == bad_rule.user_id:

            if request.method == 'POST':
                new_content = request.form.get('raw_content')
                # success, error = RuleModel.process_and_import_fixed_rule(bad_rule, new_content )

                success, error , rule = process_and_import_fixed_rule(bad_rule, new_content )

                if success:
                    flash("Rule fixed and imported successfully.", "success")
                    #return redirect(url_for('rule.bad_rules_summary'))
                    return redirect(url_for('rule.detail_rule', rule_id=rule.id))
                else:
                    flash(f"Error: {error}", "danger")
                    bad_rule.error_message = error
                    return render_template('rule/edit_bad_rule.html', rule=bad_rule, new_content=new_content)

            return render_template('rule/edit_bad_rule.html', rule=bad_rule)
        return render_template("access_denied.html")
    return render_template('404.html')

@rule_blueprint.route('/bad_rule/<int:rule_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_bad_rule(rule_id) -> jsonify:
    """Delete a bad rule (error from import)"""
    bad_rule = RuleModel.get_invalid_rule_by_id(rule_id)
    if bad_rule:
        if current_user.is_admin() or current_user.id == bad_rule.user_id :
            if request.method == 'POST':
                success = RuleModel.delete_bad_rule(rule_id)
                if success:
                    return jsonify({"success": True, "message": "Rule deleted!" , "toast_class": "success"})
            return render_template('rule/edit_bad_rule.html', rule=bad_rule)
        return render_template("access_denied.html")
    return render_template("404.html")
    
@rule_blueprint.route('/bad_rule/delete_all_bad_rule', methods=['GET', 'POST'])
@login_required
def delete_all_bad_rule() -> jsonify:
    """Delete all bad rule (error from import)"""

    bad_rules = RuleModel.get_all_bad_rule_user(current_user.id)
    error = 0
    if bad_rules:
        for bad_rule in bad_rules:
            if current_user.is_admin() or current_user.id == bad_rule.user_id :
                success = RuleModel.delete_bad_rule(bad_rule.id)
                if success == False:
                    error += 1
            else:
                return jsonify({ 
                    "success": False,
                    "toast_class": 'danger',
                    "message": "access denied"
                }), 403
        if error > 0:
            return jsonify({ 
                "success": False,
                "toast_class": 'danger',
                "message": "Error to delete {error} bad rules"
            }), 500
        else:
            return jsonify({ 
                "success": True,
                "toast_class": 'success',
                "message": "All the bad rules are delete !"
            }), 200

    else:
        return jsonify({ 
            "success": False,
            "toast_class": 'danger',
            "message": "Error to access bad rule"
        }), 500

#####################
#   Repport rule    #
#####################

@rule_blueprint.route('/report/<int:rule_id>', methods=['GET', 'POST'])
@login_required
def report(rule_id) -> jsonify:
    """Redirect to the repport secion"""
    return render_template('rule/report.html' , rule_id=rule_id)
    
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
    """Create a report for a specific rule (delegated to service)."""
    data = request.get_json()
    result = RuleModel.create_repport(current_user.id,data.get('rule_id'),data.get('message', ''),data.get('reason'))
    
    if result:
        return {
            "message": "Report created successfully.",
            "toast_class": "success",
            "success": True}, 200 
    else:
        return {"success": False,
                "message": "Error to create the report",
                "toast_class": "danger"
                }, 500 

@rule_blueprint.route('/rules_reported', methods=['GET'])
@login_required
def rules_repported():
    """Redirect to the admin report secion"""
    return render_template('admin/report_rule.html')

@rule_blueprint.route("/repport_to_check")
def repport_to_check() -> jsonify:
    """Get the number of changeto check"""
    if current_user.is_admin():
        count = RuleModel.get_total_repport_to_check_admin()
    else:
        count = 0
    return jsonify({"count": count})



@rule_blueprint.route("/get_rules_reported", methods=['GET'])
def   get_rules_reported() -> jsonify:
    """Get all the rules repported on a page"""
    page = request.args.get('page', 1, type=int)
    if current_user.is_admin():
        rules = RuleModel.get_repported_rule(page)
        if rules:
            return {"success": True,
                    "rule": [rule.to_json() for rule in rules],
                    "total_pages": rules.pages
                }
    
        return {"message": "No Rule"}, 404

    else:
        return render_template("access_denied.html")
    

@rule_blueprint.route("/delete_report", methods=['GET'])
def   deleteReport() -> jsonify:
    """Delete report"""
    id  = request.args.get("id")
    
    if current_user.is_admin():
        check = RuleModel.delete_report(id)
        if check:
            return {"success": True,
                    "message": "Report deleted successfully.",
                    "toast_class": "success"
                    }, 200
    
        return {"message": "No Repport",
                "success": False,
                "toast_class": "danger"
                }, 404
    else:
        return render_template("access_denied.html")
    

################
#   History    #
################

@rule_blueprint.route("/get_rules_page_history_", methods=['GET'])
def get_rules_page_history_():
    """Get the history of the rule with HTML diff for each version"""
    page = request.args.get('page', type=int)
    rule_id = request.args.get('rule_id', type=int)

    rules = RuleModel.get_history_rule_(page, rule_id)

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

        # Generate HTML diff for each rule
        old_html, new_html = generate_side_by_side_diff_html(old_content, new_content)

        rule_data = {
            "id": rule.id,
            "rule_title": rule.rule_title,
            "analyzed_at": rule.analyzed_at.strftime("%Y-%m-%d %H:%M") if rule.analyzed_at else "",
            "message": rule.message,
            "old_content": old_content,
            "new_content": new_content,
            "old_html": old_html,
            "new_html": new_html,
            "rule_id": rule.rule_id,
            "success": rule.success,
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
        flash(f"{updated_count} rule(s) updated from '{current_format}' to '{new_format}'.", "success")
    return redirect(url_for("rule.manage_format_rule"))


@rule_blueprint.route("/get_rules_formats", methods=['GET'])
def get_rules_format()-> dict:
    """Get the rules formats"""
    formats = RuleModel.get_all_rule_format()
    if formats:
        return {"success": True,
                "formats": [format.to_json() for format in formats],
                "length": len(formats)
            }, 200
    return {"message": "No formats"}, 404


@rule_blueprint.route("/manage_format_rule", methods=["GET", "POST"])
@login_required
def manage_format_rule() -> render_template:
    """Afficher ou créer un nouveau format de règle"""
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
            "toast_class": "danger"}, 500
    

    success = RuleModel.delete_format(id)
    if success:
        return {"success": True,
                "message": "Format delete",
                "toast_class": "success"
            }, 200
    return {"message": "Failled to delete format",
            "success": False,
            "toast_class": "danger"}, 500

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

@rule_blueprint.route("/import_rules_from_github", methods=['POST'])
@login_required
def import_rules_from_github():
    """
    Clone or access a GitHub repo, then test all YARA rules in it,
    creating rules and classifying bad rules automatically.
    """
    try:
        repo_url = request.json.get('url')
        selected_license = request.json.get('license')

        verif = valider_repo_github(repo_url)
        if not verif :
            return {"message": "Please enter a valid URL to import rules.", "toast_class": "danger-subtle"}, 400

        repo_dir, _ = clone_or_access_repo(repo_url) 

        if not repo_dir:
            return {"message": "Failed to clone or access the repository.", "toast_class": "danger-subtle"}, 400
        
        info = github_repo_metadata(repo_url , selected_license)

        
        session_th = SessionModel.Session_class(repo_dir, current_user, info)
        session_th.start()
        SessionModel.sessions.append(session_th)
        
        return {"message": "Go !", "toast_class": "success-subtle", "session_uuid": session_th.uuid}, 201
    except Exception as e:
        return {"message": f"An error occurred during import: {str(e)}", "toast_class": "danger-subtle"}, 400
    

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

@rule_blueprint.route("/history_github_importer", methods=['GET'])
@login_required
def history_github_importer():
    return render_template("rule/url_github/github_importer.html")


@rule_blueprint.route("/history_github_importer/list", methods=['GET'])
@login_required
def history_github_importer_list():
    page = request.args.get('page', 1, type=int)
    github_importer_list = RuleModel.get_importer_list_page(page)

    return {"history": [g.to_json() for g in github_importer_list], 
            "total_history": github_importer_list.total, 
            "total_pages": github_importer_list.pages}, 200


# @rule_blueprint.route("/import_get_session_running", methods=['GET'])
# @login_required
# def import_get_session_running():
#     return [{"uuid": s.uuid, "info": s.info} for s in SessionModel.sessions]

@rule_blueprint.route("/import_get_session_running", methods=['GET'])
@login_required
def import_get_session_running():
    import_sessions = [
        {"uuid": s.uuid, "info": s.info} 
        for s in SessionModel.sessions
    ]

    update_sessions = [
        {"uuid": s.uuid, "info": s.info} 
        for s in UpdateModel.sessions
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
    github_updater_list = RuleModel.get_updater_list_page(page)

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
    page = request.args.get('page', 1, type=int)  


    # Retrieve paginated results
    paginated = RuleModel.get_updater_result_new_rule_page(sid, page=page)

    if not paginated :
        return {"message": "Session not found", "toast_class": "danger-subtle"}, 404
    rules = paginated.items

    if len(rules) > 0:
        rules_list = [rule.to_json() for rule in rules]

        return {
            "rules": rules_list,
            "total_pages": paginated.pages,
            "total_rules": paginated.total,
        }, 200
    return{
        "rules": []

    }, 200


@rule_blueprint.route("/update_loading_status/<sid>/get_rules", methods=['GET'])
@login_required
def get_rules(sid):
    page = request.args.get('page', 1, type=int)  


    # Retrieve paginated results
    paginated = RuleModel.get_updater_result_rule_page(sid, page=page)
    if not paginated :
        return {"message": "Session not found", "toast_class": "danger-subtle"}, 404

    rules = paginated.items

    if rules:
        rules_list = [rule.to_json() for rule in rules]

        return {
            "rules": rules_list,
            "total_pages": paginated.pages,
            "total_rules": paginated.total,
        }, 200
    return{
        "rules": []

    }, 200

# accetped all change associate to a sid 
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
    try:
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

        return {
            "message": "Rule update verification started successfully.",
            "session_uuid": update_session.uuid,
            "toast_class": "success-subtle"
        }, 201

    except Exception as e:
        return {"message": f"Error while checking rule updates: {str(e)}", "toast_class": "danger-subtle"}, 500


#########################
#   Github url section  #
#########################

@rule_blueprint.route("/list_github_url", methods=['GET'])
def list_github_url() :
    """Go to the list of all github url"""
    return render_template("rule/url_github/list_url_github.html")
    


@rule_blueprint.route("/get_url_github", methods=['GET'])
def get_url_github():
    """List all GitHub URLs and show how many Rules exist for each one."""
    search = request.args.get("search", default=None, type=str)
    page = request.args.get("page", default=1, type=int)

    pagination_urls, total_urls = RuleModel.get_all_url_github_page(page, search)
    pagination_counts, _ = RuleModel.get_rule_count_by_github_page(page, search)

    counts_map = {item.url: item.rule_count for item in pagination_counts.items}

    github_data = []
    for rule in pagination_urls.items:
        url = rule.source
        github_data.append({
            "url": url,
            "rule_count": counts_map.get(url, 0)
        })

    return jsonify({
        "success": True,
        "github_url": github_data,
        "total_url": total_urls,
        "total_pages": pagination_urls.pages
    }), 200




@rule_blueprint.route("/github_detail", methods=['GET'])
def github_detail():
    """Display the detail page for a specific GitHub project URL."""
    url = request.args.get("url", type=str)

    if not url:
        flash("No GitHub URL was provided.", "warning")
        return redirect(url_for("rule.list_github_url"))

    return render_template(
        "rule/url_github/detail_url_github.html",
        url=url
    )

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
        return redirect(request.referrer or url_for('rule.rules_summary'))

    result_obj, error_message = RuleModel.save_invalid_rule_from_new_rule(
        new_rule_obj=temp_rule, 
        user=current_user
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
        
    # On passe le 'source_info' corrigé
    success, message, imported_object = parse_rule_by_format(content, current_user, format, source_info) 
    
    if success:
        return jsonify({"success": True, "message": message, "toast_class": "success-subtle"}), 200
    elif imported_object:
        # duplicate case
        return jsonify({"success": False, "message": message, "toast_class": "warning-subtle"}), 200
    else:
        return jsonify({"success": False, "message": message, "toast_class": "danger-subtle"}), 500