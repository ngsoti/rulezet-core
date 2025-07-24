import asyncio
from urllib.parse import urlparse
from datetime import datetime,  timezone
import difflib
from math import ceil
from flask import Blueprint, Response, jsonify, redirect, request, render_template, flash, url_for
from flask_login import current_user, login_required
from app.account.account_core import add_favorite, remove_favorite
from app.db_class.db import AnonymousUser
from app.import_github_project.cron_check_updates import disable_schedule_job, enable_schedule_job, modify_schedule_job, remove_schedule_job
from app.import_github_project.import_github_yara import  parse_yara_rules_from_repo_async
from app.import_github_project.update_github_project import Check_for_rule_updates
from ..account import account_core as AccountModel
from app.import_github_project.import_github_Zeek import read_and_parse_all_zeek_scripts_from_folder
from app.import_github_project.import_github_sigma import load_rule_files
from app.import_github_project.import_github_suricata import  parse_and_import_suricata_rules_async
from app.import_github_project.untils_import import clone_or_access_repo, delete_existing_repo_folder, extract_owner_repo, get_github_repo_author, get_license_name, git_pull_repo
from .rule_form import AddNewRuleForm, CreateFormatRuleForm, EditRuleForm, EditScheduleForm
from ..utils.utils import  form_to_dict, generate_diff_html, generate_side_by_side_diff_html
from . import rule_core as RuleModel

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
    form = AddNewRuleForm()
    licenses = []
    
    with open("app/rule/import_licenses/licenses.txt", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                licenses.append(line)
    
    form.license.choices = [(lic, lic) for lic in licenses]

    if form.validate_on_submit():
        form_dict = form_to_dict(form)
        external_vars = []
        index = 0
        while True:
            var_type = request.form.get(f'fields[{index}][type]')
            var_name = request.form.get(f'fields[{index}][name]')
            
            if var_type and var_name:  
                external_vars.append({'type': var_type, 'name': var_name})
                index += 1
            else:
                break  

        form_dict['author'] = current_user.first_name
        if form_dict['description'] == '':
            form_dict['description'] = "No description for the rule"
        if form_dict['source'] == '':
            form_dict['source'] = current_user.first_name + " , " + current_user.last_name

        if form_dict['format'] == 'yara' :
            valide , to_string , error = RuleModel.compile_yara(external_vars,form_dict)
            if valide == False:
                return render_template("rule/rule.html",error=error, form=form, rule=rule)
        elif form_dict['format'] == 'sigma':
            valide , to_string , error = RuleModel.compile_sigma(form_dict)
            if valide == False:
                return render_template("rule/rule.html",error=error, form=form, rule=rule)

        RuleModel.add_rule_core(form_dict , current_user)
        flash('Rule added !', 'success')
    
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
    rules = RuleModel.get_rules_of_user_with_id_page(user_id,page)
    total_rules = RuleModel.get_rules_of_user_with_id_count(user_id)
    if rules:
        rules_list = list()
        for rule in rules:
            u = rule.to_json()
            rules_list.append(u)

        return {"success": True,"rule": rules_list, "total_pages": rules.pages, "total_rules": total_rules}
    
    return {"message": "No Rule"}, 404

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
    })


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
        # Load licenses
        with open("app/rule/import_licenses/licenses.txt", "r", encoding="utf-8") as f:
            licenses = [line.strip() for line in f if line.strip()]

        if rule.license and rule.license not in licenses:
            licenses.insert(0, rule.license) 

        form.license.choices = [(lic, lic) for lic in licenses]

        if form.validate_on_submit():
            form_dict = form_to_dict(form)
            # try to compile
            if form_dict['format'] == 'yara' :
                valide , to_string , error = RuleModel.compile_yara([],form_dict)
                if valide == False:
                    return render_template("rule/edit_rule.html",error=error, form=form, rule=rule)
            elif form_dict['format'] == 'sigma':
                valide , to_string , error = RuleModel.compile_sigma(form_dict)
                if valide == False:
                    return render_template("rule/edit_rule.html",error=error, form=form, rule=rule)

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
            
            RuleModel.edit_rule_core(form_dict, rule_id)
            flash("Rule modified with success!", "success")

            return redirect(request.referrer or '/')
        else:
            form.format.data = rule.format
            form.source.data = rule.source
            form.title.data = rule.title
            form.description.data = rule.description
            form.license.data = rule.license  # Selected value
            form.cve_id.data = rule.cve_id
            form.version.data = rule.version
            form.to_string.data = rule.to_string
            rule.last_modif = datetime.now(timezone.utc)
        
        return render_template("rule/edit_rule.html", form=form, rule=rule)
    else:
        return render_template("access_denied.html")

#################
#   Rule info   #
#################

@rule_blueprint.route("/rules_info", methods=['GET'])
def rules_info()-> render_template:
    """Redirect to rule info"""        
    return render_template("rule/rules_info.html")

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


@rule_blueprint.route('/diff/<int:proposal_id>', methods=['GET'])
def get_rule_diff(proposal_id):
    proposal = RuleModel.get_rule_proposal(proposal_id)

    if not proposal.old_content or not proposal.proposed_content:
        return jsonify({"error": "Missing old or proposed content"}), 400

    diffs = RuleModel.get_diff_lines(proposal.old_content, proposal.proposed_content)

    return jsonify({"success": True, "diffs": diffs})



#  lignes = RuleModel.get_diff_lines(rules.old_content , rules.new_content)


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
    
    return {"message": "No Rule"}

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
    })

@rule_blueprint.route("/get_my_rules_page_filter_github", methods=['GET'])
def get_my_rules_page_filter_github() -> jsonify:
    """Get all the rules of the current user with filter"""
    page = int(request.args.get("page", 1))
    per_page = 10
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
                        "toast_class" : "danger"}), 500
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
    #rule.to_string = "]"
    if rule:
        return {"rule": rule.to_json()}
    return {"message": "No Rule"}, 404

@rule_blueprint.route("/detail_rule/<int:rule_id>", methods=['GET'])
def detail_rule(rule_id)-> render_template:
    """Get the detail of the current rule"""
    rule = RuleModel.get_rule(rule_id)
    return render_template("rule/detail_rule.html", rule=rule, rule_content=rule.to_string)

@rule_blueprint.route("/download/<int:rule_id>", methods=['GET'])
def download_rule(rule_id) -> Response:
    """Download a rule"""
    rule = RuleModel.get_rule(rule_id)
    filename = f"{rule.title}.yar"
    content = rule.to_string or ""
    return Response(
        content,
        mimetype='application/octet-stream',
        headers={
            "Content-Disposition": f"attachment;filename={filename}"
        }
    )

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
            "success": True,
            "is_favorited": False,
            "toast_class": 'success',
            "message": "rule remove from favorite"
        }), 200
    else:
        add_favorite(user_id=current_user.id, rule_id=rule_id)
        return jsonify({ 
            "success": True,
            "is_favorited": True,
            "toast_class": 'success',
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
        comments_list = list()
        for comment in comments:
            u = comment.to_json()
            comments_list.append(u)
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
        rule_id = comment.rule_id
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




# @rule_blueprint.route('/get_proposal', methods=['GET'])
# @login_required
# def get_proposal() -> jsonify:
#     """Get the detail porposal"""
#     proposalId = request.args.get('id', type=int)
#     proposal = RuleModel.get_rule_proposal(proposalId)

#     old_content = proposal.old_content or ""
#     new_content = proposal.proposed_content or ""

#     old_html, new_html = generate_side_by_side_diff_html(old_content, new_content)

#     d = proposal.to_dict()
#     d['old_diff_html'] = old_html
#     d['new_diff_html'] = new_html

#     return {
#         "proposal": d,
#     }



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
    proposed_content = data.get('proposed_content')
    message = data.get('message')
    success = RuleModel.propose_edit_core(rule_id, proposed_content, message)
    if success:
        flash("Request sended.", "success")
    else:
        flash("Request sended but fail.", "danger")
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

            elif decision == "rejected":
                RuleModel.set_status(rule_proposal_id,"rejected")
                message = "rejected"
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


@rule_blueprint.route("/get_schedule", methods=["GET"])
@login_required
def get_schedule():
    schedule_id = request.args.get("schedule_id", default=1, type=int)


    schedule = RuleModel.get_schedule(schedule_id)
    if schedule:
        if current_user.id == schedule.user_id or current_user.is_admin():
            return jsonify({
                "schedule":  schedule.to_json(),
                "message": "schedule found",
                "success": True
            }), 200
        else:
            return jsonify( 
                success= False, 
                message= "You don't have the permission to do that !", 
                toast_class= "danger"), 401
    else:
        return jsonify({
                "schedule":  [],
                "message": "schedule not found",
                "success": False
            }), 500


@rule_blueprint.route("/edit_schedule/<int:schedule_id>", methods=['GET', 'POST'])
def edit_schedule(schedule_id) -> render_template:   
    """Redirect to edit schedule """ 
    schedule = RuleModel.get_schedule(schedule_id)
    
    if current_user.id == schedule.user_id or current_user.is_admin():
        form = EditScheduleForm() 
        
        if form.validate_on_submit():
            form_dict = form_to_dict(form)
            success = RuleModel.edit_schedule(form_dict, schedule_id)
            
            if success:
                modify_schedule_job(
                    schedule_id=schedule_id,
                    days=form.days.data,
                    hour=form.hour.data,
                    minute=form.minute.data
                )

                flash("Schedule modified with success!", "success")
                return redirect(request.referrer or '/')

        else:
            # Pré-remplissage du formulaire
            form.name.data = schedule.name
            form.description.data = schedule.description
            form.hour.data = schedule.hour
            form.minute.data = schedule.minute
            form.days.data = schedule.days
            form.active.data = schedule.active

        return render_template("rule/update_github/edit_schedule.html", schedule_id=schedule_id, form=form)

    else:
        return render_template("access_denied.html")


@rule_blueprint.route("/update_rule_schedule", methods=['POST'])
def update_rule_schedule():
    """Update rule schedule"""

    data = request.get_json(force=True)
    rule_items = data.get("rules", [])
    schedule_id = data.get("schedule_id", None)

    schedule = RuleModel.get_schedule(schedule_id)
    if not schedule:
        return jsonify(
            success=False,
            message="Schedule not found.",
            toast_class="danger"
        ), 404

    if current_user.id != schedule.user_id and not current_user.is_admin():
        return jsonify(
            success=False,
            message="You don't have the permission to do that!",
            toast_class="danger"
        ), 401

    success = RuleModel.update_schedule_rules(schedule_id, rule_items)

    if success:
        return jsonify({
            "message": "Schedule updated successfully!",
            "toast_class": "success",
            "success": True
        }), 200
    else:
        return jsonify({
            "message": "Error during the update of the schedule!",
            "toast_class": "danger",
            "success": False
        }), 500



@rule_blueprint.route("/update/delete_schedule", methods=["GET"])
@login_required
def delete_schedule():
    schedule_id = request.args.get("schedule_id",  type=int)

    if not schedule_id:
        return jsonify(success=False, message="Schedule ID missing"), 400

    schedule = RuleModel.get_schedule(schedule_id)
    if not schedule:
        return jsonify(success=False, message="Schedule not found"), 404
    if current_user.is_admin() or schedule.user_id == current_user.id:
        data = RuleModel.delete_auto_update_schedule( schedule_id)

        if data:
            remove_schedule_job(schedule_id=schedule_id)
            return jsonify({
                "message": "Schedule delete with success !",
                "toast_class": "success",
                "success": True
            }), 200
        return jsonify({
                "message": "Error during the delete of the Schedule !",
                "toast_class": "danger",
                "success": False
            }), 500
    return jsonify( 
        success= False, 
        message= "You don't have the permission to do that !", 
        toast_class= "danger"), 401

@rule_blueprint.route('/update/toggle_active', methods=['GET'])
@login_required
def toggle_active_schedule():
    schedule_id = request.args.get("schedule_id",  type=int)

    if not schedule_id:
        return jsonify(success=False, message="Schedule ID missing"), 400

    schedule = RuleModel.get_schedule(schedule_id)
    if not schedule:
        return jsonify(success=False, message="Schedule not found"), 404


    if current_user.is_admin() or schedule.user_id == current_user.id:
        if schedule.active:
            schedule.active = False
            disable_schedule_job(schedule_id)
        else:
            schedule.active = True
            enable_schedule_job(schedule_id,schedule.days, schedule.hour, schedule.minute)
        
        return jsonify(success=True, message=f"Schedule {'activated' if schedule.active else 'deactivated'}" , toast_class="success"), 200
    return jsonify( 
        success= False, 
        message= "You don't have the permission to do that !", 
        toast_class= "danger"), 401


@rule_blueprint.route("/update/create_auto_update", methods=["POST"])
@login_required
def create_auto_update():
    data = request.get_json(force=True)

    update_hour = data.get("updateHour", None)
    update_minute = data.get("updateMinute", None)
    selected_days = data.get("selectedDays", [])
    rule_ids = data.get("ruleIds", []) 
    update_name = data.get("updateName", "No name")
    update_description = data.get("updateDescription", None)
    if update_name is None:
        return jsonify({
            "message": "Name null",
            "success": False,
            "toast_class": "danger"
        }), 400

    if update_hour is None or update_hour < 0 or update_hour > 23:
        return jsonify({
            "message": "Invalid or missing Hour. Must be between 0 and 23.",
            "success": False,
            "toast_class": "danger"
        }), 400

    if update_minute is None or update_minute < 0 or update_minute > 59:
        return jsonify({
            "message": "Invalid or missing Minute. Must be between 0 and 59.",
            "success": False,
            "toast_class": "danger"
        }), 400

    if not selected_days:
        return jsonify({
            "message": "You must select at least one day for the update.",
            "success": False,
            "toast_class": "warning"
        }), 400

    allowed_days = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
    invalid_days = [d for d in selected_days if d.lower() not in allowed_days]
    if invalid_days:
        return jsonify({
            "message": f"Invalid day(s) selected: {', '.join(invalid_days)}.",
            "success": False,
            "toast_class": "danger"
        }), 400

    result = RuleModel.create_auto_update_schedule(update_hour, update_minute, selected_days,update_name, update_description, rule_ids)

    if result.get("success"):
        if result.get("created"):
            message = "Auto-update successfully scheduled!"
            toast_class = "success"
            status_code = 200
        else:
            message = "An identical auto-update schedule already exists."
            toast_class = "info"
            status_code = 200  
    else:
        message = "Error during insert to the db"
        toast_class = "danger"
        status_code = 500

    return jsonify({
        "message": message,
        "success": result.get("success", False),
        "toast_class": toast_class
    }), status_code




@rule_blueprint.route("/check_updates", methods=["POST"])
@login_required
def check_updates():
    data = request.get_json()
    rule_items = data.get("rules", [])  # [{'id': 6323, 'title': '...'}]
    results = []
    sources = RuleModel.get_sources_from_titles(rule_items)     #  45 sec 
    
    ############################################# faire un chrone ( problème automatisation , time out probleme , trop de demande )
    for source in sources:
        repo_dir, exists = clone_or_access_repo(source)
        git_pull_repo(repo_dir)
            
    ###############################################

    for item in rule_items:
        rule_id = item.get("id")
        title = item.get("title", "Unknown Title")
        message_dict, success, new_rule_content = Check_for_rule_updates(rule_id)
        rule = RuleModel.get_rule(rule_id)
        
        if success and new_rule_content:
            result = {
                "id": rule_id,
                "title": title,
                "success": success,
                "message": message_dict.get("message", "No message"),
                "new_content": new_rule_content,
                "old_content": rule.to_string if rule else "Error to charge the rule"
            }

            history_id = RuleModel.create_rule_history(result)
            if history_id is None:
                result["history_id"] = None
            else:
                result["history_id"] = history_id

            results.append(result)
    return {
        "message": "Search completed successfully. All selected rules have been processed without issues.", 
            "nb_update": len(results), 
            "results": results,
            "success": True,
            "toast_class" : "success"
        }, 200 


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

@rule_blueprint.route("/update_github_rule", methods=['GET'])
@login_required
def update_github_rule() -> render_template:
    """Update a rule from github"""
    history_id = request.args.get('rule_id')
    decision = request.args.get('decision')


    history = RuleModel.get_history_rule_by_id(history_id)
    

    if current_user.is_admin() or history.analyzed_by_user_id == current_user.id:
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
    rule_type = request.args.get("rule_type", None) 
    sources = RuleModel.get_all_rule_sources_by_user()
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

@rule_blueprint.route("/import_rules_from_github", methods=['GET', 'POST'])
@login_required
def import_rules_from_github() -> redirect:
    if request.method == 'POST':
        repo_url = request.form.get('url')
        selected_license = request.form.get('license')
        external_vars = []
        index = 0
        while True:
            var_type = request.form.get(f'fields[{index}][type]')
            var_name = request.form.get(f'fields[{index}][name]')
            if var_type and var_name:
                external_vars.append({'type': var_type, 'name': var_name})
                index += 1
            else:
                break

        try:
            info = get_github_repo_author(repo_url)
            repo_dir, existe = clone_or_access_repo(repo_url) 

            if not repo_dir:
                flash("Failed to clone or access the repository.", "danger")
                return redirect(url_for("rule.rules_list"))

            owner, repo = extract_owner_repo(repo_url)
            license_from_github = selected_license or get_license_name(owner, repo)

        
            yara_imported, yara_skipped, yara_failed, bad_rules_yara = asyncio.run(
                parse_yara_rules_from_repo_async(repo_dir, license_from_github, repo_url, current_user)
            )

            
            bad_rule_dicts_Sigma, nb_bad_rules_sigma, imported_sigma, skipped_sigma = asyncio.run(
                load_rule_files(repo_dir, license_from_github, repo_url, current_user)
            )
            rule_dicts_Zeek = read_and_parse_all_zeek_scripts_from_folder(repo_dir, repo_url, license_from_github, info)


        
            imported_suricata, suricata_skipped = asyncio.run(
                parse_and_import_suricata_rules_async(repo_dir, license_from_github, repo_url, info, current_user)
            )



            imported = imported_sigma + yara_imported + imported_suricata
            skipped = skipped_sigma + yara_skipped + suricata_skipped

            # Import des règles Zeek
            if rule_dicts_Zeek:
                for rule_dic3 in rule_dicts_Zeek:
                    success = RuleModel.add_rule_core(rule_dic3, current_user)
                    if success:
                        imported += 1
                    else:
                        skipped += 1

            flash(f"{imported} rules imported. {skipped} ignored (already exist).", "success")
            delete_existing_repo_folder("app/rule/output_rules/Yara")

            if bad_rules_yara:
                flash(f"Failed to import {len(bad_rules_yara)} YARA rules.", "danger")
                RuleModel.save_invalid_rules(bad_rules_yara, "YARA", repo_url, license_from_github , current_user)

            if bad_rule_dicts_Sigma:
                flash(f"Failed to import {nb_bad_rules_sigma} Sigma rules.", "danger")
                RuleModel.save_invalid_rules(bad_rule_dicts_Sigma, "Sigma", repo_url, license_from_github , current_user)

            if bad_rule_dicts_Sigma or bad_rules_yara:
                return redirect(url_for("rule.bad_rules_summary"))

        except Exception as e:
            flash(f"Failed to import rules: with url :  {repo_url} because : {e}", "danger")

    return redirect(url_for("rule.rules_list"))


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
    user_bad_rule = RuleModel.get_user_id_of_bad_rule(rule_id)
    if current_user.is_admin() or current_user.id == user_bad_rule:
        bad_rule = RuleModel.get_invalid_rule_by_id(rule_id)

        if request.method == 'POST':
            new_content = request.form.get('raw_content')
            success, error = RuleModel.process_and_import_fixed_rule(bad_rule, new_content )

            if success:
                flash("Rule fixed and imported successfully.", "success")
                return redirect(url_for('rule.bad_rules_summary'))
            else:
                flash(f"Error: {error}", "danger")
                bad_rule.error_message = error
                return render_template('rule/edit_bad_rule.html', rule=bad_rule, new_content=new_content)

        return render_template('rule/edit_bad_rule.html', rule=bad_rule)
    else:
        return render_template("access_denied.html")

@rule_blueprint.route('/bad_rule/<int:rule_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_bad_rule(rule_id) -> jsonify:
    """Delete a bad rule (error from import)"""
    user_bad_rule = RuleModel.get_user_id_of_bad_rule(rule_id)
    if current_user.is_admin() or current_user.id == user_bad_rule :
        bad_rule = RuleModel.get_invalid_rule_by_id(rule_id)
        if request.method == 'POST':
            success = RuleModel.delete_bad_rule(rule_id)
            if success:
                return jsonify({"success": True, "message": "Rule deleted!" , "toast_class": "success"})
        return render_template('rule/edit_bad_rule.html', rule=bad_rule)
    else:
        return render_template("access_denied.html")
    
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


@rule_blueprint.route("/get_old_rule_choice", methods=['GET'])
def get_old_rule_choice()-> render_template:
    """Get the history of the rule"""
    page = request.args.get('page', type=int)
    rules = RuleModel.get_old_rule_choice(page)
    if rules:
        return {"success": True,
                "rule": [rule.to_json() for rule in rules],
                "total_pages": rules.pages
            }, 200
    return {"message": "No Rule"}, 404


####################
#   Rule formats   #
####################

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


@rule_blueprint.route("/create_format_rule", methods=["GET", "POST"])
@login_required
def create_format_rule() -> render_template:
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
            return render_template("admin/create_format.html", form=form)

    return render_template("admin/create_format.html", form=form)

@rule_blueprint.route("/get_rules_formats_pages", methods=['GET'])
def get_rules_formats_pages()-> dict:
    """Get the rules formats pages"""
    page = request.args.get('page', type=int)
    _formats = RuleModel.get_all_rule_format_page(page)
    if _formats:
        return {"success": True,
                "rules_formats": [format.to_json() for format in _formats],
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

