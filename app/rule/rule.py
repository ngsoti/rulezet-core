import asyncio
from datetime import datetime,  timezone
from math import ceil
from flask import Blueprint, Response, jsonify, redirect, request, render_template, flash, session, url_for
from flask_login import current_user, login_required
from app.account.account_core import add_favorite, remove_favorite
from ..account import account_core as AccountModel
from app.import_github_project.import_github_Zeek import read_and_parse_all_zeek_scripts_from_folder
from app.import_github_project.import_github_sigma import load_rule_files
from app.import_github_project.import_github_suricata import  parse_suricata_rules_from_file
from app.import_github_project.import_github_yara import read_and_parse_all_yara_rules_from_folder_test, save_yara_rules_as_is
from app.import_github_project.untils_import import clone_or_access_repo, delete_existing_repo_folder, extract_owner_repo, get_github_repo_author, get_license_name
from .rule_form import AddNewRuleForm, EditRuleForm
from ..utils.utils import form_to_dict
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
    
    return {"message": "No Rule"}, 404


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

@rule_blueprint.route("/delete_rule", methods=['POST'])
@login_required
def delete_rule() -> jsonify:
    """Delete a rule"""
    data = request.get_json()
    rule_id = data.get('id')
    user_id = RuleModel.get_rule_user_id(rule_id)

    if current_user.id == user_id or current_user.is_admin():
        RuleModel.delete_rule_core(rule_id)
        return jsonify({"success": True, "message": "Rule deleted!"})
    
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



            RuleModel.edit_rule_core(form_dict, rule_id)
            flash("Rule modified with success!", "success")
            return redirect("/rule/rules_list")
        else:
            form.format.data = rule.format
            form.source.data = rule.source
            form.title.data = rule.title
            form.description.data = rule.description
            form.license.data = rule.license  # Selected value
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


#################
#   Rule owner  #
#################

# @rule_blueprint.route("/get_rules_page_owner", methods=['GET'])
# def get_rules_page_owner() -> jsonify:
#     """Get all the rule of the user"""
#     page = request.args.get('page', 1, type=int)
#     rules = RuleModel.get_rules_page_owner(page)    
#     total_rules = RuleModel.get_total_rules_count_owner()  

#     if rules:
#         rules_list = list()
#         for rule in rules:
#             u = rule.to_json()
#             rules_list.append(u)
#         return {"rule": rules_list, "total_pages": rules.pages, "total_rules": total_rules}
    
#     return {"message": "No Rule"}, 404

@rule_blueprint.route("/get_my_rules_page_filter", methods=['GET'])
def get_rules_page_filter_owner() -> jsonify:
    """Get all the rules of the current user with filter"""
    page = int(request.args.get("page", 1))
    per_page = 10
    search = request.args.get("search", None)
    author = request.args.get("author", None)
    sort_by = request.args.get("sort_by", "newest")
    rule_type = request.args.get("rule_type", None) 

    query = RuleModel.filter_rules_owner( search=search, author=author, sort_by=sort_by, rule_type=rule_type)
    total_rules = query.count()
    rules = query.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "rule": [r.to_json() for r in rules],
        "total_rules": total_rules,
        "total_pages": ceil(total_rules / per_page)
    })

#get_my_rules_page_filter

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
        return jsonify({"success": False, "message": "Failed to delete the rules!"})
    else:
        return jsonify({"success": True, "message": "Rule deleted!"}) 


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
        flash("Rule remove from favorites!", "success")
    else:
        add_favorite(user_id=current_user.id, rule_id=rule_id)
        flash("Rule added to favorites!", "success")
    return redirect(request.referrer or url_for('rule.rules_list'))

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
        return jsonify({"updatedComment": update_content.to_json()})
    else:
        return render_template("access_denied.html")
    
@rule_blueprint.route("/comment_delete/<int:comment_id>", methods=["GET"])
@login_required
def delete_comment_route(comment_id) -> render_template:
    """Delete a comment"""
    comment = RuleModel.get_comment_by_id(comment_id)
    if  comment.user_id == current_user.id or current_user.is_admin():
        rule_id = comment.rule_id
        RuleModel.delete_comment(comment_id)
        return redirect(url_for("rule.detail_rule", rule_id=rule_id))
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
        rules_propose = RuleModel.get_rules_edit_propose_page_admin()
        rules_pendings = RuleModel.get_rules_edit_propose_page_pending_admin(page)
        total_rules_pending = RuleModel.get_total_change_to_check_admin()
    else:
        rules_propose = RuleModel.get_rules_edit_propose_page()
        rules_pendings = RuleModel.get_rules_edit_propose_page_pending(page)
        total_rules_pending = RuleModel.get_total_change_to_check()

    if rules_propose and rules_pendings:
        rules_list = [rule.to_json() for rule in rules_propose]
        rules_pendings_list = [rule_pending.to_json() for rule_pending in rules_pendings]
        return jsonify({
            "rules_list": rules_list,
            "total_pages_pending": rules_pendings.pages,
            "rules_pendings_list": rules_pendings_list,
            "total_rules_pending": total_rules_pending
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
    proposed_content = data.get('proposed_content')
    message = data.get('message')
    print(proposed_content)
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
                message = RuleModel.set_to_string_rule(rule_id, rule_proposal.proposed_content)
            elif decision == "rejected":
                RuleModel.set_status(rule_proposal_id,"rejected")
                message = "rejected"
            else:
                return jsonify({"message": "Invalid decision"}), 400
        return jsonify({"message": message})
    else:
        return render_template("access_denied.html")


@rule_blueprint.route('/proposal_content_discuss', methods=['GET'])
@login_required
def proposal_content_discuss() -> render_template:
    """Redirect to porposal content discuss"""
    rule_edit_id = request.args.get('id', type=int)
    return render_template("rule/proposal_content_discuss.html" , rule_edit_id = rule_edit_id)


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

@rule_blueprint.route('/get_proposal', methods=['GET'])
@login_required
def get_proposal() -> jsonify:
    """Get the detail porposal"""
    proposalId = request.args.get('id', type=int)
    proposal = RuleModel.get_rule_proposal(proposalId)
    return proposal.to_json()

@rule_blueprint.route('/get_discuss_part_from', methods=['GET'])
@login_required
def get_discuss_part_from() -> jsonify:
    """Get all the discuss  where the current user speak"""
    page = request.args.get('page', type=int)
    all_discuss_proposal = RuleModel.get_all_rules_edit_propose_user_par_frompage(page , current_user.id)

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




@rule_blueprint.route("/test_yara_python_url", methods=['GET', 'POST'])
@login_required
def test_yara_python_url() -> redirect:
    """Import all the rules from github Repo"""
    if request.method == 'POST':
        # take the different param (url and external var if existe)
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
            repo_dir , existe  = clone_or_access_repo(repo_url) 

            if not repo_dir:
                flash("Failed to clone or access the repository.", "danger")
                return redirect(url_for("rule.rules_list"))
            
            # save all the yara rules 
            save_yara_rules_as_is(repo_url) 
            
            #license 
            owner, repo = extract_owner_repo(repo_url)
            if selected_license:
                license_from_github = selected_license
            else:
                license_from_github = get_license_name(owner,repo)
            # parse rules
            # rule_dicts_Sigma , bad_rule_dicts_Sigma , nb_bad_rules_sigma= load_rule_files(repo_dir, license_from_github, repo_url)
            bad_rule_dicts_Sigma, nb_bad_rules_sigma, imported_sigma, skipped_sigma = asyncio.run(
                load_rule_files(repo_dir, license_from_github, repo_url, current_user)
            )
            rule_dicts_Zeek = read_and_parse_all_zeek_scripts_from_folder(repo_dir,repo_url,license_from_github, info)
            rule_dicts_Yara , bad_rule_dicts_Yara, nb_bad_rules_yara = read_and_parse_all_yara_rules_from_folder_test(license_from_github, repo_url, external_vars)
            rule_dicts_Suricata = parse_suricata_rules_from_file(repo_dir ,license_from_github, repo_url ,info)

            imported = imported_sigma
            skipped = skipped_sigma
            
            # if rule_dicts_Sigma:
            #     for rule_dict in rule_dicts_Sigma:
            #         success = RuleModel.add_rule_core(rule_dict , current_user)

            #         if success:
            #             imported += 1
            #         else:
            #             skipped += 1
            if rule_dicts_Yara:
                for rule_dic2 in rule_dicts_Yara:
                    success = RuleModel.add_rule_core(rule_dic2 , current_user)

                    if success:
                        imported += 1
                    else:
                        skipped += 1
            if rule_dicts_Zeek:
                for rule_dic3 in rule_dicts_Zeek:
                    success = RuleModel.add_rule_core(rule_dic3 , current_user)

                    if success:
                        imported += 1
                    else:
                        skipped += 1
            if rule_dicts_Suricata:
                for rule_dict4 in rule_dicts_Suricata:
                    success = RuleModel.add_rule_core(rule_dict4 , current_user)

                    if success:
                        imported += 1
                    else:
                        skipped += 1
            flash(f"{imported} rules imported. {skipped} ignored (already exist).", "success")
            delete_existing_repo_folder("app/rule/output_rules/Yara")

            # if an other user attempt to import the same depot, he can't have acces to the bad rule 
            if existe == False:
                if bad_rule_dicts_Yara:
                    flash(f"Failed to import {nb_bad_rules_yara} YARA rules:  ", "danger")
                    RuleModel.save_invalid_rules(bad_rule_dicts_Yara, "YARA", repo_url, license_from_github)
                if bad_rule_dicts_Sigma:
                    flash(f"Failed to import {nb_bad_rules_sigma} Sigma rules:  ", "danger")
                    RuleModel.save_invalid_rules(bad_rule_dicts_Sigma, "Sigma", repo_url, license_from_github)
                if bad_rule_dicts_Sigma or bad_rule_dicts_Yara:
                    return redirect(url_for("rule.bad_rules_summary"))

        except Exception as e:
            flash("Failed to import rules: URL  ", "danger")

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
            success, error = RuleModel.process_and_import_fixed_rule(bad_rule, new_content)

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

# @rule_blueprint.route('/bad_rule/<int:rule_id>/edit', methods=['GET', 'POST'])
# @login_required
# def edit_bad_rule(rule_id) -> render_template:
#     """Edit a bad rule to correct it"""
#     user_bad_rule = RuleModel.get_user_id_of_bad_rule(rule_id)
#     if current_user.is_admin() or current_user.id == user_bad_rule :
#         bad_rule = RuleModel.get_invalid_rule_by_id(rule_id)
#         if request.method == 'POST':
#             new_content = request.form.get('raw_content')
#             success, error = RuleModel.process_and_import_fixed_rule(bad_rule, new_content)
#             if success:
#                 flash("Rule fixed and imported successfully.", "success")
#                 # delete the bad rule
#                 # delete = RuleModel.delete_bad_rule(rule_id)
#                 # if delete:
#                 #     return redirect(url_for('rule.bad_rules_summary'))
#                 return redirect(url_for('rule.bad_rules_summary'))
#             else:
#                 flash(f"Error: {error}", "danger")
#                 bad_rule.error_message = error
#                 return render_template('rule/edit_bad_rule.html', rule=bad_rule, new_content=new_content)
#         return render_template('rule/edit_bad_rule.html', rule=bad_rule)
#     else:
#         return render_template("access_denied.html")

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
                return jsonify({"success": True, "message": "Rule deleted!"})
        return render_template('rule/edit_bad_rule.html', rule=bad_rule)
    else:
        return render_template("access_denied.html")

