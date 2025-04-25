from datetime import datetime, timezone
from flask import Blueprint, Response, jsonify, redirect, request,render_template, flash, url_for
from flask_login import current_user, login_required

from app.db_class.db import Rule, RuleFavoriteUser
from app.favorite.favorite_core import add_favorite
from app.import_github_project.read_github_YARA import extract_owner_repo, get_license_name, read_and_parse_all_yara_rules_from_folder, save_yara_rules_as_is

from .rule_form import AddNewRuleForm, EditRuleForm
from ..utils.utils import form_to_dict
from . import rule_core as RuleModel
from ..comment import comment_core as CommentModel

rule_blueprint = Blueprint(
    'rule',
    __name__,
    template_folder='templates',    
    static_folder='static'
)


@rule_blueprint.route("/", methods=['GET', 'POST'])
@login_required
def rule():
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
        RuleModel.add_rule_core(form_dict)
        flash('Rule added !', 'success')
        
    return render_template("rule/rule.html", form=form)

@rule_blueprint.route("/rules_list", methods=['GET', 'POST'])
@login_required
def rules_list():        
    return render_template("rule/rules_list.html")


@rule_blueprint.route("/get_rules_page", methods=['GET'])
def get_rules_page():
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



@rule_blueprint.route("/get_rules_page_owner", methods=['GET'])
def get_rules_page_owner():
    page = request.args.get('page', 1, type=int)
    rules = RuleModel.get_rules_page_owner(page)
    
    total_rules = RuleModel.get_total_rules_count_owner()  

    if rules:
        rules_list = list()
        for rule in rules:
            u = rule.to_json()
            rules_list.append(u)

        return {"rule": rules_list, "total_pages": rules.pages, "total_rules": total_rules}
    
    return {"message": "No Rule"}, 404







@rule_blueprint.route("/delete_rule", methods=['GET', 'POST'])
@login_required
def delete_rule():
    rule_id = request.args.get('id', 1, int)
    user_id = RuleModel.get_rule_user_id(rule_id)

    if current_user.id == user_id or current_user.is_admin():
        RuleModel.delete_rule_core(rule_id)
        return jsonify({"success": True, "message": "Rule deleted!"})
    
    return render_template("access_denied.html")


@rule_blueprint.route("/get_current_user", methods=['GET', 'POST'])
@login_required
def get_current_user():
    return jsonify({'user': current_user.is_admin()})



    






@rule_blueprint.route("/detail_rule/<int:rule_id>", methods=['GET'])
@login_required
def detail_rule(rule_id):
    rule = RuleModel.get_rule(rule_id)
    return render_template("rule/detail_rule.html", rule=rule)


@rule_blueprint.route('/vote_rule', methods=['GET','POST'])
@login_required
def vote_rule():
    rule_id = request.args.get('id', 1 , int)
    vote_type = request.args.get('vote_type', 2 , str)
    rule = RuleModel.get_rule(rule_id)

    

    if rule:
        alreadyVote , already_vote_type= RuleModel.has_already_vote(rule_id, current_user.id)
        if vote_type == 'up':  
            if alreadyVote == False:
                RuleModel.increment_up(rule_id)
                RuleModel.has_voted('up',rule_id)
            elif already_vote_type == 'up':
                RuleModel.remove_one_to_increment_up(rule_id)
                RuleModel.remove_has_voted('up',rule_id)
        elif vote_type == 'down':
            if alreadyVote == False:
                RuleModel.decrement_up(rule_id)
                RuleModel.has_voted('down',rule_id)
            elif already_vote_type == 'down':
                RuleModel.remove_one_to_decrement_up(rule_id)
                RuleModel.remove_has_voted('down',rule_id)

        return jsonify({
            'vote_up': rule.vote_up,
            'vote_down': rule.vote_down
        })

    return jsonify({"message": "Rule not found"})


@rule_blueprint.route("/owner_rules", methods=['GET'])
@login_required
def owner_rules():
    return render_template("rule/rules_owner.html")




@rule_blueprint.route("/edit_rule/<int:rule_id>", methods=['GET', 'POST'])
@login_required
def edit_rule(rule_id):
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
            RuleModel.edit_rule_core(form_dict, rule_id)
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

@rule_blueprint.route("/download/<int:rule_id>", methods=['GET', 'POST'])
@login_required
def download_rule(rule_id):

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

# not use yet
@rule_blueprint.route("/search_rules", methods=['GET','POST'])
@login_required
def search_rules():
    query = request.args.get("query", "").strip().lower()
    if not query:
        return jsonify({"rules": []})

    results = RuleModel.search_rules(current_user.id,query)  
    return jsonify({"rules": [r.to_json() for r in results]})

#-----------------------------------------------------------favorite_part-----------------------------------------------------------#


@rule_blueprint.route('/favorite/<int:rule_id>', methods=['GET'])
@login_required
def add_favorite_rule(rule_id):
    """Add a rule to user's favorites via link."""
    rule = RuleModel.get_rule(rule_id)

    existing = RuleFavoriteUser.query.filter_by(user_id=current_user.id, rule_id=rule_id).first()
    if existing:
        flash("This rule is already in your favorites.", "info")
    else:
        fav = add_favorite(user_id=current_user.id, rule_id=rule_id)
        flash("Rule added to favorites!", "success")

    return redirect(url_for('rule.rules_list')) 



#-----------------------------------------------------------comment_part-----------------------------------------------------------#


@rule_blueprint.route("/detail_rule/get_comments_page", methods=['GET'])
@login_required
def comment_rule():
    page = request.args.get('page', 1, type=int)
    rule_id = request.args.get('rule_id', type=int)
    comments = CommentModel.get_comment_page(page , rule_id)
    total_comments = CommentModel.get_total_comments_count()
    if comments:
        comments_list = list()
        for comment in comments:
            u = comment.to_json()
            comments_list.append(u)
        return {"comments_list": comments_list, "total_comments": total_comments}
    return {"message": "No Comments"}, 404



@rule_blueprint.route("/comment_add", methods=["POST", "GET"])
@login_required
def add_comment():
    new_content = request.args.get('new_content', '', type=str)
    rule_id = request.args.get('rule_id', 1, type=int)

    success, message = CommentModel.add_comment_core(rule_id, new_content)
    flash(message, "success" if success else "danger")
    new_comment = CommentModel.get_latest_comment_for_user_and_rule(current_user.id, rule_id)
    return {
        "comment": {
            "id": new_comment.id,
            "content": new_comment.content,
            "user_name": new_comment.user_name,  
            "user_id": new_comment.user.id,
            "created_at": new_comment.created_at.strftime("%Y-%m-%d %H:%M")
        }
    }

@rule_blueprint.route("/edit_comment", methods=["POST", "GET"])
@login_required
def edit_comment():
    comment_id = request.args.get('commentID', 1, type=int)
    new_content = request.args.get('newContent', '', type=str)

    comment = CommentModel.get_comment_by_id(comment_id)
    if  comment.user_id == current_user.id or current_user.is_admin():
        update_content = CommentModel.update_comment(comment_id, new_content)
        # flash("Comment updated successfully.", "success")
        return jsonify({"updatedComment": update_content.to_json()})
    else:
        return render_template("access_denied.html")
    
@rule_blueprint.route("/comment_delete/<int:comment_id>", methods=["POST", "GET"])
@login_required
def delete_comment_route(comment_id):
    comment = CommentModel.get_comment_by_id(comment_id)
    if  comment.user_id == current_user.id or current_user.is_admin():
        rule_id = comment.rule_id
        CommentModel.delete_comment(comment_id)
        # flash("Comment deleted.", "success")
        return redirect(url_for("rule.detail_rule", rule_id=rule_id))
    else:
        return render_template("access_denied.html")


#-----------------------------------------------------------propose_edit-----------------------------------------------------------#


@rule_blueprint.route("/rule_propose_edit", methods=["POST", "GET"])
@login_required
def rule_propose_edit():
    return render_template("rule/rule_propose_edit.html")



@rule_blueprint.route("/get_rules_propose_edit_page", methods=['GET'])
def get_rules_propose_edit_page():
    page = request.args.get('page', 1, type=int)
    rules_propose = RuleModel.get_rules_edit_propose_page(page)
    rules_pendings = RuleModel.get_rules_edit_propose_page_pending(page)
    
    
    if rules_propose and rules_pendings:
        rules_list = list()
        for rule in rules_propose:
            u = rule.to_json()
            rules_list.append(u)
        rules_pendings_list = list()
        for rule_pending in rules_pendings:
            m = rule_pending.to_json()
            rules_pendings_list.append(m)

        return {"rules_list": rules_list, "total_pages": rules_propose.pages, "rules_pendings_list": rules_pendings_list}
    
    return {"message": "No Rule"}, 404

@rule_blueprint.route('/propose_edit/<int:rule_id>', methods=['POST'])
@login_required
def propose_edit(rule_id):
    rule = RuleModel.get_rule(rule_id)
    data = request.form
    proposed_content = data.get('proposed_content')
    message = data.get('message')

    success = RuleModel.propose_edit_core(rule_id, proposed_content, message)

    flash("success" if success else "error")
    return redirect(url_for('rule.detail_rule', rule_id=rule_id))



@rule_blueprint.route("/validate_proposal", methods=['GET'])
def validate_proposal():
    rule_id = request.args.get('ruleId', type=int) # id of the real rule 
    decision = request.args.get('decision', type=str)
    rule_proposal_id = request.args.get('ruleproposalId', type=int) #id of the rule request

    user_id = RuleModel.get_rule_user_id(rule_id)


    if user_id == current_user.id:
        if rule_id and decision and rule_proposal_id:
            # the rule modified
            rule_proposal = RuleModel.get_rule_proposal(rule_proposal_id)
            # the real rule
            rule = RuleModel.get_rule(rule_id)

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

@rule_blueprint.route("/test_yara_python_url", methods=['GET', 'POST'])
@login_required
def test_yara_python_url():
    if request.method == 'POST':
        repo_url = request.form.get('url')

        try:
            # Step 1: Save all the YARA files from the given URL and take the license if it existe
            repo_dir = save_yara_rules_as_is(repo_url)

            # license_from_github = get_license_file_from_github_repo(repo_dir) old version
            # take owner and repo to extract the license
            owner, repo = extract_owner_repo(repo_url)
            license_from_github = get_license_name(owner,repo)
            # print("License:", license_from_github)

            # Step 2: Read and parse all files in the output_rules folder
            all_rules = read_and_parse_all_yara_rules_from_folder(license_from_github,repo_url=repo_url)
            

            # Step 3: Try to add each rule to the database
            imported = 0
            skipped = 0
            for rule_dict in all_rules:
                success = RuleModel.add_rule_core(rule_dict)

                if success:
                    imported += 1
                else:
                    skipped += 1

            flash(f"{imported} YARA rules imported. {skipped} ignored (already exist).", "success")
        except Exception as e:
            flash(f"Failed to import rules: {str(e)}", "danger")

    return redirect(url_for("rule.rules_list"))