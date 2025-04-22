import asyncio
from datetime import datetime, timezone
import string
import tempfile
from flask import Flask, Blueprint, Response, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask import get_flashed_messages
import git
from sqlalchemy import true

from app.comment.comment_core import add_comment_core, delete_comment, dislike_comment, get_comment_by_id, get_comments_for_rule, get_latest_comment_for_user_and_rule, like_comment, update_comment
from app.db_class import db
from app.db_class.db import Comment, Rule, RuleFavoriteUser
from app.favorite.favorite_core import add_favorite

from app.import_github_project.read_github_YARA import clone_or_access_repo, get_yara_files_from_repo, parse_yara_rule

from app.import_github_project.yara_python import clone_or_access_repo_v1, extract_yara_rules
from app.rule.rule_form import EditRuleForm
from app.utils.utils import form_to_dict
from .rule import rule_core as RuleModel
from .favorite import favorite_core as FavoriteModel
from .comment import comment_core as CommentModel



home_blueprint = Blueprint(
    'home',
    __name__,
    template_folder='templates',
    static_folder='static'
)


@home_blueprint.route("/")
def home():
    # list all the rules
    get_flashed_messages()
    return render_template("home.html")


@home_blueprint.route("/get_rules_page", methods=['GET'])
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


@home_blueprint.route("/delete_rule", methods=['GET', 'POST'])
@login_required
def delete_rule():
    rule_id = request.args.get('id', 1, int)
    user_id = RuleModel.get_rule_user_id(rule_id)

    if current_user.id == user_id or current_user.is_admin():
        RuleModel.delete_rule_core(rule_id)
        return jsonify({"success": True, "message": "Rule deleted!"})
    
    return render_template("access_denied.html")


@home_blueprint.route("/get_current_user", methods=['GET', 'POST'])
@login_required
def get_current_user():
    return jsonify({'user': current_user.is_admin()})


@home_blueprint.route("/detail_rule/get_current_user", methods=['GET', 'POST'])
@login_required
def get_current_user_from_detail():
    return jsonify({'user': current_user.is_admin()})



@home_blueprint.route("/edit_rule/<int:rule_id>", methods=['GET', 'POST'])
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
            return redirect("/")
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
    return redirect("/")




@home_blueprint.route('/vote_rule', methods=['GET','POST'])
@login_required
def vote_rule():
    rule_id = request.args.get('id', 1 , int)
    vote_type = request.args.get('vote_type', 2 , str)
    rule = Rule.query.get(rule_id)
    if rule:
        if vote_type == 'up':
            RuleModel.increment_up(rule_id)
        elif vote_type == 'down':
            RuleModel.decrement_up(rule_id)

        return jsonify({
            'vote_up': rule.vote_up,
            'vote_down': rule.vote_down
        })

    return jsonify({"message": "Rule not found"}), 404




@home_blueprint.route("/detail_rule/<int:rule_id>", methods=['GET'])
@login_required
def detail_rule(rule_id):
    rule = RuleModel.get_rule(rule_id)
    return render_template("rule/detail_rule.html", rule=rule)


@home_blueprint.route("/detail_rule/get_comments_page", methods=['GET'])
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




@home_blueprint.route("/comment_add", methods=["POST", "GET"])
@login_required
def add_comment():
    new_content = request.args.get('new_content', '', type=str)
    rule_id = request.args.get('rule_id', 1, type=int)

    success, message = add_comment_core(rule_id, new_content)
    flash(message, "success" if success else "danger")
    new_comment = get_latest_comment_for_user_and_rule(current_user.id, rule_id)
    return {
        "comment": {
            "id": new_comment.id,
            "content": new_comment.content,
            "user_name": new_comment.user_name,  
            "user_id": new_comment.user.id,
            "created_at": new_comment.created_at.strftime("%Y-%m-%d %H:%M")
        }
    }


@home_blueprint.route("/edit_comment", methods=["POST", "GET"])
@login_required
def edit_comment():
    comment_id = request.args.get('commentID', 1, type=int)
    new_content = request.args.get('newContent', '', type=str)

    comment = get_comment_by_id(comment_id)
    if  comment.user_id == current_user.id or current_user.is_admin():
        update_content = update_comment(comment_id, new_content)
        flash("Comment updated successfully.", "success")
        return jsonify({"updatedComment": update_content.to_json()})
    else:
        print("aie")
        return {"message": "No Comments"}




@home_blueprint.route("/comment_delete/<int:comment_id>", methods=["POST", "GET"])
@login_required
def delete_comment_route(comment_id):
    comment = get_comment_by_id(comment_id)
    if  comment.user_id == current_user.id or current_user.is_admin():
        rule_id = comment.rule_id
        delete_comment(comment_id)
        flash("Comment deleted.", "success")
        return redirect(url_for("home.detail_rule", rule_id=rule_id))
    flash("Unauthorized action.", "danger")
    return redirect(url_for("home.home"))

    







@home_blueprint.route('/favorite/<int:rule_id>', methods=['GET'])
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

    return redirect(url_for('account.favorite')) 

from flask_login import login_required, current_user








@home_blueprint.route("/download/<int:rule_id>", methods=['GET', 'POST'])
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








@home_blueprint.route("/import_yara_from_repo", methods=['GET', 'POST'])
@login_required
def import_yara_from_repo():
    if not current_user.is_admin:
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("rule.rule"))
    
    if request.method == 'POST':
        repo_url = request.form.get('url')
        # local_dir = "Rules_Github/Yara_Project"
        
        try:
            # Clone or access the GitHub repository
            repo_dir = clone_or_access_repo(repo_url)

            # Retrieve all .yar, .yara, and .rule files
            yara_files = get_yara_files_from_repo(repo_dir)

            imported = 0
            skipped = 0

            # Import YARA rules
            for file_path in yara_files:
                # Parse the YARA rule and retrieve data (including GitHub URL)
                rule_dict = parse_yara_rule(file_path, repo_dir=repo_dir, repo_url=repo_url)

                # Add version and other data if necessary
                rule_dict["version"] = "1.0"

                # Attempt to add the rule to the database
                success = RuleModel.add_rule_core(rule_dict)
                if success:
                    imported += 1
                else:
                    skipped += 1

            # Return a message indicating how many rules were imported or skipped
            flash(f"{imported} YARA rules imported. {skipped} ignored (already exist).", "success")

        except Exception as e:
            # In case of an error, show the error message
            flash(f"Failed to import: {str(e)}", "danger")

    return redirect(url_for("home.home"))


# @home_blueprint.route("/test_yara_python", methods=['GET', 'POST'])
# @login_required
# def test_yara_python():
#     # Appel de la méthode avec le fichier YARA
#     fichier_yara = 'app/test.yar'
#     extract_yara_rules(fichier_yara)
#     return redirect(url_for("home.home"))

@home_blueprint.route("/test_yara_python", methods=['GET', 'POST'])
@login_required
def test_yara_python():
    
    # Path to the YARA file
    yara_file = 'app/test.yar'
    
    

    rules_info = extract_yara_rules(yara_file)

    if not rules_info:
        return redirect(url_for("home.home", message="No valid YARA rules found"))

    imported = 0
    skipped = 0
    for rule_dict in rules_info:

        success = RuleModel.add_rule_core(rule_dict)

        if success:
            imported += 1
        else:
            skipped += 1
    flash(f"{imported} YARA rules imported. {skipped} ignored (already exist).", "success")
    return redirect(url_for("home.home"))




@home_blueprint.route("/test_yara_python_url", methods=['GET', 'POST'])
@login_required
def test_yara_python_url():
    if request.method == 'POST':
        repo_url = request.form.get('url')

        try:
            # tmp_dir = tempfile.mkdtemp()
            tmp_dir = "app/github_depot"
            git.Repo.clone_from(repo_url, tmp_dir)
            # tmp_dir = clone_or_access_repo_v1(repo_url)
            

            yara_files = get_yara_files_from_repo(tmp_dir)

            for file_path in yara_files:
                extract_yara_rules(file_path)

        except Exception as e:
            flash(f"Failed to import: {str(e)}", "danger")

    return redirect(url_for("home.home"))



# @home_blueprint.route("/test_yara_python_url", methods=['GET', 'POST'])
# @login_required
# def test_yara_python_url():
#     if request.method == 'POST':
#         repo_url = request.form.get('url')

#         try:
#             tmp_dir = tempfile.mkdtemp()
#             git.Repo.clone_from(repo_url, tmp_dir)

#             yara_files = get_yara_files_from_repo(tmp_dir)

#             imported = 0
#             skipped = 0
#             all_rules = []

#             for file_path in yara_files:
#                 print(file_path)
#                 rules_info = extract_yara_rules(file_path)
#                 all_rules.append(rules_info)

#             for rules_dict in all_rules:
#                 print(rules_dict)
#                 success = RuleModel.add_rule_core(rules_dict)
#                 print("je suis mort")
#                 if success:
#                     imported += 1
#                 else:
#                     skipped += 1

#             flash(f"{imported} YARA rules imported. {skipped} ignored (already exist).", "success")
#         except Exception as e:
#             flash(f"Failed to import: {str(e)}", "danger")

#     return redirect(url_for("home.home"))



    