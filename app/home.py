from datetime import datetime, timezone
from flask import Flask, Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask import get_flashed_messages
from sqlalchemy import true

from app.db_class import db
from app.db_class.db import Rule, RuleFavoriteUser
from app.favorite.favorite_core import add_favorite

from app.import_github_project.read_github_YARA import clone_or_access_repo, get_yara_files_from_repo, parse_yara_rule
from app.rule.rule_form import EditRuleForm
from app.utils.utils import form_to_dict
from .rule import rule_core as RuleModel
from .favorite import favorite_core as FavoriteModel


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
def delete_rule():
    rule_id = request.args.get('id', 1, int)
    user_id = RuleModel.get_rule_user_id(rule_id)

    if current_user.id == user_id or current_user.is_admin():
        RuleModel.delete_rule_core(rule_id)
        return jsonify({"success": True, "message": "Rule deleted!"})
    
    return jsonify({"success": False, "message": "Access denied"})


@home_blueprint.route("/get_current_user", methods=['GET', 'POST'])
def get_current_user():
    return jsonify({'user': current_user.is_admin()})


@home_blueprint.route("/edit_rule/<int:rule_id>", methods=['GET', 'POST'])
def edit_rule(rule_id):
    rule = RuleModel.get_rule(rule_id)
    user_id = RuleModel.get_rule_user_id(rule_id)

    if current_user.id == user_id or current_user.is_admin():
        form = EditRuleForm()

        # Load licenses
        with open("app/rule/licenses.txt", "r", encoding="utf-8") as f:
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
            rule.last_modif = datetime.now(timezone.utc)

        return render_template("rule/edit_rule.html", form=form, rule=rule)
    else:
        flash("Access denied", "danger")
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
def detail_rule(rule_id):
    rule = RuleModel.get_rule(rule_id)  
    return render_template("rule/detail_rule.html", rule=rule)


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

# @home_blueprint.route("/import_yara")
# @login_required
# def import_yara():
#     if not current_user.is_admin:
#         flash("Access denied", "danger")
#         return redirect(url_for("rule.rule"))

#     parse_yara_rule()
#     flash("YARA rules imported successfully!", "success")
#     return redirect(url_for("rule.rule"))


# @home_blueprint.route("/import_yara_from_url", methods=["POST"])
# @login_required
# def import_yara_from_url():
#     if not current_user.is_admin:
#         flash("Accès refusé", "danger")
#         return redirect(url_for("home.home"))

#     url = request.form.get("github_url")
#     try:
#         added = import_yara_from_github(url)
#         if added == 0:
#             flash("Aucune nouvelle règle YARA importée.", "info")
#         else:
#             flash(f"{added} règle(s) YARA importée(s) avec succès !", "success")
#     except Exception as e:
#         flash(f"Erreur lors de l'import : {e}", "danger")

#     return redirect(url_for("home.home"))





@home_blueprint.route("/import_yara_from_repo", methods=['GET', 'POST'])
@login_required
def import_yara_from_repo():
    if not current_user.is_admin:
        flash("Accès refusé. Admin uniquement.", "danger")
        return redirect(url_for("rule.rule"))
    if request.method == 'POST':
        repo_url = request.form.get('url') 
        local_dir = "Rules_Github/Yara_Project"

    try:
        repo = clone_or_access_repo(repo_url, local_dir)
        yara_files = get_yara_files_from_repo(local_dir)

        imported = 0
        skipped = 0

        for file_path in yara_files:
            rule_dict = parse_yara_rule(file_path)

            rule_dict["version"] = "1.0"
            # rule_dict["author"] = current_user.username if hasattr(current_user, "username") else "unknown"

            success = RuleModel.add_rule_core(rule_dict)
            if success:
                imported += 1
            else:
                skipped += 1

        
        flash(f"{imported} YARA rules imported. {skipped} ignored (existe already).", "success")

    except Exception as e:
        flash(f"fail to import: {str(e)}", "danger")

    return redirect(url_for("home.home"))
