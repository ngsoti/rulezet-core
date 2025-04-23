from sqlalchemy import true
from app.favorite import favorite_core as FavoriteModel
from app.favorite.favorite_core import remove_favorite
from ..db_class.db import RuleFavoriteUser, User
from flask import Blueprint, jsonify, render_template, redirect, url_for, request, flash
from .form import LoginForm, EditUserForm, AddNewUserForm
from ..rule import rule_core as RuleModel
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user,
)
from . import account_core as AccountModel
from ..favorite import favorite_core as FavoriteModel
from ..utils.utils import form_to_dict

account_blueprint = Blueprint(
    'account',
    __name__,
    template_folder='templates',
    static_folder='static'
)



@account_blueprint.route("/")
@login_required
def index():
    return render_template("account/account_index.html", user=current_user)


@account_blueprint.route("/edit", methods=['GET', 'POST'])
@login_required
def edit_user():
    """Edit the user"""
    form = EditUserForm()

    if form.validate_on_submit():
        form_dict = form_to_dict(form)
        AccountModel.edit_user_core(form_dict, current_user.id)
        return redirect("/account")
    else:
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.email.data = current_user.email

    return render_template("account/edit_user.html", form=form)


@account_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    """Log in an existing user."""
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.password_hash is not None and \
                user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            flash('You are now logged in. Welcome back!', 'success')
            return redirect( "/")
        else:
            flash('Invalid email or password.', 'error')
    return render_template('account/login.html', form=form)


@account_blueprint.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home.home'))




@account_blueprint.route('/register', methods=['GET', 'POST'])
def add_user():
    """Add a new user"""
    form = AddNewUserForm()
    if form.validate_on_submit():
        form_dict = form_to_dict(form)
        AccountModel.add_user_core(form_dict)
        flash('You are now register. You can connect !', 'success')
    return render_template("account/register_user.html", form=form) 


@account_blueprint.route('/favorite', methods=['GET'])
@login_required
def favorite():
    """favorite page"""
    # rules = FavoriteModel.get_all_user_favorites_with_rules(current_user.id)
    # rules_list = [r.to_json() for r in rules]
    return render_template("account/favorite_user.html")

@account_blueprint.route("/profil")
@login_required
def profil():
    return render_template("account/account_index.html", user=current_user)


# @account_blueprint.route('/favorite/remove_favorite', methods=['POST'])
# @login_required
# def remove_favorite_user():
#     rule_id = request.args.get('id', 1 , int)
#     a = remove_favorite(current_user.id, rule_id)
#     if a == true:
#         flash('The rule has been removed from your favorites.', 'success')
#     else:
#         flash('This rule is not in your favorites.', 'warning')
    
#     return redirect(url_for('account/favorite_user.html'))



@account_blueprint.route("/favorite/get_rules_page_favorite",  methods=['GET','POST'])
@login_required
def get_rules_page_favorite():
    page = request.args.get('page', 1, type=int)
    id_user = current_user.id
    rules = RuleModel.get_rules_page_favorite(page, id_user)
    # total_rules = RuleModel.get_total_rules_favorites_count()
    if rules:
        rules_list = list()
        for rule in rules:
            u = rule.to_json()
            rules_list.append(u)

        return {"rule": rules_list, "total_pages": rules.pages}
    
    return {"message": "No Rule"}, 404


@account_blueprint.route("/favorite/delete_rule",  methods=['GET','POST'])
@login_required
def remove_rule_favorite():
    rule_id = request.args.get('id', 1, type=int)
    user_id = current_user.id
    if current_user.id == user_id or current_user.is_admin():
        rep = remove_favorite(user_id, rule_id)
        if rep:
            return jsonify({"success": True, "message": "Rule deleted!"})

    return jsonify({"success": False, "message": "Access denied"}), 403

    


@account_blueprint.route("/favorite/search_rules", methods=['GET','POST'])
@login_required
def search_rules():
    query = request.args.get("query", "").strip().lower()
    if not query:
        return jsonify({"rules": []})

    results = FavoriteModel.search_rules_favorite(current_user.id,query)  
    return jsonify({"rules": [r.to_json() for r in results]})
