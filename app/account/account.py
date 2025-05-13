from ..db_class.db import User
from flask import Blueprint, jsonify, render_template, redirect, url_for, request, flash
from .form import LoginForm, EditUserForm, AddNewUserForm
from ..rule import rule_core as RuleModel
from . import account_core as AccountModel
from ..utils.utils import form_to_dict
from flask_login import current_user, login_required, login_user, logout_user

account_blueprint = Blueprint(
    'account',
    __name__,
    template_folder='templates',
    static_folder='static'
)



###############
# User action #
###############

@account_blueprint.route("/")
@login_required
def index() -> render_template:
    """Redirect to the user section"""
    return render_template("account/account_index.html", user=current_user)

@account_blueprint.route("/edit", methods=['GET', "POST"])
@login_required
def edit_user() -> redirect:
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
def login() -> redirect:
    """Log in an existing user."""
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.password_hash is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            flash('You are now logged in. Welcome back!', 'success')
            return redirect( "/")
        else:
            flash('Invalid email or password.', 'error')
    return render_template('account/login.html', form=form)

@account_blueprint.route('/logout')
@login_required
def logout() -> redirect:
    "Log out an User"
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home.home'))

@account_blueprint.route('/register', methods=['GET', 'POST'])
def add_user() -> redirect:
    """Add a new user"""
    form = AddNewUserForm()
    if form.validate_on_submit():
        form_dict = form_to_dict(form)
        AccountModel.add_user_core(form_dict)
        flash('You are now register. You can connect !', 'success')
        return redirect("/account/login")
    return render_template("account/register_user.html", form=form) 

@account_blueprint.route('/favorite')
@login_required
def favorite() -> render_template:
    """Favorite page"""
    return render_template("account/favorite_user.html")

@account_blueprint.route("/profil")
@login_required
def profil() -> render_template:
    """Profil page"""
    return render_template("account/account_index.html", user=current_user)


############
# Favorite #
############


@account_blueprint.route("/favorite/get_rules_page_favorite",  methods=['GET'])
@login_required
def get_rules_page_favorite() -> jsonify:
    """Rule favorite page"""
    page = request.args.get('page', 1, type=int)
    rules = RuleModel.get_rules_page_favorite(page, current_user.id)

    if rules:
        return {"rule": [rule.to_json() for rule in rules], "total_pages": rules.pages}
    return {"message": "No Rule"}, 404

@account_blueprint.route("/favorite/delete_rule",  methods=['GET','POST'])
@login_required
def remove_rule_favorite() -> jsonify:
    """Remove a rule from favorite"""
    rule_id = request.args.get('id', 1, type=int)
    rep = AccountModel.remove_favorite(current_user.id, rule_id)
    if rep:
        return jsonify({"success": True, "message": "Rule deleted!"})
    return jsonify({"success": False, "message": "Access denied"}), 403


