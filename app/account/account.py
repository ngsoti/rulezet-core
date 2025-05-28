from typing import Union
from ..db_class.db import User
from flask import Blueprint, jsonify, render_template, redirect, url_for, request, flash
from .form import LoginForm, EditUserForm, AddNewUserForm
from ..rule import rule_core as RuleModel
from . import account_core as AccountModel
from ..utils.utils import form_to_dict, generate_api_key
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

@account_blueprint.route("/all_users")
@login_required
def user_list() -> render_template:
    """Redirect to the user section"""
    return render_template("admin/user_list.html")

@account_blueprint.route("/detail_user/<int:user_id>")
@login_required
def detail_user(user_id) -> render_template:
    """Redirect to the detail user section"""
    return render_template("account/detail_user.html" , user_id=user_id)

@account_blueprint.route("/get_user")
@login_required
def get_user() -> jsonify:
    """Give the user section"""
    user_id = request.args.get('user_id',type=int)
    if current_user.is_admin():
        my_user = AccountModel.get_user(user_id)
        if my_user:
            return jsonify({"success": True, "user": my_user.to_json()})
        else:
            return jsonify({"success": False, "message": "no user found"})
    else:
        return render_template("access_denied.html")

@account_blueprint.route("/get_user_donne")
@login_required
def get_user_donne() -> jsonify:
    """Return the user activity and metadata."""
    user_id = request.args.get('user_id', type=int)
    
    if current_user.is_admin():
        user_data = AccountModel.get_user_data_full(user_id)
        if user_data:
            return jsonify({"success": True, "donne": user_data})
        else:
            return jsonify({"success": False, "message": "User not found"})
    else:
        return render_template("access_denied.html")

@account_blueprint.route("/promote_remove_admin")
@login_required
def promote_remove_admin() -> jsonify:
    """Return the user activity and metadata."""
    user_id = request.args.get('userId', type=int)
    action = request.args.get('action', type=str)
    
    if current_user.is_admin():
        response = AccountModel.promote_remove_user_admin(user_id, action)
        if response:
            if action == "remove":
                return jsonify({"success": True , "admin": False})
            else:
                return jsonify({"success": True , "admin": True})
        else:
            return jsonify({"success": False})
    else:
        return render_template("access_denied.html")

@account_blueprint.route("/delete_user")
@login_required
def delete_user() -> render_template:
    """Delete an user"""
    user_id = request.args.get('id', 1, type=int)
    if current_user.is_admin():
        delete = AccountModel.delete_user_core(user_id)
        if delete:
            return {"message": "User Deleted",  
                    "success": True}, 200 
        return {"message": "Failed to delete",
                "success": False}, 500
    else:
        return render_template("access_denied.html")

@account_blueprint.route("/get_all_users")
@login_required
def get_all_users() -> Union[render_template, dict]:
    """Get all the users"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get("search", None)
    connected = request.args.get("connected", None) 
    admin = request.args.get("admin", None) 



    #users = AccountModel.get_users_page(page)
    users_filter = AccountModel.get_users_page_filter(page , search , connected, admin)
    total_user = AccountModel.get_count_users()
    if current_user.is_admin():
        if users_filter:
            return {"user": [user.to_json() for user in users_filter], 
                    "total_pages": users_filter.pages, 
                    "total_users": total_user , 
                    "success": True}, 200 
        return {"message": "No User",
                "toast_class": "danger-subtle"}, 404
    else:
        return render_template("access_denied.html")

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
            AccountModel.connected(current_user)
            flash('You are now logged in. Welcome back!', 'success')
            return redirect( "/")
        else:
            flash('Invalid email or password.', 'error')
    return render_template('account/login.html', form=form)

@account_blueprint.route('/logout')
@login_required
def logout() -> redirect:
    "Log out an User"
    AccountModel.disconnected(current_user)
    logout_user()
    
    flash('You have been logged out.', 'info')
    return redirect(url_for('home.home'))

@account_blueprint.route('/register', methods=['GET', 'POST'])
def add_user() -> redirect:
    """Add a new user"""
    form = AddNewUserForm()
    if form.validate_on_submit():
        form_dict = form_to_dict(form)
        form_dict["key"] = generate_api_key()
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

@account_blueprint.route("/acces_denied")
@login_required
def acces_denied() -> render_template:
    """acces_denied page"""
    return render_template("access_denied.html")

############
# Favorite #
############


@account_blueprint.route("/favorite/get_rules_page_favorite",  methods=['GET'])
@login_required
def get_rules_page_favorite() -> jsonify:
    """Rule favorite page"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get("search", None)
    author = request.args.get("author", None)
    sort_by = request.args.get("sort_by", "newest")
    rule_type = request.args.get("rule_type", None) 
    rules = RuleModel.get_rules_page_favorite(page, current_user.id , search,author, sort_by, rule_type)

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


