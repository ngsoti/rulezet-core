from sqlalchemy import true
from app.favorite import favorite_core
from app.favorite.favorite_core import get_all_user_favorites_with_rules, get_user_favorites, remove_favorite
from ..db_class.db import RuleFavoriteUser, User
from flask import Blueprint, render_template, redirect, url_for, request, flash
from .form import LoginForm, EditUserForm, AddNewUserForm
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
    rules = FavoriteModel.get_all_user_favorites_with_rules(current_user.id)
    rules_list = [r.to_json() for r in rules]
    return render_template("account/favorite_user.html", rules_list=rules_list)

@account_blueprint.route("/profil")
@login_required
def profil():
    return render_template("account/account_index.html", user=current_user)


@account_blueprint.route('/favorite/remove_favorite', methods=['POST'])
@login_required
def remove_favorite_user():
    rule_id = request.args.get('id', 1 , int)
    a = remove_favorite(current_user.id, rule_id)
    if a == true:
        flash('The rule has been removed from your favorites.', 'success')
    else:
        flash('This rule is not in your favorites.', 'warning')
    
    return redirect(url_for('account/favorite_user.html'))


