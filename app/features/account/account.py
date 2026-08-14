from typing import Union
import datetime
from ...core.db_class.db import User, RegisteredInstance, InstanceConfig
from ... import db
from flask import Blueprint, jsonify, render_template, redirect, url_for, request, flash
from .form import LoginForm, EditUserForm, AddNewUserForm, ForgotPasswordForm, ResetPasswordForm
from ..rule import rule_core as RuleModel
from . import account_core as AccountModel
from ..bundle import bundle_core as BundleModel
from ...core.utils.utils import form_to_dict, generate_api_key, safe_referrer
from ...core.utils.activity_log import log_activity
from flask_login import current_user, login_required, login_user, logout_user
from datetime import datetime, timedelta, timezone
from collections import Counter
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
    from app.features.roles.roles_core import get_user_roles
    return render_template("account/account_index.html", user=current_user,
                            user_roles=get_user_roles(current_user.id))

@account_blueprint.route("/admin/instances")
@login_required
def admin_instances():
    import uuid as _uuid_mod
    from flask import current_app, abort
    from sqlalchemy import func
    from app import db
    from app.core.db_class.db import RemotePullLog
    if not current_user.is_admin() or not current_app.config.get('IS_OFFICIAL_INSTANCE'):
        abort(404)
    instances = RegisteredInstance.query.order_by(RegisteredInstance.last_seen.desc()).all()
    own_cfg   = InstanceConfig.query.first()

    # Pull counts per instance UUID (one query)
    pull_counts = {
        row.instance_uuid: row.cnt
        for row in db.session.query(
            RemotePullLog.instance_uuid,
            func.count(RemotePullLog.id).label('cnt'),
        ).group_by(RemotePullLog.instance_uuid).all()
        if row.instance_uuid
    }
    # Last pull date per instance UUID
    last_pulls = {
        row.instance_uuid: row.last
        for row in db.session.query(
            RemotePullLog.instance_uuid,
            func.max(RemotePullLog.created_at).label('last'),
        ).group_by(RemotePullLog.instance_uuid).all()
        if row.instance_uuid
    }

    # Same GitHub-release cache the update banner uses (see
    # _start_update_checker in app/__init__.py) — reused here instead of a
    # second live GitHub call, so this list can flag a registered instance
    # as outdated too.
    latest_release = current_app.config.get('LATEST_RELEASE') or {}
    latest_version = latest_release.get('version')

    instances_data = []
    for inst in instances:
        d = inst.to_json()
        d['pull_count'] = pull_counts.get(inst.uuid, 0)
        last = last_pulls.get(inst.uuid)
        d['last_pull'] = last.strftime('%Y-%m-%d %H:%M') if last else None
        d['is_outdated'] = bool(
            latest_version and inst.version and inst.version.lstrip('v') != latest_version
        )
        instances_data.append(d)

    return render_template(
        "admin/instances.html",
        instances=instances_data,
        own_uuid=own_cfg.uuid if own_cfg else None,
        latest_version=latest_version,
    )


@account_blueprint.route("/admin/instances/<string:instance_uuid>/pulls")
@login_required
def admin_instance_pulls(instance_uuid):
    from flask import current_app, abort, jsonify
    from app.core.db_class.db import RemotePullLog
    if not current_user.is_admin() or not current_app.config.get('IS_OFFICIAL_INSTANCE'):
        abort(404)
    logs = (RemotePullLog.query
            .filter_by(instance_uuid=instance_uuid)
            .order_by(RemotePullLog.created_at.desc())
            .limit(100)
            .all())
    return jsonify([l.to_json() for l in logs])


@account_blueprint.route("/admin/all_users")
@login_required
def user_list() -> render_template:
    """Redirect to the user section"""
    return render_template("admin/user_list.html")

@account_blueprint.route("/detail_user/<int:user_id>")
@login_required
def detail_user(user_id) -> render_template:
    """Redirect to the detail user section"""
    user = AccountModel.get_user(user_id)
    if not user:
        flash("User not found.", "error")
        # redirect to the previous page
        return redirect(safe_referrer())
    is_owner_or_admin = current_user.id == user.id or current_user.is_admin()
    from app.features.roles.roles_core import get_user_roles
    user_dict = user.to_json(include_private=is_owner_or_admin)
    user_dict['roles'] = get_user_roles(user.id)
    return render_template("account/detail_user.html" , user=user_dict)

@account_blueprint.route("/user_mini/<int:user_id>")
def user_mini(user_id):
    """Lightweight public user card — used by UserChip tooltip."""
    user = AccountModel.get_user(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404
    rules_count = RuleModel._active().filter_by(user_id=user.id).count()
    followers_count = user.followers.count() if hasattr(user, 'followers') else 0
    from app.features.roles.roles_core import get_user_roles
    # This endpoint has no @login_required — it's hit by anyone hovering a
    # UserChip. is_admin must stay just as gated here as it is on
    # detail_user/get_user, or it re-opens the admin-status-enumeration
    # issue those were fixed for: only the profile owner or an admin sees it.
    viewer_may_see_admin = current_user.is_authenticated and (current_user.id == user.id or current_user.is_admin())
    return jsonify({
        "id":        user.id,
        "username":  user.get_username(),
        "avatar":    user.get_avatar_url(),
        "bio":       (user.bio or "")[:120] if user.bio else None,
        "location":  user.location,
        "created_at": user.created_at.strftime("%b %Y") if user.created_at else None,
        "rules_count": rules_count,
        "followers": followers_count,
        "roles":     get_user_roles(user.id),
        "is_admin":  user.is_admin() if viewer_may_see_admin else False,
    })


@account_blueprint.route("/get_user")
@login_required
def get_user() -> jsonify:
    """Give the user section — full record (incl. email/admin status) is only
    ever returned for yourself or, if you're an admin, anyone."""
    user_id = request.args.get('user_id', type=int)
    if user_id != current_user.id and not current_user.is_admin():
        return jsonify({"success": False, "message": "Forbidden"}), 403
    my_user = AccountModel.get_user(user_id)
    if my_user:
        return jsonify({"success": True, "user": my_user.to_json()})
    else:
        return jsonify({"success": False, "message": "no user found"})

@account_blueprint.route("/get_user_donne")
@login_required
def get_user_donne() -> jsonify:
    """Return the user activity and metadata — self or admin only, same
    reasoning as get_user above (this also exposes email/admin status)."""
    user_id = request.args.get('user_id', type=int)
    if user_id != current_user.id and not current_user.is_admin():
        return jsonify({"success": False, "message": "Forbidden"}), 403
    user_data = AccountModel.get_user_data_full(user_id)
    if user_data:
        return jsonify({"success": True, "donne": user_data})
    else:
        return jsonify({"success": False, "message": "User not found"})


@account_blueprint.route("/promote_remove_admin", methods=['POST'])
@login_required
def promote_remove_admin() -> jsonify:
    """Return the user activity and metadata."""
    data    = request.get_json() or {}
    user_id = int(data.get('userId', 0)) or None
    action  = str(data.get('action', ''))

    if current_user.is_admin():
        response = AccountModel.promote_remove_user_admin(user_id, action)
        if response:
            if action == "remove":
                log_activity("admin.demote_user", f"Removed admin rights from user id={user_id}",
                             target_type="user", target_id=user_id)
                return jsonify({"success": True , "admin": False})
            else:
                log_activity("admin.promote_user", f"Granted admin rights to user id={user_id}",
                             target_type="user", target_id=user_id)
                return jsonify({"success": True , "admin": True})
        else:
            return jsonify({"success": False})
    else:
        return render_template("access_denied.html")

@account_blueprint.route("/delete_user", methods=['POST'])
@login_required
def delete_user() -> render_template:
    """Delete an user"""
    data    = request.get_json() or {}
    user_id = int(data.get('id', 0)) or None
    if current_user.is_admin():
        delete = AccountModel.delete_user_core(user_id)
        if delete:
            log_activity("admin.delete_user", f"Deleted user id={user_id}",
                         target_type="user", target_id=user_id)
            return {"message": "User Deleted",
                    "success": True,
                    "toast_class" : "success-subtle"}, 200
        return {"message": "Failed to delete",
                "success": False,
                "toast_class" : "danger-subtle"}, 500
    else:
        return render_template("access_denied.html")

@account_blueprint.route("/users_data_table")
@login_required
def users_data_table():
    """Paginated user list for the admin UserList component."""
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 403

    from sqlalchemy import asc, desc, or_
    from app.core.db_class.db import Rule

    page     = request.args.get('page',     1,        type=int)
    per_page = min(request.args.get('per_page', 20,   type=int), 100)
    search   = (request.args.get('search',  '')  or '').strip()
    f_admin  = request.args.get('admin',    '')
    f_conn   = request.args.get('connected','')
    f_verif  = request.args.get('verified', '')
    sort_by  = request.args.get('sort',     'created_at')
    sort_dir = request.args.get('dir',      'desc')

    query = User.query

    if search:
        like = f'%{search}%'
        query = query.filter(or_(
            User.first_name.ilike(like), User.last_name.ilike(like),
            User.email.ilike(like),      User.username.ilike(like),
        ))

    if f_admin == 'true':    query = query.filter(User.admin.is_(True))
    elif f_admin == 'false': query = query.filter(User.admin.is_(False))

    if f_conn == 'true':    query = query.filter(User.is_connected.is_(True))
    elif f_conn == 'false': query = query.filter(User.is_connected.is_(False))

    if f_verif == 'true':    query = query.filter(User.is_verified.is_(True))
    elif f_verif == 'false': query = query.filter(User.is_verified.is_(False))

    _sort_map = {
        'created_at': User.created_at, 'last_seen': User.last_seen,
        'first_name': User.first_name,  'id': User.id,
    }
    sort_col = _sort_map.get(sort_by, User.created_at)
    query = query.order_by(desc(sort_col) if sort_dir == 'desc' else asc(sort_col))

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    from sqlalchemy import func
    from app.core.db_class.db import Bundle
    from app import db

    user_ids = [u.id for u in pagination.items]

    rule_counts = dict(
        db.session.query(Rule.user_id, func.count(Rule.id))
        .filter(Rule.user_id.in_(user_ids), Rule.is_deleted == False)
        .group_by(Rule.user_id)
        .all()
    ) if user_ids else {}

    bundle_counts = dict(
        db.session.query(Bundle.user_id, func.count(Bundle.id))
        .filter(Bundle.user_id.in_(user_ids))
        .group_by(Bundle.user_id)
        .all()
    ) if user_ids else {}

    from app.core.db_class.db import UserRole, Role
    roles_by_user = {}
    if user_ids:
        role_rows = (
            db.session.query(UserRole.user_id, Role.id, Role.name)
            .join(Role, Role.id == UserRole.role_id)
            .filter(UserRole.user_id.in_(user_ids))
            .all()
        )
        for uid, rid, rname in role_rows:
            roles_by_user.setdefault(uid, []).append({'id': rid, 'name': rname})

    items = []
    for u in pagination.items:
        j = u.to_json()
        j['rule_count']   = rule_counts.get(u.id, 0)
        j['bundle_count'] = bundle_counts.get(u.id, 0)
        j['roles']        = roles_by_user.get(u.id, [])
        items.append(j)

    return jsonify({'items': items, 'total': pagination.total, 'total_pages': pagination.pages})


@account_blueprint.route("/get_all_users")
@login_required
def get_all_users() -> Union[render_template, dict]:
    """Get all the users"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get("search", None)
    connected = request.args.get("connected", None)
    admin = request.args.get("admin", None)

    users_filter = AccountModel.get_users_page_filter(page , search , connected, admin)

    if current_user.is_admin():
        if users_filter:
            return {"user": [user.to_json() for user in users_filter],
                    "total_pages": users_filter.pages,
                    "total_users": users_filter.total ,
                    "success": True}, 200
        return {"message": "No User",
                "toast_class": "danger-subtle"}, 404
    else:
        return render_template("access_denied.html")

@account_blueprint.before_app_request
def _update_last_seen():
    if current_user.is_authenticated:
        AccountModel.update_last_seen(current_user.id)



@account_blueprint.route("/edit", methods=['GET', 'POST'])
@login_required
def edit_user():
    """Edit the user"""
    form = EditUserForm()
    if form.validate_on_submit():
        form_dict     = form_to_dict(form)
        avatar_file   = form.profile_picture.data
        remove_avatar = request.form.get("remove_avatar") == "1"
        success, pending_email = AccountModel.edit_user_core(
            form_dict,
            current_user.id,
            avatar_file=avatar_file,
            remove_avatar=remove_avatar
        )
        if success:
            log_activity("user.edit_profile", "Updated profile",
                         target_type="user", target_id=current_user.id)
            if pending_email:
                email_ok = AccountModel.request_email_change_core(current_user.id, pending_email)
                if email_ok:
                    flash(
                        f'Profile updated. A confirmation link was sent to {pending_email}. '
                        'Your email address will be updated once you confirm it.',
                        'info'
                    )
                else:
                    flash(
                        f'Profile updated, but the email address {pending_email} is already in use by another account.',
                        'warning'
                    )
            else:
                flash('Profile updated successfully!', 'success')
            return redirect("/account")
    else:
        form.first_name.data  = current_user.first_name
        form.last_name.data   = current_user.last_name
        form.email.data       = current_user.email
        form.username.data    = current_user.username
        form.bio.data         = current_user.bio
        form.location.data    = current_user.location
        form.website_url.data = current_user.website_url
        form.github_url.data  = current_user.github_url
        form.twitter_url.data = current_user.twitter_url

    return render_template("account/edit_user.html", form=form)


@account_blueprint.route('/confirm-email-change/<token>')
@login_required
def confirm_email_change(token):
    """Apply a pending email change after the user clicks the confirmation link."""
    success, message = AccountModel.confirm_email_change_core(token)
    if success:
        log_activity("user.email_change", "Changed email address",
                     target_type="user", target_id=current_user.id)
        flash(message, 'success')
    else:
        flash(message, 'danger')
    return redirect('/account')

 



@account_blueprint.route('/login', methods=['GET', 'POST'])
def login() -> redirect:
    """Log in an existing user."""
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.password_hash is not None and user.verify_password(form.password.data):
            if not user.is_verified:
                flash("Please verify your email first.", "warning")
                return redirect(f"/account/verify/{user.id}")
            login_user(user, form.remember_me.data)
            AccountModel.connected(current_user)
            log_activity("user.login", f"User '{user.get_username()}' logged in",
                         target_type="user", target_id=user.id)
            flash('You are now logged in. Welcome back!', 'success')
            return redirect( "/")
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('account/login.html', form=form)

@account_blueprint.route('/logout')
@login_required
def logout() -> redirect:
    "Log out an User"
    log_activity("user.logout", f"User '{current_user.get_username()}' logged out",
                 target_type="user", target_id=current_user.id)
    AccountModel.disconnected(current_user)
    logout_user()

    flash('You have been logged out.', 'info')
    # return redirect(url_for('home.home'))
    # we dont want ti go back to home or the connection page we juste want to stay in the page where I am 
    return redirect(url_for('home.home'))

@account_blueprint.route('/register', methods=['GET', 'POST'])
def add_user() -> redirect:
    """Add a new user"""
    form = AddNewUserForm()
    if form.validate_on_submit():
        form_dict = form_to_dict(form)
        form_dict["key"] = generate_api_key()
        user, success = AccountModel.add_user_core(form_dict)

        if not success:
            flash('Error during the registration. Please try again !', 'error')
            return redirect("/account/register")
        if not user:
            flash('Error during the registration. Please try again !', 'error')
            return redirect("/account/register")

        log_activity("user.register", f"New user registered: '{user.get_username()}'",
                     target_type="user", target_id=user.id)
        flash('Registration successful. Please check your email for verification.', 'success')
        return redirect(f"/account/verify/{user.id}")
    return render_template("account/register_user.html", form=form)

@account_blueprint.route('/favorite')
@login_required
def favorite() -> render_template:
    """Favorite page"""
    return render_template("account/favorite_user.html")

@account_blueprint.route("/profil")
@login_required
def profil() -> render_template:
    """Profile page"""
    from app.features.roles.roles_core import get_user_roles
    return render_template("account/account_index.html", user=current_user,
                            user_roles=get_user_roles(current_user.id))

@account_blueprint.route("/acces_denied")
@login_required
def acces_denied() -> render_template:
    """acces_denied page"""
    return render_template("access_denied.html")

#############
#   Email   #
#############

@account_blueprint.route('/verify/<int:user_id>', methods=['GET', 'POST'])
def verify(user_id):
    user = AccountModel.get_user(user_id)
    if not user:
        flash("User not found.", "error")
        return redirect("/account/login")

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Never delete an already-verified account just because this stale
    # timestamp is in the past — verification_expiration only means anything
    # for an account that's still awaiting its first verification. Without
    # this guard, anyone could delete an arbitrary verified user by hitting
    # this route once their (now-irrelevant) original code had expired.
    if not user.is_verified and user.verification_expiration and now > user.verification_expiration:
        # delete user
        AccountModel.delete_user_core(user_id)
        flash("Code expired. Your account has been deleted. Please register again.", "error")
        return redirect("/account/register")

    if request.method == 'POST':
        input_code = request.form.get('verification_code')
        if not input_code:
            flash("Please enter a code.", "error")
            return redirect(f"/account/verify/{user_id}")
        if input_code == user.verification_code:
            success = AccountModel.verify_user_core(user_id)
            if not success:
                flash("Failed to verify account.", "error")
                return redirect("/account/login")
            log_activity(
                "user.verified",
                f"User '{user.get_username()}' verified their account",
                target_type="user", target_id=user_id,
                is_public=False,
            )
            flash("Account verified!", "success")
            login_user(user, remember=True)
            return redirect("/")
        else:
            flash("Invalid code.", "error")
            
    return render_template("account/verify.html", user_id=user_id)

# /resend-verification-code

@account_blueprint.route('/resend-verification-code/<int:user_id>', methods=['POST'])
def resend_verification_code(user_id):
    user = AccountModel.get_user(user_id)
    if not user:
        flash("User not found.", "error")
        return redirect("/account/login")

    # Registration logs the user in immediately, pre-verification, so a
    # logged-in caller here should only ever be resending their own code —
    # otherwise they could reset an arbitrary unverified account's code by
    # editing this URL. An anonymous caller (no session) is left alone since
    # that's how a stale, pre-login "verify" page can legitimately reach this.
    if current_user.is_authenticated and current_user.id != user_id and not current_user.is_admin():
        flash("You can only resend a code for your own account.", "error")
        return redirect("/account/login")

    success = AccountModel.resend_verification_code_core(user_id)
    if not success:
        flash("Failed to resend verification code.", "error")
        return redirect(f"/account/verify/{user_id}")
    flash("Verification code resent.", "success")
    return render_template("account/verify.html", user_id=user_id)


@account_blueprint.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect('/')
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        AccountModel.request_password_reset_core(form.email.data)
        flash('If this email is registered, a reset link has been sent. Check your inbox.', 'info')
        return redirect('/account/forgot-password')
    return render_template('account/forgot_password.html', form=form)


@account_blueprint.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect('/')
    form = ResetPasswordForm()
    if form.validate_on_submit():
        success, message = AccountModel.reset_password_core(token, form.password.data)
        if success:
            flash('Password reset successfully. You can now log in.', 'success')
            return redirect('/account/login')
        flash(message, 'danger')
        return redirect(f'/account/reset-password/{token}')
    return render_template('account/reset_password.html', form=form, token=token)


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
        log_activity(
            "rule.unfavorite",
            f"Removed rule id={rule_id} from favorites",
            target_type="rule", target_id=rule_id,
            is_public=False,
        )
        return jsonify({"success": True, "message": "Rule deleted!"})
    return jsonify({"success": False, "message": "Access denied"}), 403


#####################
#    contributor    #
#####################
@account_blueprint.route("/contributor")
@login_required
def contributor() -> str: 
    """Contributor page"""
    return render_template("account/contributor.html")


_VALID_LEADERBOARD_SORTS = ['total_points', 'suggestions_accepted', 'rules_owned',
                            'rules_popular_score', 'last_contribution_date']
_VALID_ACTIVE_SINCE = ['week', 'month', 'year']


@account_blueprint.route('/leaderboard/global', methods=['GET'])
def get_global_leaderboard():
    """Recup the global leaderboard — paginated, sortable, searchable by name"""

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    sort_by = request.args.get('sort_by', 'total_points', type=str)
    direction = request.args.get('dir', 'desc', type=str)
    search = request.args.get('search', None, type=str)
    active_since = request.args.get('active_since', None, type=str)

    if sort_by not in _VALID_LEADERBOARD_SORTS:
        return jsonify({"error": "Invalid sort_by parameter"}), 400
    if active_since and active_since not in _VALID_ACTIVE_SINCE:
        return jsonify({"error": "Invalid active_since parameter"}), 400

    pagination_data = AccountModel.get_leaderboard_paginated(
        page=page, per_page=per_page, sort_by=sort_by, direction=direction,
        search=search, active_since=active_since,
    )

    return jsonify(pagination_data)


@account_blueprint.route('/leaderboard/category', methods=['GET'])
def get_category_leaderboard():
    """Recup the category leaderboard — same generic paginated/sortable/searchable
    leaderboard as /leaderboard/global, just with a different default sort column."""

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 5, type=int)
    sort_by = request.args.get('sort_by', 'suggestions_accepted', type=str)
    direction = request.args.get('dir', 'desc', type=str)
    search = request.args.get('search', None, type=str)
    active_since = request.args.get('active_since', None, type=str)

    if sort_by not in _VALID_LEADERBOARD_SORTS:
        return jsonify({"error": "Invalid sort_by parameter"}), 400
    if active_since and active_since not in _VALID_ACTIVE_SINCE:
        return jsonify({"error": "Invalid active_since parameter"}), 400

    pagination_data = AccountModel.get_leaderboard_paginated(
        page=page, per_page=per_page, sort_by=sort_by, direction=direction,
        search=search, active_since=active_since,
    )

    return jsonify(pagination_data)


@account_blueprint.route('/my_contributions', methods=['GET'])
@login_required
def get_my_contributions():
    """Recup the my contributions"""
    
    user_id = current_user.id
    
   
    data = AccountModel.get_user_contributions_data(user_id=user_id)
    
    if not data or not data.get('user_stats'):
        # create the user_stats if it doesn't exist
        success = AccountModel.get_or_create_gamification_profile(user_id=user_id)
        if not success:
            return jsonify({"error": "Failed to create user_stats"}), 500
        data = AccountModel.get_user_contributions_data(user_id=user_id)
    
  
    return jsonify(data)


@account_blueprint.route('/user_contributions/<int:user_id>', methods=['GET'])
@login_required
def get_user_contributions(user_id):
    """Recup the user contributions"""
    if current_user.id != user_id and not current_user.is_admin():
        return jsonify({"error": "Forbidden"}), 403

    data = AccountModel.get_user_contributions_data(user_id=user_id)
    
    if not data or not data.get('user_stats'):
        # create the user_stats if it doesn't exist
        success = AccountModel.get_or_create_gamification_profile(user_id=user_id)
        if not success:
            return jsonify({"error": "Failed to create user_stats"}), 500
        data = AccountModel.get_user_contributions_data(user_id=user_id)
    
  
    return jsonify(data)

#refresh
@account_blueprint.route('/refresh', methods=['GET'])
@login_required
def refresh():
    """Recup the my contributions"""
    if not current_user.is_admin():
        return jsonify({"message": "Admin access required", "success": False, "toast_class": "danger-subtle"}), 403

    action = request.args.get('action')

    success = AccountModel.refreshData(action)
    if not success:
        return jsonify({"message": "Failed to refresh data", "success": False , "toast_class" : "danger-subtle"}), 500
    
    # update the user with the reel value like If someone has already like or propose an edit 
    success_ = AccountModel.update_gamification_profiles()
    if not success_:
        return jsonify({"message": "Error to update the gameifcation section", "success": False , "toast_class" : "danger-subtle"}), 500


    return jsonify({"message": "Data refreshed", "success": True , "toast_class" : "success-subtle"}), 200

# get_total_users
@account_blueprint.route('/get_total_users', methods=['GET'])
def get_total_users():
    total_users = AccountModel.get_total_users()
    if not total_users:
        return jsonify({"message": "Failed to get total users", "success": False , "toast_class" : "danger-subtle"}), 500

    return jsonify({"total_users": total_users, "success": True , "toast_class" : "success-subtle"}), 200


@account_blueprint.route('/admin', methods=['GET'])
def admin():
    if current_user.is_admin():
        return jsonify({"message": "Access granted", "success": True , "toast_class" : "success-subtle"}), 200
    return jsonify({"message": "Access denied", "success": False , "toast_class" : "danger-subtle"}), 403


# ── Bulk Field Parser ────────────────────────────────────────────────────────

@account_blueprint.route('/admin/bulk_parse_fields', methods=['GET'])
@login_required
def bulk_parse_fields_page():
    if not current_user.is_admin():
        from flask import abort
        abort(403)
    from app.features.rule.field_parser_core import FIELD_META, PARSEABLE_FIELD_KEYS
    return render_template('admin/bulk_parse_fields.html',
                           field_meta=FIELD_META,
                           parseable_fields=PARSEABLE_FIELD_KEYS)


@account_blueprint.route('/admin/bulk_parse_fields/test_extract', methods=['POST'])
@login_required
def bulk_parse_fields_test_extract():
    """
    Live preview for the Field Parsing Rules tester: runs the EXACT same
    extraction function the background job uses (keyword or regex mode,
    whichever the field is currently configured with), so what you see here
    is guaranteed to match what the job would extract.
    """
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Admin only'}), 403
    from app.features.rule.field_parser_core import locate_field_match

    data    = request.get_json(force=True) or {}
    content = data.get('content', '') or ''
    field_cfg = {
        'keywords': data.get('keywords', []),
        'regex':    data.get('regex', ''),
    }
    mode = 'regex' if (field_cfg['regex'] or '').strip() else 'keywords'
    value, start, end, line_index = locate_field_match(content, field_cfg)
    return jsonify({
        'success': True, 'mode': mode, 'value': value,
        'match_start': start, 'match_end': end, 'line_index': line_index,
    })


@account_blueprint.route('/admin/bulk_parse_fields/trigger', methods=['POST'])
@login_required
def bulk_parse_fields_trigger():
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Admin only'}), 403
    from app.features.jobs.jobs_core import create_job
    data = request.get_json(force=True)
    rule_ids      = data.get('rule_ids', 'ALL')
    fields_config = data.get('fields_config', {})
    format_filter = (data.get('format_filter') or '').strip() or None
    rescan_cve    = bool(data.get('rescan_cve'))
    enabled = [k for k, v in fields_config.items() if v.get('enabled')]
    if not enabled and not rescan_cve:
        return jsonify({'success': False, 'message': 'No fields enabled'}), 400
    count = len(rule_ids) if isinstance(rule_ids, list) else (format_filter or 'ALL')
    label_bits = list(enabled) + (['cve/vulnerability'] if rescan_cve else [])
    job = create_job(
        job_type='bulk_parse_fields',
        label=f'Bulk parse fields ({", ".join(label_bits)})',
        payload={'rule_ids': rule_ids, 'format_filter': format_filter,
                 'fields_config': fields_config, 'rescan_cve': rescan_cve},
        created_by=current_user.id,
    )
    log_activity('admin.bulk_parse_fields', f'Triggered bulk field parse for {count} rules, fields: {", ".join(label_bits)}',
                 target_type='job', target_id=job.id)
    return jsonify({'success': True, 'job_uuid': job.uuid})


@account_blueprint.route('/admin/bulk_parse_fields/trigger_platform_tags', methods=['POST'])
@login_required
def bulk_parse_fields_trigger_platform_tags():
    """Scan every rule's title/description/content for OS mentions and attach
    the matching tag, following an admin-defined, saved pattern config — see
    handle_bulk_tag_platforms in job_handlers.py.

    config_id is required and is re-validated here (not just trusted from
    save time): every referenced tag must still exist right now, and every
    regex must still compile, or the job is refused outright and nothing is
    queued. The job handler re-validates again immediately before it starts
    scanning, since a tag could still be deleted in the gap between this
    request and the job actually running.
    """
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Admin only'}), 403
    from app.features.jobs.jobs_core import create_job
    from app.features.rule.field_parser_core import get_config, validate_platform_tag_config, CONFIG_TYPE_PLATFORM_TAGS

    data      = request.get_json(force=True) or {}
    config_id = data.get('config_id')
    if not config_id:
        return jsonify({'success': False, 'message': 'config_id is required — save a platform-tag config first.'}), 400

    cfg = get_config(config_id, config_type=CONFIG_TYPE_PLATFORM_TAGS)
    if not cfg:
        return jsonify({'success': False, 'message': 'Platform-tag config not found.'}), 404

    ok, error, _resolved = validate_platform_tag_config(cfg.config)
    if not ok:
        return jsonify({'success': False, 'message': f'Config is invalid, not launching: {error}'}), 400

    job = create_job(
        job_type='bulk_tag_platforms',
        label=f'Detect & tag platforms ({cfg.name})',
        payload={'rule_ids': 'ALL', 'format_filter': None, 'config_id': cfg.id},
        created_by=current_user.id,
    )
    if not job:
        return jsonify({'success': False, 'message': 'Failed to create job'}), 500
    log_activity('admin.bulk_tag_platforms', f'Triggered platform-tag detection for all rules using config "{cfg.name}"',
                 target_type='job', target_id=job.id, target_uuid=job.uuid)
    return jsonify({'success': True, 'job': job.to_json(), 'message': 'Platform tagging job queued!'})


@account_blueprint.route('/admin/bulk_parse_fields/configs', methods=['GET'])
@login_required
def bulk_parse_fields_configs_list():
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    from app.features.rule.field_parser_core import get_all_configs, CONFIG_TYPE_FIELD_PARSER
    cfgs = get_all_configs(config_type=CONFIG_TYPE_FIELD_PARSER)
    return jsonify({'configs': [c.to_json() for c in cfgs]})


@account_blueprint.route('/admin/bulk_parse_fields/configs', methods=['POST'])
@login_required
def bulk_parse_fields_configs_save():
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    from app.features.rule.field_parser_core import save_config, CONFIG_TYPE_FIELD_PARSER
    data = request.get_json(force=True)
    name = (data.get('name') or '').strip()
    config = data.get('config', {})
    if not name:
        return jsonify({'success': False, 'message': 'Name is required'}), 400
    cfg = save_config(name=name, config=config, user_id=current_user.id, config_type=CONFIG_TYPE_FIELD_PARSER)
    return jsonify({'success': True, 'config': cfg.to_json()})


@account_blueprint.route('/admin/bulk_parse_fields/configs/<int:config_id>', methods=['PATCH'])
@login_required
def bulk_parse_fields_configs_update(config_id):
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    from app.features.rule.field_parser_core import get_config, CONFIG_TYPE_FIELD_PARSER
    cfg = get_config(config_id, config_type=CONFIG_TYPE_FIELD_PARSER)
    if not cfg:
        return jsonify({'success': False, 'message': 'Config not found'}), 404
    data = request.get_json(force=True)
    if 'name' in data:
        cfg.name = data['name'].strip() or cfg.name
    if 'config' in data:
        cfg.config = data['config']
    db.session.commit()
    return jsonify({'success': True, 'config': cfg.to_json()})


@account_blueprint.route('/admin/bulk_parse_fields/configs/<int:config_id>', methods=['DELETE'])
@login_required
def bulk_parse_fields_configs_delete(config_id):
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    from app.features.rule.field_parser_core import delete_config, CONFIG_TYPE_FIELD_PARSER
    ok = delete_config(config_id, config_type=CONFIG_TYPE_FIELD_PARSER)
    return jsonify({'success': ok})


# ── Platform-tag pattern configs ─────────────────────────────────────────────
# Same generic FieldParserConfig table as above, scoped to config_type
# 'platform_tags' so the two tools' saved configs never mix in either's list.

@account_blueprint.route('/admin/bulk_parse_fields/platform_configs', methods=['GET'])
@login_required
def platform_tag_configs_list():
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    from app.features.rule.field_parser_core import get_all_configs, CONFIG_TYPE_PLATFORM_TAGS
    cfgs = get_all_configs(config_type=CONFIG_TYPE_PLATFORM_TAGS)
    return jsonify({'configs': [c.to_json() for c in cfgs]})


@account_blueprint.route('/admin/bulk_parse_fields/platform_configs/validate', methods=['POST'])
@login_required
def platform_tag_configs_validate():
    """Validate-only, no save — lets the form show errors as the admin builds
    the pattern list, before they even try to save or launch anything."""
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    from app.features.rule.field_parser_core import validate_platform_tag_config
    data = request.get_json(force=True) or {}
    ok, error, resolved = validate_platform_tag_config(data.get('config', {}))
    return jsonify({'success': True, 'valid': ok, 'message': error, 'resolved_patterns': resolved})


@account_blueprint.route('/admin/bulk_parse_fields/platform_configs', methods=['POST'])
@login_required
def platform_tag_configs_save():
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    from app.features.rule.field_parser_core import save_config, validate_platform_tag_config, CONFIG_TYPE_PLATFORM_TAGS
    data   = request.get_json(force=True) or {}
    name   = (data.get('name') or '').strip()
    config = data.get('config', {})
    if not name:
        return jsonify({'success': False, 'message': 'Name is required'}), 400
    ok, error, resolved = validate_platform_tag_config(config)
    if not ok:
        return jsonify({'success': False, 'message': error}), 400
    # Persist the re-resolved patterns (tag_name/icon/color filled in fresh
    # from the DB), not whatever the client sent — this is what the config
    # editor needs to render a real tag chip on load without another lookup,
    # and it's guaranteed accurate since it just came from validation above.
    cfg = save_config(name=name, config={'patterns': resolved}, user_id=current_user.id, config_type=CONFIG_TYPE_PLATFORM_TAGS)
    return jsonify({'success': True, 'config': cfg.to_json()})


@account_blueprint.route('/admin/bulk_parse_fields/platform_configs/<int:config_id>', methods=['PATCH'])
@login_required
def platform_tag_configs_update(config_id):
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    from app.features.rule.field_parser_core import get_config, validate_platform_tag_config, CONFIG_TYPE_PLATFORM_TAGS
    cfg = get_config(config_id, config_type=CONFIG_TYPE_PLATFORM_TAGS)
    if not cfg:
        return jsonify({'success': False, 'message': 'Config not found'}), 404
    data = request.get_json(force=True) or {}
    new_config = data.get('config', cfg.config)
    ok, error, resolved = validate_platform_tag_config(new_config)
    if not ok:
        return jsonify({'success': False, 'message': error}), 400
    if 'name' in data:
        cfg.name = data['name'].strip() or cfg.name
    cfg.config = {'patterns': resolved}
    db.session.commit()
    return jsonify({'success': True, 'config': cfg.to_json()})


@account_blueprint.route('/admin/bulk_parse_fields/platform_configs/<int:config_id>', methods=['DELETE'])
@login_required
def platform_tag_configs_delete(config_id):
    if not current_user.is_admin():
        return jsonify({'success': False}), 403
    from app.features.rule.field_parser_core import delete_config, CONFIG_TYPE_PLATFORM_TAGS
    ok = delete_config(config_id, config_type=CONFIG_TYPE_PLATFORM_TAGS)
    return jsonify({'success': ok})




@account_blueprint.route('/user_activity_stats/<int:user_id>')
@login_required
def get_user_activity_stats(user_id):
    user_rules = RuleModel.get_all_rules_by_user(user_id)
    user_bundles = BundleModel.get_all_bundles_by_user(user_id)
    

    formats_counts = Counter([r.format for r in user_rules if r.format])
    

    timeline_data = Counter([r.creation_date.strftime('%Y-%m') for r in user_rules if r.creation_date])
    sorted_timeline = dict(sorted(timeline_data.items()))


    r_likes = sum(r.vote_up or 0 for r in user_rules)
    r_dislikes = sum(r.vote_down or 0 for r in user_rules)
    b_likes = sum(b.vote_up or 0 for b in user_bundles)
    b_dislikes = sum(b.vote_down or 0 for b in user_bundles)

    
    total_votes = r_likes + r_dislikes + b_likes + b_dislikes
    trust_score = 100
    if total_votes > 0:
        trust_score = round((r_likes + b_likes) / total_votes * 100, 1)

    return jsonify({
        "activity_stats": {
            "rules_likes": r_likes,
            "rules_dislikes": r_dislikes,
            "bundles_likes": b_likes,
            "bundles_dislikes": b_dislikes,
            "total_rules": len(user_rules),
            "total_bundles": len(user_bundles),
            "trust_score": trust_score
        },
        "format_distribution": dict(formats_counts),
        "timeline": sorted_timeline
    })

@account_blueprint.route('/user_edit_proposals/<int:user_id>')
@login_required
def get_user_edit_proposals(user_id):
    proposals = RuleModel.get_all_rule_proposal_user_id(user_id)

    if not proposals:
        return jsonify({
            "proposals": [],
            "stats": {
                "total": 0,
                "pending": 0,
                "accepted": 0,
                "rejected": 0
            }
        })

    return jsonify({
        "proposals": [p.to_json_for_discuss() for p in proposals],
        "stats": {
            "total": len(proposals),
            "pending": len([p for p in proposals if p.status == 'pending']),
            "accepted": len([p for p in proposals if p.status == 'accepted']),
            "rejected": len([p for p in proposals if p.status == 'rejected'])
        }
    })