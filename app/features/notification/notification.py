from flask import Blueprint, jsonify, request, render_template, abort
from flask_login import current_user, login_required

from app.features.notification.notification_core import (
    get_notifications, get_unread_count, get_bell_items, get_recent_job_notifications,
    mark_read, mark_all_read, delete_notification,
    follow_user, unfollow_user, is_following,
    get_follower_count, get_following_count,
    get_preference, update_preference,
)
from app.core.db_class.db import UserFollow, User

notification_blueprint = Blueprint('notification', __name__)


def _require_auth():
    if not current_user.is_authenticated:
        abort(401)


# ── Bell API ───────────────────────────────────────────────────────────────────

@notification_blueprint.get('/unread_count')
@login_required
def api_unread_count():
    return jsonify({'count': get_unread_count(current_user.id)})


@notification_blueprint.get('/bell')
@login_required
def api_bell():
    items = get_bell_items(current_user.id)
    return jsonify([n.to_json() for n in items])


@notification_blueprint.get('/bell/jobs')
@login_required
def api_bell_jobs():
    items = get_recent_job_notifications(current_user.id)
    return jsonify([n.to_json() for n in items])


# ── Full list API ──────────────────────────────────────────────────────────────

@notification_blueprint.get('/list')
@login_required
def api_list():
    page        = request.args.get('page', 1, type=int)
    per_page    = request.args.get('per_page', 20, type=int)
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    notif_type  = request.args.get('type', None)
    date_from   = request.args.get('date_from', None)
    date_to     = request.args.get('date_to', None)
    search      = request.args.get('search', None)
    pagination  = get_notifications(current_user.id, page, per_page, unread_only, notif_type,
                                     date_from, date_to, search)
    return jsonify({
        'notifications': [n.to_json() for n in pagination.items],
        'total':         pagination.total,
        'pages':         pagination.pages,
        'page':          pagination.page,
        'unread_count':  get_unread_count(current_user.id),
    })


# ── Mutations ──────────────────────────────────────────────────────────────────

@notification_blueprint.post('/<int:notif_id>/read')
@login_required
def api_mark_read(notif_id):
    ok = mark_read(notif_id, current_user.id)
    return jsonify({'ok': ok}), (200 if ok else 404)


@notification_blueprint.post('/read_all')
@login_required
def api_mark_all_read():
    ok = mark_all_read(current_user.id)
    return jsonify({'ok': ok})


@notification_blueprint.delete('/<int:notif_id>')
@login_required
def api_delete(notif_id):
    ok = delete_notification(notif_id, current_user.id)
    return jsonify({'ok': ok}), (200 if ok else 404)


@notification_blueprint.delete('/delete_all')
@login_required
def api_delete_all():
    from app.features.notification.notification_core import delete_all_notifications
    delete_all_notifications(current_user.id)
    return jsonify({'ok': True})


# ── Follow API ─────────────────────────────────────────────────────────────────

@notification_blueprint.post('/follow/<int:user_id>')
@login_required
def api_follow(user_id):
    ok, msg = follow_user(current_user.id, user_id)
    return jsonify({'ok': ok, 'message': msg}), (200 if ok else 400)


@notification_blueprint.delete('/follow/<int:user_id>')
@notification_blueprint.post('/unfollow/<int:user_id>')
@login_required
def api_unfollow(user_id):
    ok, msg = unfollow_user(current_user.id, user_id)
    return jsonify({'ok': ok, 'message': msg})


@notification_blueprint.get('/follow/<int:user_id>/status')
@login_required
def api_follow_status(user_id):
    return jsonify({
        'is_following':   is_following(current_user.id, user_id),
        'followers':      get_follower_count(user_id),
        'following':      get_following_count(user_id),
    })


# ── My followers / following (with user details) ───────────────────────────────

def _user_to_card(user):
    return {
        'id':       user.id,
        'username': user.get_username(),
        'avatar':   user.get_avatar_url(),
        'location': user.location,
        'bio':      (user.bio or '')[:80] if user.bio else None,
    }


@notification_blueprint.get('/my_followers')
@login_required
def api_my_followers():
    rows = UserFollow.query.filter_by(followed_id=current_user.id).all()
    users = []
    for row in rows:
        u = User.query.get(row.follower_id)
        if u:
            users.append(_user_to_card(u))
    return jsonify(users)


@notification_blueprint.get('/my_following')
@login_required
def api_my_following():
    rows = UserFollow.query.filter_by(follower_id=current_user.id).all()
    users = []
    for row in rows:
        u = User.query.get(row.followed_id)
        if u:
            users.append(_user_to_card(u))
    return jsonify(users)


# ── Preferences API ───────────────────────────────────────────────────────────

@notification_blueprint.get('/preferences')
@login_required
def api_get_preferences():
    pref = get_preference(current_user.id)
    return jsonify(pref.to_json())


@notification_blueprint.post('/preferences')
@login_required
def api_update_preferences():
    data = request.json or {}
    pref = update_preference(current_user.id, data)
    if pref is None:
        return jsonify({'ok': False}), 500
    return jsonify({'ok': True, 'preferences': pref.to_json()})


# ── Page ───────────────────────────────────────────────────────────────────────

@notification_blueprint.get('/')
@login_required
def page_notifications():
    return render_template('notification/notifications.html')
