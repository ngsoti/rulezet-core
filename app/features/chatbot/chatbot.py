from flask import Blueprint, jsonify, redirect, render_template, request
from flask_login import current_user, login_required

from . import chatbot_core as ChatbotModel

chatbot_blueprint = Blueprint('chatbot', __name__)


@chatbot_blueprint.route('/message', methods=['POST'])
@login_required
def send_message():
    from app.core.db_class.db import InstanceConfig
    cfg = InstanceConfig.query.first()
    if cfg and not cfg.chatbot_enabled:
        return jsonify({"success": False, "reply": "The chatbot is disabled on this instance."}), 403

    data = request.get_json(force=True) or {}
    message = (data.get('message') or '').strip()
    history = data.get('history') or []
    conversation_id = (data.get('conversation_id') or '').strip() or None
    if not message:
        return jsonify({"success": False, "reply": "Say something first."}), 400
    if not isinstance(history, list):
        history = []

    try:
        result = ChatbotModel.handle_message(current_user, history, message, conversation_id)
    except ConnectionError as e:
        return jsonify({"success": False, "reply": str(e)}), 502

    return jsonify(result), 200


# ── Admin: conversation history ────────────────────────────────────────────
# Mixed blueprint (the routes above are for any authenticated user), so each
# admin route below gates itself inline rather than via a blueprint-wide
# before_request hook — same pattern as app/features/jobs/jobs.py.

@chatbot_blueprint.route('/admin/conversations', methods=['GET'])
@login_required
def admin_conversations():
    """Moved to the unified AI admin hub (see home.ia_admin) — kept as a
    redirect so any existing bookmark/link still lands somewhere useful."""
    if not current_user.is_admin():
        return render_template('access_denied.html')
    return redirect('/ia/admin?tab=chatbot')


@chatbot_blueprint.route('/admin/conversations/data', methods=['GET'])
@login_required
def admin_conversations_data():
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    from datetime import datetime, timedelta

    from app.core.db_class.db import ChatbotConversation, User

    page       = request.args.get('page', 1, type=int)
    per_page   = min(100, request.args.get('per_page', 25, type=int))
    search     = request.args.get('search', '', type=str).strip()
    user_id_f  = request.args.get('user_id', None, type=int)
    date_from  = request.args.get('date_from', '', type=str).strip()
    date_to    = request.args.get('date_to', '', type=str).strip()
    count_min  = request.args.get('message_count_min', None, type=int)
    count_max  = request.args.get('message_count_max', None, type=int)
    errors_only = request.args.get('errors_only', '', type=str).strip().lower() in ('1', 'true')
    sort_key   = request.args.get('sort', 'last_message_at', type=str)
    sort_dir   = request.args.get('dir', 'desc', type=str)

    _allowed_sorts = {'started_at', 'last_message_at', 'message_count'}
    if sort_key not in _allowed_sorts:
        sort_key = 'last_message_at'
    if sort_dir not in ('asc', 'desc'):
        sort_dir = 'desc'

    q = ChatbotConversation.query
    if search:
        q = q.join(User, ChatbotConversation.user_id == User.id).filter(
            (User.username.ilike(f'%{search}%')) |
            (User.first_name.ilike(f'%{search}%')) |
            (User.last_name.ilike(f'%{search}%'))
        )
    if user_id_f:
        q = q.filter(ChatbotConversation.user_id == user_id_f)
    if date_from:
        try:
            q = q.filter(ChatbotConversation.started_at >= datetime.strptime(date_from, '%Y-%m-%d'))
        except ValueError:
            pass
    if date_to:
        try:
            q = q.filter(ChatbotConversation.started_at < datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1))
        except ValueError:
            pass
    if count_min is not None:
        q = q.filter(ChatbotConversation.message_count >= count_min)
    if count_max is not None:
        q = q.filter(ChatbotConversation.message_count <= count_max)
    if errors_only:
        q = q.filter(ChatbotConversation.error_count > 0)

    sort_col = getattr(ChatbotConversation, sort_key)
    q = q.order_by(sort_col.asc() if sort_dir == 'asc' else sort_col.desc())

    total       = q.count()
    total_pages = max(1, (total + per_page - 1) // per_page)
    page        = min(page, total_pages)
    items       = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "items":       [c.to_json() for c in items],
        "total":       total,
        "page":        page,
        "per_page":    per_page,
        "total_pages": total_pages,
    }), 200


@chatbot_blueprint.route('/admin/conversations/users', methods=['GET'])
@login_required
def admin_conversations_users():
    """Distinct users who have at least one chatbot conversation, with their
    conversation count — feeds the user filter dropdown (same '[{name/label,
    count}]' shape as /rule/get_rules_authors_usage)."""
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    from sqlalchemy import func

    from app import db
    from app.core.db_class.db import ChatbotConversation, User

    rows = (
        db.session.query(User, func.count(ChatbotConversation.id))
        .join(ChatbotConversation, ChatbotConversation.user_id == User.id)
        .group_by(User.id)
        .order_by(func.count(ChatbotConversation.id).desc())
        .all()
    )
    return jsonify([
        {"user_id": u.id, "username": u.get_username(), "avatar": u.get_avatar_url(), "count": count}
        for u, count in rows
    ])


@chatbot_blueprint.route('/admin/conversations/<string:conversation_uuid>', methods=['GET'])
@login_required
def admin_conversation_detail(conversation_uuid):
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    from app.core.db_class.db import ChatbotConversation

    conv = ChatbotConversation.query.filter_by(uuid=conversation_uuid).first()
    if not conv:
        return jsonify({"error": "Not found"}), 404

    return jsonify({
        "conversation": conv.to_json(),
        "messages": [m.to_json() for m in conv.messages],
    }), 200


@chatbot_blueprint.route('/admin/conversations/<string:conversation_uuid>/delete', methods=['POST'])
@login_required
def admin_conversation_delete(conversation_uuid):
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    from app import db
    from app.core.db_class.db import ChatbotConversation

    conv = ChatbotConversation.query.filter_by(uuid=conversation_uuid).first()
    if not conv:
        return jsonify({"success": False, "message": "Not found"}), 404

    db.session.delete(conv)
    db.session.commit()
    return jsonify({"success": True, "message": "Conversation deleted"}), 200
