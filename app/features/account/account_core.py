import os
import secrets
import hashlib
from werkzeug.utils import secure_filename


import datetime , random
from datetime import timezone, timedelta
from typing import  Tuple
from flask_login import current_user
from sqlalchemy import func, or_
from flask_mail import Message
from app import mail

from ... import db
from ...core.db_class.db import BackgroundJob, Bundle, BundleVote, CustomTheme, Gamification, RequestOwnerRule, Rule, RuleEditProposal, RuleFavoriteUser, RuleUpdateHistory, RuleVote, Tag, User, UserConfig
from ...core.utils.utils import generate_api_key
from ..rule import rule_core as RuleModel
import uuid


AVATAR_UPLOAD_FOLDER = os.path.join("app", "static", "uploads", "avatars")
ALLOWED_AVATAR_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}
MAX_AVATAR_SIZE_MB = 2


#####################
#   User actions    #
#####################

# CRUD

TIME_EMAIL_EXPIRATION = timedelta(minutes=30)
TIME_RESET_EXPIRATION = timedelta(hours=1)

# Create

def add_user_core(form_dict) -> tuple:
    """Add a user to the DB with email verification logic."""
    api_key = form_dict.get("key")
    if not api_key:
        api_key = generate_api_key()
 
    code = str(random.randint(100000, 999999))
    from datetime import timezone, timedelta, datetime as dt
    now = dt.now(timezone.utc).replace(tzinfo=None)
    expires = now + TIME_EMAIL_EXPIRATION
 
    user = User(
        first_name=form_dict["first_name"],
        last_name=form_dict["last_name"],
        email=form_dict["email"],
        password=form_dict["password"],
        api_key=api_key,
        verification_code=code,
        verification_expiration=expires,
        is_verified=False,
        created_at=now,          # set on registration
    )
 
    db.session.add(user)
    db.session.commit()

    try:
        from ..config.config_core import create_default_config_core
        create_default_config_core(user.id)
    except Exception:
        pass

    success, message = send_verify_email(user, code)
    if not success:
        return message, False
 
    return user, True


def resend_verification_code_core(user_id) -> bool:
    """Resend the verification code to the user"""
    user = get_user(user_id)
    if user:
        # An already-verified account has no legitimate reason to receive a
        # new code — allowing it lets an unauthenticated caller manufacture a
        # verification_expiration timestamp for an arbitrary verified user
        # (one that never had one set), which the /verify/<id> route would
        # then delete once that timestamp passed. See the guard added there.
        if user.is_verified:
            return False, "Account is already verified"
        user.verification_code = str(random.randint(100000, 999999))
        user.verification_expiration = datetime.datetime.now(timezone.utc).replace(tzinfo=None) + TIME_EMAIL_EXPIRATION
        db.session.commit()
        
        success , message = send_verify_email(user, user.verification_code)
        if not success:
            return False , message

        return True , "Verification code resent"
    else:
        return False , "User not found"

def send_verify_email(user, code):
   try:
        msg = Message(
            "Your Verification Code",
            sender="noreply@your-app.com",
            recipients=[user.email]
        )

        msg.body = f"Hello {user.first_name}, your verification code is: {code}. It expires in 30 minutes."

        msg.html = f"""
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #eeeeee; border-radius: 12px; overflow: hidden;">

            <div style="text-align: center; margin: 20px 0;">
                <img src="https://rulezet.org/static/image/logo.png" 
                    alt="Rulezet Logo" 
                    style="display: inline-block; width: 150px; height: auto;">
            </div>
            <div style="background-color: #2c3e50; padding: 30px; text-align: center;">
                <h1 style="color: #ffffff; margin: 0; font-size: 24px; letter-spacing: 1px;">Confirm Your Email </h1>
            </div>
            
            <div style="padding: 40px 30px; line-height: 1.6; color: #333333; background-color: #ffffff;">
                <p style="font-size: 16px;">Hi {user.first_name},</p>
                <p style="font-size: 16px;">Thank you for joining our community! To secure your account, please enter the following verification code on the registration page:</p>
                
                <div style="text-align: center; margin: 40px 0;">
                    <div style="display: inline-block; padding: 20px 40px; font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #3498db; background-color: #f7f9fc; border: 2px solid #3498db; border-radius: 8px;">
                        {code}
                    </div>
                </div>
                
                <p style="font-size: 14px; color: #7f8c8d; text-align: center;">
                    This code is valid for <strong>30 minutes</strong>.<br>
                    If you did not request this code, you can safely ignore this email.
                </p>
            </div>
            
            <div style="background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #bdc3c7; border-top: 1px solid #eeeeee;">
                <p style="margin: 5px 0;">&copy; 2026 Rulezet. All rights reserved.</p>
            </div>
        </div>
        """
        
        mail.send(msg)

        return True , "Email sent successfully"

   except Exception as e:
        return False , str(e)


def request_password_reset_core(email: str) -> bool:
    """Generate a password reset token and email it. Always returns True to prevent enumeration."""
    user = User.query.filter_by(email=email).first()
    if not user or not user.is_verified:
        return True  # silent — prevent email enumeration
    raw_token = secrets.token_urlsafe(32)
    hashed    = hashlib.sha256(raw_token.encode()).hexdigest()
    user.password_reset_token      = hashed
    user.password_reset_expiration = datetime.datetime.now(timezone.utc).replace(tzinfo=None) + TIME_RESET_EXPIRATION
    db.session.commit()
    send_reset_email(user, raw_token)
    return True


def reset_password_core(raw_token: str, new_password: str) -> tuple:
    """Validate reset token and set new password. Returns (success, message)."""
    hashed = hashlib.sha256(raw_token.encode()).hexdigest()
    user = User.query.filter_by(password_reset_token=hashed).first()
    if not user:
        return False, "Invalid or expired link."
    now = datetime.datetime.now(timezone.utc).replace(tzinfo=None)
    if not user.password_reset_expiration or now > user.password_reset_expiration:
        user.password_reset_token      = None
        user.password_reset_expiration = None
        db.session.commit()
        return False, "This link has expired. Please request a new one."
    user.password              = new_password
    user.password_reset_token  = None
    user.password_reset_expiration = None
    db.session.commit()
    return True, "Password reset successfully."


def send_reset_email(user, raw_token: str) -> tuple:
    from flask import url_for
    try:
        reset_url = url_for('account.reset_password', token=raw_token, _external=True)
        msg = Message(
            "Reset your Rulezet password",
            sender="noreply@rulezet.org",
            recipients=[user.email]
        )
        msg.body = (
            f"Hello {user.first_name},\n\n"
            f"Click the link below to reset your password. It expires in 1 hour.\n\n"
            f"{reset_url}\n\n"
            "If you didn't request this, you can safely ignore this email."
        )
        msg.html = f"""
        <div style="font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;max-width:600px;margin:0 auto;border:1px solid #eeeeee;border-radius:12px;overflow:hidden;">
            <div style="text-align:center;padding:20px 0 0;">
                <img src="https://rulezet.org/static/image/logo.png" alt="Rulezet" style="width:140px;height:auto;">
            </div>
            <div style="background:#0a58ca;padding:30px;text-align:center;">
                <h1 style="color:#fff;margin:0;font-size:22px;letter-spacing:1px;">Password Reset Request</h1>
            </div>
            <div style="padding:40px 30px;line-height:1.7;color:#333;background:#fff;">
                <p style="font-size:16px;">Hi {user.first_name},</p>
                <p style="font-size:15px;">We received a request to reset your password. Click the button below — the link expires in <strong>1 hour</strong>.</p>
                <div style="text-align:center;margin:36px 0;">
                    <a href="{reset_url}" style="display:inline-block;padding:14px 36px;background:linear-gradient(135deg,#0a58ca,#0d6efd);color:#fff;text-decoration:none;border-radius:8px;font-weight:600;font-size:15px;letter-spacing:.3px;">Reset Password</a>
                </div>
                <p style="font-size:13px;color:#888;text-align:center;">If you didn't request this, you can safely ignore this email. Your password won't change.</p>
                <p style="font-size:12px;color:#aaa;word-break:break-all;">Or copy this link: {reset_url}</p>
            </div>
            <div style="background:#f8f9fa;padding:20px;text-align:center;font-size:12px;color:#bdc3c7;border-top:1px solid #eee;">
                <p style="margin:5px 0;">&copy; 2026 Rulezet. All rights reserved.</p>
            </div>
        </div>
        """
        mail.send(msg)
        return True, "Email sent"
    except Exception as e:
        return False, str(e)


def verify_user_core(id) -> bool:
    """Verify the user in the DB"""
    user = get_user(id)
    if user:
        user.is_verified = True
        db.session.commit()
        return True
    else:
        return False

# Update
def update_last_seen(user_id) -> None:
    """Update the last_seen timestamp for the user."""
    user = get_user(user_id)
    if user:
        user.last_seen = datetime.datetime.utcnow()
        db.session.commit()



def edit_user_core(form_dict, id, avatar_file=None, remove_avatar=False) -> tuple:
    """Edit the user in the DB. Returns (success, pending_email_or_None).
    If the email changed, the new address is NOT applied immediately — caller must
    call request_email_change_core() to send the confirmation link."""
    user = get_user(id)
    if not user:
        return False, None

    user.first_name = form_dict["first_name"]
    user.last_name  = form_dict["last_name"]

    # Detect email change but don't apply it yet
    new_email = form_dict["email"]
    pending_email = None
    if new_email != user.email:
        pending_email = new_email
    else:
        user.email = new_email

    if form_dict.get("password"):
        user.password = form_dict["password"]

    user.username    = form_dict.get("username") or None
    user.bio         = form_dict.get("bio") or None
    user.location    = form_dict.get("location") or None
    user.website_url = form_dict.get("website_url") or None
    user.github_url  = form_dict.get("github_url") or None
    user.twitter_url = form_dict.get("twitter_url") or None

    if remove_avatar and user.profile_picture:
        _delete_avatar_file(user.profile_picture)
        user.profile_picture = None
    elif avatar_file and avatar_file.filename:
        ext = avatar_file.filename.rsplit(".", 1)[-1].lower()
        if ext in ALLOWED_AVATAR_EXTENSIONS:
            os.makedirs(AVATAR_UPLOAD_FOLDER, exist_ok=True)
            if user.profile_picture:
                _delete_avatar_file(user.profile_picture)
            filename = f"{uuid.uuid4().hex}.{ext}"
            avatar_file.save(os.path.join(AVATAR_UPLOAD_FOLDER, filename))
            user.profile_picture = filename

    db.session.commit()
    return True, pending_email


def request_email_change_core(user_id: int, new_email: str) -> bool:
    """Store a pending email change and send a confirmation link to the new address."""
    user = get_user(user_id)
    if not user:
        return False
    conflict = User.query.filter(User.email == new_email, User.id != user_id).first()
    if conflict:
        return False
    raw_token = secrets.token_urlsafe(32)
    hashed    = hashlib.sha256(raw_token.encode()).hexdigest()
    user.pending_email          = new_email
    user.email_change_token     = hashed
    user.email_change_expiration = (
        datetime.datetime.now(timezone.utc).replace(tzinfo=None) + TIME_RESET_EXPIRATION
    )
    db.session.commit()
    send_email_change_email(user, new_email, raw_token)
    return True


def confirm_email_change_core(raw_token: str) -> tuple:
    """Validate an email-change token and apply the new address. Returns (success, message)."""
    hashed = hashlib.sha256(raw_token.encode()).hexdigest()
    user   = User.query.filter_by(email_change_token=hashed).first()
    if not user:
        return False, "Invalid or expired link."
    now = datetime.datetime.now(timezone.utc).replace(tzinfo=None)
    if not user.email_change_expiration or now > user.email_change_expiration:
        user.email_change_token      = None
        user.email_change_expiration = None
        user.pending_email           = None
        db.session.commit()
        return False, "This confirmation link has expired. Please update your email again."
    new_email = user.pending_email
    conflict  = User.query.filter(User.email == new_email, User.id != user.id).first()
    if conflict:
        user.email_change_token      = None
        user.email_change_expiration = None
        user.pending_email           = None
        db.session.commit()
        return False, "This email address is already in use by another account."
    user.email               = new_email
    user.pending_email       = None
    user.email_change_token  = None
    user.email_change_expiration = None
    db.session.commit()
    return True, "Email address updated successfully."


def send_email_change_email(user, new_email: str, raw_token: str) -> tuple:
    from flask import url_for
    try:
        confirm_url = url_for('account.confirm_email_change', token=raw_token, _external=True)
        msg = Message(
            "Confirm your new Rulezet email address",
            sender="noreply@rulezet.org",
            recipients=[new_email]
        )
        msg.body = (
            f"Hello {user.first_name},\n\n"
            f"Someone requested to change the email address on your Rulezet account to this address.\n\n"
            f"Click the link below to confirm the change. It expires in 1 hour.\n\n"
            f"{confirm_url}\n\n"
            "If you didn't request this, you can safely ignore this email — "
            "your current email address will not change."
        )
        msg.html = f"""
        <div style="font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;max-width:600px;margin:0 auto;border:1px solid #eeeeee;border-radius:12px;overflow:hidden;">
            <div style="text-align:center;padding:20px 0 0;">
                <img src="https://rulezet.org/static/image/logo.png" alt="Rulezet" style="width:140px;height:auto;">
            </div>
            <div style="background:#0a58ca;padding:30px;text-align:center;">
                <h1 style="color:#fff;margin:0;font-size:22px;letter-spacing:1px;">Confirm New Email Address</h1>
            </div>
            <div style="padding:40px 30px;line-height:1.7;color:#333;background:#fff;">
                <p style="font-size:16px;">Hi {user.first_name},</p>
                <p style="font-size:15px;">Click the button below to confirm <strong>{new_email}</strong> as your new email address. The link expires in <strong>1 hour</strong>.</p>
                <div style="text-align:center;margin:36px 0;">
                    <a href="{confirm_url}" style="display:inline-block;padding:14px 36px;background:linear-gradient(135deg,#0a58ca,#0d6efd);color:#fff;text-decoration:none;border-radius:8px;font-weight:600;font-size:15px;letter-spacing:.3px;">Confirm Email Change</a>
                </div>
                <p style="font-size:13px;color:#888;text-align:center;">If you didn't request this, ignore this email — your current address remains unchanged.</p>
                <p style="font-size:12px;color:#aaa;word-break:break-all;">Or copy this link: {confirm_url}</p>
            </div>
            <div style="background:#f8f9fa;padding:20px;text-align:center;font-size:12px;color:#bdc3c7;border-top:1px solid #eee;">
                <p style="margin:5px 0;">&copy; 2026 Rulezet. All rights reserved.</p>
            </div>
        </div>
        """
        mail.send(msg)
        return True, "Email sent"
    except Exception as e:
        return False, str(e)
 
 
def _delete_avatar_file(filename: str) -> None:
    """Delete an avatar file from disk if it exists."""
    if not filename:
        return
    path = os.path.join(AVATAR_UPLOAD_FOLDER, filename)
    if os.path.isfile(path):
        os.remove(path)



def connected(user) -> bool:
    """connected an user"""
    if not user.is_connected:
        user.is_connected = True
        db.session.commit()
    return user.is_connected

def disconnected(user) -> bool:
    """disconnected an user"""
    if user.is_connected:
        user.is_connected = False
        db.session.commit()
    return not user.is_connected

def promote_remove_user_admin(user_id , action) -> bool:
    """Promote or remove user to admin right"""
    if current_user.is_admin():
        user = get_user(user_id)
        if not user or user.id == current_user.id:
            return False
        if action == 'remove':
            user.admin = False
            db.session.commit()
            return True
        elif action == 'promote':
            user.admin = True
            db.session.commit()
            return True
        else:
            return False
        
    else:
        return False

# Delete

def delete_user_core(id) -> bool:
    """Delete the user from the DB and clean up their avatar file."""
    rules = RuleModel.get_rules_of_user_with_id(id)
    RuleModel.give_all_right_to_admin(rules)

    user = get_user(id)
    if not user:
        return False

    # Resolve FK constraints before deleting the user row.
    # UserConfig has non-nullable user_id → must delete the row.
    UserConfig.query.filter(
        (UserConfig.user_id == id) | (UserConfig.created_by == id)
    ).delete(synchronize_session=False)

    # Tag.created_by and BackgroundJob.created_by are NOT NULL → reassign to admin.
    admin = get_admin_user()
    if admin and admin.id != id:
        Tag.query.filter_by(created_by=id).update(
            {'created_by': admin.id}, synchronize_session=False
        )
        BackgroundJob.query.filter_by(created_by=id).update(
            {'created_by': admin.id}, synchronize_session=False
        )

    # CustomTheme.created_by is nullable → set NULL.
    CustomTheme.query.filter_by(created_by=id).update(
        {'created_by': None}, synchronize_session=False
    )

    # clean up avatar file before DB delete
    if user.profile_picture:
        _delete_avatar_file(user.profile_picture)

    db.session.delete(user)
    db.session.commit()
    return True


# Read

def get_default_user()-> id:
    """Return the default user"""
    return User.query.filter_by(email='default@default.default').first()

def get_admin_user()-> id:
    """Return the default user"""
    return User.query.filter_by(email='admin@admin.admin').first()

def get_user(id) -> id:
    """Return the user"""
    return User.query.get(id)


def search_users_lite(query: str, limit: int = 5) -> list[dict]:
    """Lightweight user lookup for the global nav search — caller must only
    invoke this for authenticated visitors; returns only fields already
    considered public elsewhere (see /account/user_mini/<id>): id, username,
    avatar. Never email/admin/any other field from User.to_json().
    """
    like_pattern = f"%{query}%"
    matches = (
        User.query.filter(or_(
            User.first_name.ilike(like_pattern),
            User.last_name.ilike(like_pattern),
        ))
        .limit(limit)
        .all()
    )

    exact = User.query.get(int(query)) if query.isdigit() else None

    results = []
    seen_ids = set()
    for user in ([exact] if exact else []) + matches:
        if not user or user.id in seen_ids:
            continue
        seen_ids.add(user.id)
        results.append({
            "id": user.id,
            "username": user.get_username(),
            "avatar": user.get_avatar_url(),
        })
        if len(results) >= limit:
            break
    return results

def get_user_rules(user_id: int) -> list:
    """Return all rules created by the user."""
    return Rule.query.filter_by(user_id=user_id).all()

def get_user_votes_summary(user_id: int) -> dict:
    """
    Return the total vote_up and vote_down from all rules and bundles created by the user.
    Uses SQL SUM — never loads full objects into memory.
    """

    r = db.session.query(
        func.coalesce(func.sum(Rule.vote_up), 0),
        func.coalesce(func.sum(Rule.vote_down), 0)
    ).filter(Rule.user_id == user_id).one()

    b = db.session.query(
        func.coalesce(func.sum(Bundle.vote_up), 0),
        func.coalesce(func.sum(Bundle.vote_down), 0)
    ).filter(Bundle.user_id == user_id).one()

    return {
        "total_upvotes":     r[0] + b[0],
        "total_downvotes":   r[1] + b[1],
        "rules_upvotes":     r[0],
        "rules_downvotes":   r[1],
        "bundles_upvotes":   b[0],
        "bundles_downvotes": b[1],
    }
def get_user_rule_formats(user_id: int) -> list:
    """Return the list of unique formats used by the user in their rules."""
    rules = get_user_rules(user_id)
    return list(set(r.format for r in rules if r.format))

def get_user_favorite_rules(user_id: int) -> Tuple[int]:
    """Return list of rule IDs favorited by the user."""
    return [fav.rule_id for fav in RuleFavoriteUser.query.filter_by(user_id=user_id).all()]

def get_user_data_full(user_id: int) -> dict:
    """Compile all user activity metadata into a single dictionary."""
    user = get_user(user_id)
    if not user:
        return None

    rules = get_user_rules(user_id)
    votes = get_user_votes_summary(user_id) 
    formats = get_user_rule_formats(user_id)
    favorites = get_user_favorite_rules(user_id)
    types = RuleModel.get_rule_type_count(user_id)

    return {
        "user": user.to_json(),
        "rule_count": len(rules),
        "total_upvotes": votes["total_upvotes"],      
        "total_downvotes": votes["total_downvotes"],  
        "rules_upvotes": votes["rules_upvotes"],     
        "rules_downvotes": votes["rules_downvotes"],
        "bundles_upvotes": votes["bundles_upvotes"],  
        "bundles_downvotes": votes["bundles_downvotes"],
        "formats_used": formats,
        "favorite_rule_ids": favorites,
        "rule_detail": types.get_json()
    }

def get_users_page_filter(page, search=None, connected=None, admin=None):
    """Get paginated users with optional filters"""
    per_page = 30
    query = User.query  

    if search:
        search_lower = f"%{search.lower()}%"
        query = query.filter(
            or_(
                User.first_name.ilike(search_lower),
                User.last_name.ilike(search_lower),
                User.email.ilike(search_lower)
            )
        )

    if admin is not None:
        if admin.lower() == "true":
            query = query.filter(User.admin.is_(True))
        elif admin.lower() == "false":
            query = query.filter(User.admin.is_(False))

    if connected is not None:
        if connected.lower() == "true":
            query = query.filter(User.is_connected.is_(True))
        elif connected.lower() == "false":
            query = query.filter(User.is_connected.is_(False))

    query = query.order_by(User.id.asc())

    return query.paginate(page=page, per_page=per_page, error_out=False)

def get_username_by_id(user_id) -> str:
    """Return user's firstname """
    user = get_user(user_id)
    return user.first_name 

#####################
#   User Favorite   #
#####################

# CREATE

def add_favorite(user_id: int, rule_id: int) -> RuleFavoriteUser:
    """Adds a rule to the user's favorites"""
    import datetime 
    exists = is_rule_favorited_by_user(user_id=user_id, rule_id=rule_id)
    if not exists:
        favorite = RuleFavoriteUser(user_id=user_id, rule_id=rule_id, created_at=datetime.datetime.now(tz=datetime.timezone.utc))
        db.session.add(favorite)
        db.session.commit()
        try:
            from app.features.rule.rule_quality.quality_score_core import refresh_engagement_boost
            rule = Rule.query.get(rule_id)
            if rule:
                refresh_engagement_boost(rule)
        except Exception:
            pass
        return favorite
    return exists

# READ

def is_rule_favorited_by_user(user_id: int, rule_id: int) -> bool:
    """Checks if a rule is favorited by a user"""
    return RuleFavoriteUser.query.filter_by(user_id=user_id, rule_id=rule_id).first() is not None


# DELETE

def remove_favorite(user_id: int, rule_id: int) -> bool:
    """Delete a favorite if found"""
    favorite = RuleFavoriteUser.query.filter_by(user_id=user_id, rule_id=rule_id).first()
    if favorite:
        db.session.delete(favorite)
        db.session.commit()
        try:
            from app.features.rule.rule_quality.quality_score_core import refresh_engagement_boost
            rule = Rule.query.get(rule_id)
            if rule:
                refresh_engagement_boost(rule)
        except Exception:
            pass
        return True
    return False

#######################
#   Request Section   #
#######################

def create_request(rule_id, source):
    """Create or update an ownership request."""
    if source == "":
        # request for one rule
        rule = RuleModel.get_rule(rule_id)
        existing_request = RequestOwnerRule.query.filter_by(
            user_id=current_user.id,
            title=f"Request for ownership of rule {rule.title} "
        ).first()

        if existing_request:
            existing_request.content = f"{current_user.first_name} {current_user.last_name} wants to become the owner of '{rule.title}'"
            existing_request.status = "pending"
            existing_request.updated_at = datetime.datetime.now(tz=datetime.timezone.utc)
            db.session.commit()
            return existing_request
        
        new_request = RequestOwnerRule(
            user_id_to_send=rule.user_id,
            user_id=current_user.id,
            uuid=str(uuid.uuid4()),
            title=f"Request for ownership of rule {rule.title}",
            content=f"{current_user.first_name} {current_user.last_name} wants to become the owner of '{rule.title}'",
            status="pending",
            created_at=datetime.datetime.now(tz=datetime.timezone.utc),
            updated_at=datetime.datetime.now(tz=datetime.timezone.utc),
            rule_id=rule.id
        )
        db.session.add(new_request)
        db.session.commit()
        return new_request

    else:
        # Request for a source
        rules_for_source = Rule.query.filter_by(source=source).all()
        unique_editors = set(rule.user_id for rule in rules_for_source if rule.user_id)
        created_requests = []

        for editor_id in unique_editors:
            if editor_id == current_user.id:
                continue  

            existing_request = RequestOwnerRule.query.filter_by(
                user_id=current_user.id,
                user_id_to_send=editor_id,
                rule_source=source,
                title=f"Request for ownership of the rule(s) in '{source}' "
            ).first()

            if existing_request:
                existing_request.content = f"{current_user.first_name} {current_user.last_name} wants to become the owner of the rule(s) in '{source}'"
                existing_request.status = "pending"
                existing_request.updated_at = datetime.datetime.now(tz=datetime.timezone.utc)
                db.session.commit()
                created_requests.append(existing_request)
            else:
                new_request = RequestOwnerRule(
                    user_id_to_send=editor_id,
                    user_id=current_user.id,
                    uuid=str(uuid.uuid4()),
                    title=f"Request for ownership of the rule(s) in '{source}' ",
                    content=f"{current_user.first_name} {current_user.last_name} wants to become the owner of the rule(s) in '{source}' ",
                    status="pending",
                    created_at=datetime.datetime.now(tz=datetime.timezone.utc),
                    updated_at=datetime.datetime.now(tz=datetime.timezone.utc),
                    rule_source=source
                )
                db.session.add(new_request)
                created_requests.append(new_request)

        db.session.commit()
        return created_requests

def get_requests_page(page, per_page=20) -> dict:
    """Return all requets by page"""
    return (RequestOwnerRule.query.filter(RequestOwnerRule.status == "pending")
            .order_by(RequestOwnerRule.created_at.desc())
            .paginate(page=page, per_page=per_page, max_per_page=100))

def get_process_requests_page(page, per_page=20) -> dict:
    """Return all process requets by page"""
    return (RequestOwnerRule.query.filter(RequestOwnerRule.status != "pending")
            .order_by(RequestOwnerRule.updated_at.desc())
            .paginate(page=page, per_page=per_page, max_per_page=100))

def update_request_status(request_id, status):
    req = RequestOwnerRule.query.get(request_id)
    if req:
        req.status = status
        db.session.commit()
        return True
    return False

def get_request_by_id(request_id):
    if not request_id:
        return None
    return RequestOwnerRule.query.get(request_id)

def get_all_requests_one_rule_with_rule_id(_rule_id) -> list:
    """Get all the request with rule_id"""
    return RequestOwnerRule.query.filter(RequestOwnerRule.rule_id == _rule_id , RequestOwnerRule.rule_source == None , RequestOwnerRule.status == "pending").all()

def get_all_requests_with_source(_source) -> list:
    """Get all the request with source"""
    return RequestOwnerRule.query.filter(RequestOwnerRule.rule_source == _source , RequestOwnerRule.status == "pending").all()

def get_made_requests_page(page, per_page=20) -> dict:
    """Return all requests made by the current user, paginated."""
    return (RequestOwnerRule.query.filter(RequestOwnerRule.user_id == current_user.id)
            .order_by(RequestOwnerRule.created_at.desc())
            .paginate(page=page, per_page=per_page, max_per_page=100))

def get_total_requests_to_check() -> int:
    """Return the total count of pending requests for rules owned by the current user."""
    return RequestOwnerRule.query.filter(
        RequestOwnerRule.status == "pending",
        RequestOwnerRule.user_id_to_send == current_user.id
    ).count()

def get_requests_page_user(page, per_page=20) -> dict:
    """Return all 'pending' requests that are relevant to the current user, paginated."""
    return (RequestOwnerRule.query.filter(
        RequestOwnerRule.user_id_to_send == current_user.id,
        RequestOwnerRule.status == "pending"
    ).order_by(RequestOwnerRule.created_at.desc())
      .paginate(page=page, per_page=per_page, max_per_page=100))

def get_process_requests_page_user(page, per_page=20) -> dict:
    """Return all 'process' requests that are relevant to the current user, paginated."""
    return (RequestOwnerRule.query.filter(
        RequestOwnerRule.user_id_to_send == current_user.id,
        RequestOwnerRule.status != "pending"
    ).order_by(RequestOwnerRule.updated_at.desc())
      .paginate(page=page, per_page=per_page, max_per_page=100))

def is_the_owner(request_id) -> bool:
    """
    Return True if the current user is the owner of the single rule this
    request concerns.

    Source-scoped (bulk, multi-rule) requests are deliberately NOT
    self-approvable here — `source` is a free-text field any user can set on
    their own rule at creation time, so "is an editor of a rule with this
    source" used to mean "typed the same source string on a throwaway rule",
    letting anyone claim ownership of every rule sharing that source. Bulk
    transfers by source now always require an admin (both call sites already
    `or` this with `current_user.is_admin()` — see app/home.py), matching how
    the Manual Ownership admin tool handles the same kind of bulk transfer.
    """
    request = RequestOwnerRule.query.get(request_id)
    if not request:
        return False

    if request.rule_source is None:
        rule = RuleModel.get_rule(request.rule_id)
        if rule and rule.user_id == current_user.id:
            return True
        return False

    return False

def get_total_requests_to_check_admin() -> int:
    """Return the total count of requests with status 'pending'."""
    return RequestOwnerRule.query.filter_by(status="pending").count()


###################
#   Gamification  #
###################

def get_or_create_gamification_profile(user_id: int) -> Gamification:
    """Retrieves the Gamification profile for a user, or creates one if it doesn't exist."""
    user = get_user(user_id)
    if not user:
        return None
    
    profile = Gamification.query.filter_by(user_id=user_id).first()
    if not profile:
        profile = Gamification(user_id=user_id, uuid=str(uuid.uuid4()))
        db.session.add(profile)
        db.session.commit()
    return profile

def update_rules_suggestion_gamification(gamification_id: int, user_id: int) -> None:
    try:
        if not gamification_id:
            return False
        if not user_id:
            return False
        gamification = get_gamification_by_id(gamification_id)
        if not gamification:
            return
        
        # found in RuleUpdateHistory table all the update accepted. Onlythe ruleHistorye from the user
        rules_history = RuleEditProposal.query.filter_by(user_id=user_id).all()
        if rules_history: # just update one time the value because in the good way we have the good value
            suggestions_submitted = 0
            suggestions_accepted = 0
            suggestions_rejected = 0
            for rule_history in rules_history:
                if rule_history.status == "accepted":
                    suggestions_accepted = suggestions_accepted + 1
                elif rule_history.status == "rejected":
                    suggestions_rejected = suggestions_rejected + 1
                else:
                    suggestions_submitted = suggestions_submitted + 1

            gamification.suggestions_submitted = suggestions_submitted
            gamification.suggestions_accepted = suggestions_accepted
            gamification.suggestions_rejected = suggestions_rejected

        db.session.commit()
        return True
    except Exception as e:
        return False

def get_gamification_by_id(gamification_id: int) -> Gamification:
    return Gamification.query.get(gamification_id)


def apply_vote_gamification(voter_gamif_id, rule_owner_id, like_delta, dislike_delta):
    """
    Update gamification for voter and rule owner in a single commit.
    like_delta / dislike_delta: -1, 0, or +1
    """
    try:
        voter_gamif = get_gamification_by_id(voter_gamif_id)
        if voter_gamif:
            voter_gamif.rules_liked    = max(0, (voter_gamif.rules_liked    or 0) + like_delta)
            voter_gamif.rules_disliked = max(0, (voter_gamif.rules_disliked or 0) + dislike_delta)

        owner_gamif = Gamification.query.filter_by(user_id=rule_owner_id).first()
        if not owner_gamif:
            owner_gamif = Gamification(user_id=rule_owner_id, uuid=str(uuid.uuid4()))
            db.session.add(owner_gamif)

        total_rules = RuleModel.get_count_rules_by_user_id(rule_owner_id)
        owner_gamif.rules_owned = total_rules

        votes = get_user_votes_summary(rule_owner_id)
        popular_score = max(0, votes['total_upvotes'] - votes['total_downvotes'])
        owner_gamif.rules_popular_score = popular_score

        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False

#-----------
#   Like
#-----------

def update_like_gamification(gamification_id, action) -> None:
    """Increment the like section"""
    try:
        if not gamification_id:
            return
        gamification = get_gamification_by_id(gamification_id)
        if action == "add_one_to_like":
            gamification.rules_liked = gamification.rules_liked + 1
        elif action == "remove_one_to_like":
            gamification.rules_liked = gamification.rules_liked - 1
        elif action == "add_one_to_dislike":
            gamification.rules_disliked = gamification.rules_disliked + 1
        elif action == "remove_one_to_dislike":
            gamification.rules_disliked = gamification.rules_disliked - 1
        db.session.commit()
        
        return True
    except Exception as e:
        return False


#-----------
#   Suggest
#-----------

def update_propose_edit_gamification(gamification_id, action) -> None:
    """Increment the suggestion section"""
    try:
        if not gamification_id:
            return
        gamification = get_gamification_by_id(gamification_id)

        if action == "add_one_to_suggested":
            gamification.suggestions_submitted = gamification.suggestions_submitted + 1
        elif action == "add_one_to_accepted":
            gamification.suggestions_accepted = gamification.suggestions_accepted + 1
        elif action == "add_one_to_rejected":
            gamification.suggestions_rejected = gamification.suggestions_rejected + 1
           
        
        db.session.commit()
        
        return True
    except Exception as e:
        return False
    
#--------------
# Rules owned
#--------------
def update_rules_owned_gamification(gamification_id , user_id) -> None:
   """Update the value for the rules owned section"""
   try:
        if not gamification_id:
            return False
        if not user_id:
            return False
        
        # get the total number of rules for the user
        total_rules = RuleModel.get_count_rules_by_user_id(user_id)

        gamification = get_gamification_by_id(gamification_id)
        if not gamification:
            return False

        gamification.rules_owned = total_rules


        db.session.commit()

        # update the total points of rules_popular_score 
        # get the total number of like and dislike (rule/bundle)for the user
        dict = get_user_votes_summary(user_id)
        if not dict:
            
            return False
        total_like = dict['total_upvotes']
        total_dislike = dict['total_downvotes']

        # calcule of the popular score
        popular_score = total_like  - total_dislike 
        
        if popular_score < 0:
            popular_score = 0
        gamification.rules_popular_score = popular_score
       
        db.session.commit()

       
        
        return True
   except Exception as e:
        return False
   



_LEADERBOARD_SORT_COLUMNS = {
    'total_points':           Gamification.total_points,
    'suggestions_accepted':   Gamification.suggestions_accepted,
    'rules_owned':            Gamification.rules_owned,
    'rules_popular_score':    Gamification.rules_popular_score,
    'last_contribution_date': Gamification.last_contribution_date,
}

_ACTIVE_SINCE_DAYS = {'week': 7, 'month': 30, 'year': 365}


def get_leaderboard_paginated(page: int, per_page: int, sort_by: str = 'total_points',
                               direction: str = 'desc', search: str = None,
                               active_since: str = None) -> dict:
    """Generic paginated/sortable/searchable Gamification leaderboard — the
    single source for the Global Ranking, Quality Masters, and Popularity
    Leaders tables, which just differ by default sort column.

    `rank` is computed with a window function over the FULL sort order
    before any search/date filtering is applied, so a name search never
    shifts what number shows next to a contributor — it only changes which
    rows are visible, never their true position.
    """
    col = _LEADERBOARD_SORT_COLUMNS.get(sort_by, Gamification.total_points)
    order_expr = col.desc() if direction == 'desc' else col.asc()

    ranked = db.session.query(
        Gamification.id.label('gid'),
        func.row_number().over(order_by=order_expr).label('rank'),
    ).subquery()

    query = (
        db.session.query(Gamification, ranked.c.rank)
        .join(User)
        .join(ranked, ranked.c.gid == Gamification.id)
    )

    if search:
        pattern = f"%{search}%"
        query = query.filter(or_(
            User.first_name.ilike(pattern), User.last_name.ilike(pattern), User.username.ilike(pattern),
        ))

    if active_since in _ACTIVE_SINCE_DAYS:
        cutoff = datetime.datetime.utcnow() - timedelta(days=_ACTIVE_SINCE_DAYS[active_since])
        query = query.filter(Gamification.last_contribution_date >= cutoff)

    query = query.order_by(order_expr)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    leaderboard_data = []
    for stats, rank in pagination.items:
        leaderboard_data.append({
            "user_id": stats.user_id,
            "first_name": stats.user.first_name,
            "last_name": stats.user.last_name,
            "username": stats.user.get_username(),
            "avatar": stats.user.get_avatar_url(),
            "rank": rank,
            "total_points": stats.total_points,
            "suggestions_accepted": stats.suggestions_accepted,
            "rules_owned": stats.rules_owned,
            "rules_popular_score": stats.rules_popular_score,
            "last_contribution_date": (
                stats.last_contribution_date.strftime('%Y-%m-%d') if stats.last_contribution_date else None
            ),
        })

    return {
        "leaderboard": leaderboard_data,
        "total_pages": pagination.pages,
        "current_page": pagination.page,
        "total_items": pagination.total,
    }

def get_user_contributions_data(user_id: int) -> dict:
    """
    Retrieves a single user's stats, excluding badges.
    """
    stats = Gamification.query.filter_by(user_id=user_id).first()
    
    if not stats:
        return {"user_stats": None}

    return {
        "user_stats": stats.to_json(),
    }

def refreshData(action):
    """Recup all the user or just the user's stats"""
    if action == "global":
        # update data for the global leaderboard
        error = 0
        for user in User.query.all():
            data = get_or_create_gamification_profile(user.id)
            if not data:
                error = error + 1
        if error > 0:
            return False
        else:
            return True

    else:
        # update data for the my contributions
        data = get_or_create_gamification_profile(current_user.id)
        if not data:
            return False
        return True
    
def update_liked_gamification(gamification_id , user_id) -> bool:
    """See in RuleVote and in BundleVote all the like and dislike create by the user"""
    try:
        if not gamification_id:
            return False
        if not user_id:
            return False
        
       # like and dislike for the user
        dict = get_user_votes_summary(user_id)
        if not dict:
            return False
        total_like = dict['total_upvotes']
        total_dislike = dict['total_downvotes']

        # calcule of the popular score
        popular_score = total_like  - total_dislike 
        
        if popular_score < 0:
            popular_score = 0
        gamification = get_gamification_by_id(gamification_id)
        if not gamification:
            return False
        gamification.rules_popular_score = popular_score
        db.session.commit()

        return True
    except Exception as e:
        return False
    
def update_gamification_profiles():
    """Update the gamification profiles for all users"""
    users = User.query.all()
    for user in users:
        # update the user with the reel value like If someone has already like or propose an edit
        user_gamification = get_or_create_gamification_profile(user.id)
        if user_gamification:
            # found all the like oand dislike of an user in 
            s = update_rules_owned_gamification(user_gamification.id, user.id)
            if not s:
                pass
            # found RuleSuggestion
            s_ = update_rules_suggestion_gamification(user_gamification.id, user.id)
            if not s_:
                pass    
            s__ = update_liked_gamification(user_gamification.id, user.id)
            if not s__:
                pass
            
        else:
            return False

    return True


def get_total_users():
    return User.query.count()