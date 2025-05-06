from flask_login import current_user

from .. import db
from app.db_class.db import Request
import datetime

def create_request(rule, user_id, current_user):
    """Create or update an ownership request."""
    existing_request = Request.query.filter_by(user_id=user_id, title=f"Request for ownership of rule {rule.id} - {rule.title} by {rule.author}").first()

    if existing_request:
        existing_request.user_id_owner_rule = rule.user_id
        existing_request.content = f"{current_user.first_name} {current_user.last_name} (ID: {current_user.id}) wants to become the owner of '{rule.title}'"
        existing_request.status = "pending"
        existing_request.updated_at = datetime.datetime.now(tz=datetime.timezone.utc)
        db.session.commit()
        return existing_request


    new_request = Request(
        user_id_owner_rule = rule.user_id,
        user_id=user_id,
        title=f"Request for ownership of rule {rule.id} - {rule.title} by {rule.author}",
        content=f"{current_user.first_name} {current_user.last_name} (ID: {current_user.id}) wants to become the owner of '{rule.title}'",
        status="pending",
        created_at=datetime.datetime.now(tz=datetime.timezone.utc),
        updated_at=datetime.datetime.now(tz=datetime.timezone.utc),
        rule_id=rule.id
    )
    db.session.add(new_request)
    db.session.commit()
    return new_request


def get_requests_page(page):
    """Return all requets by page"""
    return Request.query.paginate(page=page, per_page=60, max_per_page=70)

def update_request_status(request_id, status):
    req = Request.query.get(request_id)
    if req:
        req.status = status
        db.session.commit()
        return True
    return False

def delete_request(request_id):
    req = Request.query.get(request_id)
    if req:
        db.session.delete(req)
        db.session.commit()
        return True
    return False

def get_request_by_id(request_id):
    if not request_id:
        return None
    return Request.query.get(request_id)

def get_request_rule_id(request_id):
    if not request_id:
        return None
    request_obj = Request.query.get(request_id)
    return request_obj.rule_id if request_obj else None

def get_request_user_id(request_id):
    request_obj = Request.query.get(request_id)
    if request_obj:
        return request_obj.user_id
    return None


def get_total_requests_to_check():
    """Return the total count of pending requests for rules owned by the current user."""
    return Request.query.filter(
        Request.status == "pending",
        Request.user_id_owner_rule == current_user.id
    ).count()


def get_requests_page_user(page):
    """Return all requests for the current user filtered by user_id_owner_rule"""
    return Request.query.filter(Request.user_id_owner_rule == current_user.id).paginate(page=page, per_page=60, max_per_page=70)


def is_the_owner(request_id):
    """Return True if the current user is the owner of the request"""
    request = Request.query.get(request_id)
    if request and request.user_id_owner_rule == current_user.id:
        return True
    return False


def get_total_requests_to_check_admin():
    """Return the total count of requests with status 'pending'."""
    return Request.query.filter_by(status="pending").count()
