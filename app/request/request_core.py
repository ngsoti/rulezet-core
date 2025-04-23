from .. import db
from app.db_class.db import Request
from datetime import datetime

def create_request(rule, user_id, current_user):
    """Create or update an ownership request."""


    existing_request = Request.query.filter_by(user_id=user_id, title=f"Request for ownership of rule {rule.title}").first()

    if existing_request:

        existing_request.content = f"{current_user.first_name} {current_user.last_name} (ID: {current_user.id}) wants to become the owner of '{rule.title}'"
        existing_request.status = "pending"
        existing_request.updated_at = datetime.utcnow()
        db.session.commit()
        return existing_request


    new_request = Request(
        user_id=user_id,
        title=f"Request for ownership of rule {rule.id}",
        content=f"{current_user.first_name} {current_user.last_name} (ID: {current_user.id}) wants to become the owner of '{rule.title}'",
        status="pending",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
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

def get_total_requests():
    """Return the total count of requests."""
    return Request.query.count()



def get_total_requests_to_check():
    """Return the total count of requests not check yet."""
    return Request.query.filter_by(status="pending").count()
