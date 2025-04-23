from .. import db
from app.db_class.db import Request
from datetime import datetime

def create_request(rule, user_id, current_user):
    """Create or update an ownership request."""


    existing_request = Request.query.filter_by(user_id=user_id, title=f"Request for ownership of rule {rule.id}").first()

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
        updated_at=datetime.utcnow()
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