import datetime
from flask_login import current_user
from sqlalchemy import or_
from .. import db
from ..db_class.db import RequestOwnerRule, Rule, RuleFavoriteUser, User
from ..utils.utils import generate_api_key
from ..rule import rule_core as RuleModel

#####################
#   User actions    #
#####################

# CRUD

# Create

def add_user_core(form_dict) -> User :
    """Add a user to the DB"""
    user = User(
        first_name=form_dict["first_name"],
        last_name=form_dict["last_name"],
        email=form_dict["email"],
        password=form_dict["password"],
        api_key = form_dict["key"] or generate_api_key()
    )
    db.session.add(user)
    db.session.commit()

    return user

# Update

def edit_user_core(form_dict, id) -> None:
    """Edit the user to the DB"""
    user = get_user(id)
    user.first_name=form_dict["first_name"]
    user.last_name=form_dict["last_name"]
    user.email=form_dict["email"]

    db.session.commit()

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
    """Delete the user to the DB"""
    # give the right to admin 
    rules = RuleModel.get_rules_of_user_with_id(id)
    RuleModel.give_all_right_to_admin(rules)

    user = get_user(id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return True
    else:
        return False

# Read

def get_default_user()-> id:
    """Return the default user"""
    return User.query.filter_by(email='default@default.default').first()

def get_user(id) -> id:
    """Return the user"""
    return User.query.get(id)

def get_user_rules(user_id: int) -> list:
    """Return all rules created by the user."""
    return Rule.query.filter_by(user_id=user_id).all()

def get_user_votes_summary(user_id: int) -> dict:
    """Return the total vote_up and vote_down from all rules created by the user."""
    rules = get_user_rules(user_id)
    return {
        "total_upvotes": sum(r.vote_up or 0 for r in rules),
        "total_downvotes": sum(r.vote_down or 0 for r in rules)
    }

def get_user_rule_formats(user_id: int) -> list:
    """Return the list of unique formats used by the user in their rules."""
    rules = get_user_rules(user_id)
    return list(set(r.format for r in rules if r.format))

def get_user_favorite_rules(user_id: int) -> list:
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
        "formats_used": formats,
        "favorite_rule_ids": favorites,
        "rule_detail": types.get_json()
    }



def get_all_users() -> range:
    """Return all users"""
    return User.query.all()

def get_users_page_filter(page, search=None, connected=None, admin=None):
    """Get paginated users with optional filters"""
    per_page = 10
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


def get_count_users() -> int:
    """Return the count of all users"""
    return User.query.count()

def get_users_page(page) -> range:
    """Return all users by page"""
    return User.query.paginate(page=page, per_page=20, max_per_page=50)

def get_user_by_lastname(lastname) -> str:
    """Return user's lastname"""
    return User.query.filter_by(last_name=lastname).all()

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
    exists = is_rule_favorited_by_user(user_id=user_id, rule_id=rule_id)
    if not exists:
        favorite = RuleFavoriteUser(user_id=user_id, rule_id=rule_id, created_at=datetime.datetime.now(tz=datetime.timezone.utc))
        db.session.add(favorite)
        db.session.commit()
        return favorite
    return exists

# READ

def get_favorite(fav_id: int) -> RuleFavoriteUser:
    """Retrieves a favorite by its ID"""
    return RuleFavoriteUser.query.get(fav_id)

def get_user_favorites(user_id: int):
    """Retrieves all favorite rules of a user"""
    return RuleFavoriteUser.query.filter_by(user_id=user_id).all()

def get_rule_favorited_by(rule_id: int):
    """Retrieves all users who favorited a rule"""
    return RuleFavoriteUser.query.filter_by(rule_id=rule_id).all()

def is_rule_favorited_by_user(user_id: int, rule_id: int) -> bool:
    """Checks if a rule is favorited by a user"""
    return RuleFavoriteUser.query.filter_by(user_id=user_id, rule_id=rule_id).first() is not None

def get_rules_favorites_page(page):
    """Returns all rules by page"""
    return RuleFavoriteUser.query.paginate(page=page, per_page=3, max_per_page=3)



# DELETE

def remove_favorite(user_id: int, rule_id: int) -> bool:
    """Delete a favorite if found"""
    favorite = RuleFavoriteUser.query.filter_by(user_id=user_id, rule_id=rule_id).first()
    if favorite:
        db.session.delete(favorite)
        db.session.commit()
        return True
    return False

def get_all_user_favorites_with_rules(user_id: int):
    """Retrieves all favorite rules of a user with rule information"""
    favorites = RuleFavoriteUser.query.filter_by(user_id=user_id).all()
    rules_list = []
    
    for fav in favorites:
        rule = Rule.query.get(fav.rule_id)
        if rule:
            rules_list.append(rule)  
    
    return rules_list


#######################
#   Request Section   #
#######################

def create_request(rule, user_id, current_user):
    """Create or update an ownership request."""
    existing_request = RequestOwnerRule.query.filter_by(user_id=user_id, title=f"Request for ownership of rule {rule.id} - {rule.title} by {rule.author}").first()

    if existing_request:
        existing_request.user_id_owner_rule = rule.user_id
        existing_request.content = f"{current_user.first_name} {current_user.last_name} (ID: {current_user.id}) wants to become the owner of '{rule.title}'"
        existing_request.status = "pending"
        existing_request.updated_at = datetime.datetime.now(tz=datetime.timezone.utc)
        db.session.commit()
        return existing_request


    new_request = RequestOwnerRule(
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
    return RequestOwnerRule.query.paginate(page=page, per_page=20, max_per_page=20)

def update_request_status(request_id, status):
    req = RequestOwnerRule.query.get(request_id)
    if req:
        req.status = status
        db.session.commit()
        return True
    return False

def delete_request(request_id):
    req = RequestOwnerRule.query.get(request_id)
    if req:
        db.session.delete(req)
        db.session.commit()
        return True
    return False

def get_request_by_id(request_id):
    if not request_id:
        return None
    return RequestOwnerRule.query.get(request_id)

def get_request_rule_id(request_id):
    if not request_id:
        return None
    request_obj = RequestOwnerRule.query.get(request_id)
    return request_obj.rule_id if request_obj else None

def get_request_user_id(request_id):
    request_obj = RequestOwnerRule.query.get(request_id)
    if request_obj:
        return request_obj.user_id
    return None


def get_total_requests_to_check():
    """Return the total count of pending requests for rules owned by the current user."""
    return RequestOwnerRule.query.filter(
        RequestOwnerRule.status == "pending",
        RequestOwnerRule.user_id_owner_rule == current_user.id
    ).count()


def get_requests_page_user(page):
    """Return all requests for the current user filtered by user_id_owner_rule"""
    return RequestOwnerRule.query.filter(RequestOwnerRule.user_id_owner_rule == current_user.id).paginate(page=page, per_page=60, max_per_page=70)


def is_the_owner(request_id):
    """Return True if the current user is the owner of the request"""
    request = RequestOwnerRule.query.get(request_id)
    if request and request.user_id_owner_rule == current_user.id:
        return True
    return False


def get_total_requests_to_check_admin():
    """Return the total count of requests with status 'pending'."""
    return RequestOwnerRule.query.filter_by(status="pending").count()