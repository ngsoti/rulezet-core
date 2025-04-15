from .. import db
from ..db_class.db import RuleFavoriteUser, User, Rule
from datetime import datetime

# CREATE

def add_favorite(user_id: int, rule_id: int) -> RuleFavoriteUser:
    """Adds a rule to the user's favorites"""
    exists = is_rule_favorited_by_user(user_id=user_id, rule_id=rule_id)
    if not exists:
        favorite = RuleFavoriteUser(user_id=user_id, rule_id=rule_id, created_at=datetime.now())
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
    """Deletes a favorite if found"""
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
