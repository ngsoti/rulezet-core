import uuid
import datetime

from flask_login import current_user
from sqlalchemy import case, func

from .. import db
from ..db_class.db import *



def add_rule_core(form_dict):
    title = form_dict["title"].strip()

    existing_rule = get_rule_by_title(title)
    if existing_rule:
        return False
    new_rule = Rule(
        format=form_dict["format"],
        title=title,
        license=form_dict["license"],
        description=form_dict["description"],
        uuid=str(uuid.uuid4()),
        source=form_dict["source"],
        author=form_dict["author"],
        version=form_dict["version"],
        user_id=current_user.id,
        creation_date = datetime.now(),
        last_modif = datetime.now(),
        vote_up=0,
        vote_down=0,
        to_string = form_dict["to_string"]
    )

    db.session.add(new_rule)
    db.session.commit()
    return True




def delete_rule_core(id):
    rule = get_rule(id)
    if rule:
        db.session.delete(rule)
        db.session.commit()
        return True
    else:
        return False


def edit_rule_core(form_dict, id) -> None:
    """Edit the rule in the DB"""
    rule = get_rule(id)

    rule.format = form_dict["format"]
    rule.title = form_dict["title"]
    rule.license = form_dict["license"]
    rule.description = form_dict["description"]
    rule.source = form_dict["source"]
    rule.version = form_dict["version"]
    rule.to_string = form_dict["to_string"]
    rule.last_modif = datetime.now()

    db.session.commit()

def increment_up(id):
    rule = get_rule(id)
    rule.vote_up = int(rule.vote_up) + 1
    db.session.commit()


def decrement_up(id):
    rule = get_rule(id)
    rule.vote_down = int(rule.vote_down) + 1
    db.session.commit()



def remove_one_to_increment_up(id):
    rule = get_rule(id)
    rule.vote_up = int(rule.vote_up) - 1
    db.session.commit()

def remove_one_to_decrement_up(id):
    rule = get_rule(id)
    rule.vote_down = int(rule.vote_down) - 1
    db.session.commit()



def get_rules_page(page):
    """Return all rules by page"""
    return Rule.query.paginate(page=page, per_page=1000, max_per_page=1700)






def get_rules_page_owner(page):
    """Return all owner rules by page where the user_id matches the current logged-in user"""
    return Rule.query.filter_by(user_id=current_user.id).paginate(page=page, per_page=1000, max_per_page=1700)

def get_total_rules_count_owner():
    """Return the total count of rules created by the current logged-in user"""
    return Rule.query.filter_by(user_id=current_user.id).count()

def get_rule(id):
    """Return the rule"""
    return Rule.query.get(id)

def get_rule_by_title(title):
    return Rule.query.filter_by(title=title).all()

def get_total_rules_count():
    return Rule.query.count()



def get_rule_user_id(rule_id: int):
    rule = Rule.query.filter_by(id=rule_id).first()
    if rule:
        return rule.user_id  
    return None  

def get_rules_page_favorite(page, id_user, per_page=10):
    favorites_query = (
        Rule.query
        .join(RuleFavoriteUser, Rule.id == RuleFavoriteUser.rule_id)
        .filter(RuleFavoriteUser.user_id == id_user)
        .order_by(RuleFavoriteUser.created_at.desc())
    )
    
    paginated_rules = favorites_query.paginate(page=page, per_page=per_page, error_out=False)
    return paginated_rules



def set_user_id(rule_id, user_id):
    rule = get_rule(rule_id)
    if rule:
        rule.user_id = user_id
        db.session.commit()  
        return True
    return False



def propose_edit_core(rule_id, proposed_content, message=None):
    if not proposed_content:
        return False
    rule = get_rule(rule_id)

    new_proposal = RuleEditProposal(
        rule_id=rule_id,
        user_id=current_user.id,
        proposed_content=proposed_content,
        message=message,
        old_content =rule.to_string
    )
    db.session.add(new_proposal)
    db.session.commit()
    return True



# def get_rules_edit_propose_page(page):
#     """Return all rules by page"""
#     return RuleEditProposal.query.paginate(page=page, per_page=60, max_per_page=70)

# def get_rules_edit_propose_page_pending(page):
#     return RuleEditProposal.query.filter_by(status='pending').paginate(
#         page=page,
#         per_page=60,
#         max_per_page=70
#     )

from sqlalchemy.orm import joinedload
def get_rules_edit_propose_page(page):
    """Return all rule proposals where the original rule belongs to current user"""
    return RuleEditProposal.query.join(Rule).filter(
        Rule.user_id == current_user.id
    ).options(joinedload(RuleEditProposal.rule)).paginate(
        page=page,
        per_page=60,
        max_per_page=70
    )

def get_rules_edit_propose_page_pending(page):
    """Return all pending rule proposals where the original rule belongs to current user"""
    return RuleEditProposal.query.join(Rule).filter(
        Rule.user_id == current_user.id,
        RuleEditProposal.status == 'pending'
    ).options(joinedload(RuleEditProposal.rule)).paginate(
        page=page,
        per_page=60,
        max_per_page=70
    )



def get_rule_proposal(id):
    """Return the rule"""
    return RuleEditProposal.query.get(id)

def set_to_string_rule(rule_id, proposed_content):
    try:
        rule = Rule.query.get(rule_id)
        if not rule:
            return {"message": "Rule not found"}, 404

        rule.to_string = proposed_content  
        db.session.commit()
        return {"message": "Rule updated successfully"}, 200

    except Exception as e:
        db.session.rollback()
        return {"message": "Error updating rule", "error": str(e)}, 500
    
def set_status(proposal_id, status):
    if status not in ['accepted', 'rejected']:
        return {'error': 'Statut invalide'}, 400

    proposal = RuleEditProposal.query.get(proposal_id)

    if not proposal:
        return {'error': 'Proposition non trouvée'}, 404

    proposal.status = status
    db.session.commit()

    return {'success': True, 'new_status': status}, 200



def get_last_rules_from_db(limit=10):
    return Rule.query.order_by(
        case(
            (Rule.creation_date > Rule.last_modif, Rule.creation_date),
            else_=Rule.last_modif
        ).desc()
    ).limit(limit).all()




# vote 

def has_already_vote(rule_id, user_id):
    vote =  RuleVote.query.filter_by(rule_id=rule_id, user_id=user_id).first()
    if vote:
        return True , vote.vote_type
    return False , None

def has_voted(vote,rule_id):
    user_id = current_user.id
    vote = RuleVote(rule_id=rule_id, user_id=user_id, vote_type=vote)
    db.session.add(vote)    
    db.session.commit()
    return True


def remove_has_voted(vote, rule_id):
    user_id = current_user.id
    existing_vote = RuleVote.query.filter_by(rule_id=rule_id, user_id=user_id, vote_type=vote).first()

    if existing_vote:
        db.session.delete(existing_vote)
        db.session.commit()
        return True 

    return False 



def search_rules(user_id, query):
    return Rule.query.filter(
        Rule.user_id == user_id,
        (Rule.title.ilike(f"%{query}%") | 
         Rule.description.ilike(f"%{query}%") |
         Rule.author.ilike(f"%{query}%"))
    ).all()