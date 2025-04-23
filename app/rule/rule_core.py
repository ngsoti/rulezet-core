import uuid
import datetime

from flask_login import current_user

from .. import db
from ..db_class.db import *



def add_rule_core(form_dict):
    title = form_dict["title"].strip()

    existing_rule = get_rule_by_title(title)
    print(title)
    if existing_rule:
        return False
    print("je suis ici")
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
    print("ma regle ")

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

    db.session.commit()

def increment_up(id):
    rule = get_rule(id)
    rule.vote_up = int(rule.vote_up) + 1
    db.session.commit()


def decrement_up(id):
    rule = get_rule(id)
    rule.vote_down = int(rule.vote_down) + 1
    db.session.commit()



def get_rules_page(page):
    """Return all rules by page"""
    return Rule.query.paginate(page=page, per_page=60, max_per_page=70)

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
    """
    Récupère les règles favorites d'un utilisateur avec pagination.
    
    :param page: Numéro de page.
    :param id_user: ID de l'utilisateur.
    :param per_page: Nombre d'éléments par page.
    :return: Objet pagination contenant les règles.
    """
    favorites_query = (
        Rule.query
        .join(RuleFavoriteUser, Rule.id == RuleFavoriteUser.rule_id)
        .filter(RuleFavoriteUser.user_id == id_user)
        .order_by(RuleFavoriteUser.created_at.desc())
    )
    
    paginated_rules = favorites_query.paginate(page=page, per_page=per_page, error_out=False)
    return paginated_rules



def set_user_id(rule_id, user_id):
    """
    Met à jour l'ID utilisateur pour la règle spécifiée.
    
    :param rule_id: ID de la règle à mettre à jour.
    :param user_id: Nouveau ID de l'utilisateur.
    :return: True si la mise à jour est effectuée, sinon False.
    """
    rule = get_rule(rule_id)
    if rule:
        rule.user_id = user_id
        db.session.commit()  
        return True
    return False
