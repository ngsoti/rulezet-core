from flask_restx import Namespace, Resource
from flask import jsonify, request, url_for
from flask_login import  current_user, login_required
from wtforms.validators import Email, ValidationError

from app.utils.utils import get_user_from_api

from app.db_class.db import User
from app.account import account_core as AccountModel
from ...rule import rule_core as RuleModel

account_private_ns = Namespace(
    "Private account action 🔑 (with api key)",
    description="Private account operations"
)   

@account_private_ns.route('/edit')
class EditUser(Resource):
    @login_required
    def post(self):
        data = request.get_json(silent=True)
        if not data:
            data = request.args.to_dict()
        user = get_user_from_api(request.headers)
        if not user:
            return {"message": "Access denied"}, 403
        
        first_name = data.get("first_name")
        last_name = data.get("last_name")
        email = data.get("email")

        for field_name, value in [("first_name", first_name), ("last_name", last_name), ("email", email)]:
            if not value:
                return {"message": f"{field_name} is required"}, 400

        try:
            Email(message="Invalid email format")(None, type("DummyField", (), {"data": email})())
        except ValidationError:
            return {"message": "Invalid email format"}, 400



        if email != current_user.email:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                return {
                    "message": (
                        f"Email already registered. "
                        f'(Did you mean to <a href="{url_for("account.index")}">log in</a> instead?)'
                    )
                }, 409

        if data.get("password"):    
            password = data.get("password")
            if len(password) < 8 or len(password) > 64:
                return {"message": "Password must be between 8 and 64 characters."}, 400
            if not any(c.isupper() for c in password):
                return {"message": "Password must contain at least one uppercase letter."}, 400
            if not any(c.islower() for c in password):
                return {"message": "Password must contain at least one lowercase letter."}, 400
            if not any(c.isdigit() for c in password):
                return {"message": "Password must contain at least one digit."}, 400
            if not any(c in '@$!%*?&' for c in password):
                return {"message": "Password must contain at least one special character (@$!%*?&)."}, 400 
       
            form_dict = {
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "password": password
            }
        else:
            form_dict = {
                "email": email,
                "first_name": first_name,
                "last_name": last_name
            }

        AccountModel.edit_user_core(form_dict, current_user.id)

        return {"message": "User updated successfully"}, 200

@account_private_ns.route("/favorite/get_rules_page_favorite")
class GetRulesPageFavorite(Resource):
    @login_required
    def get(self):
        page = request.args.get('page', 1, type=int)
        
        rules = RuleModel.get_rules_page_favorite(page, current_user.id)

        if rules:
            return jsonify({
                "rule": [rule.to_json() for rule in rules],
                "total_pages": rules.pages
            })
        return jsonify({"message": "No Rule"}), 403
    
@account_private_ns.route("/favorite/delete_rule")
class RemoveRuleFavorite(Resource):
    @login_required 
    def post(self):
        rule_id = request.args.get('id', 1, type=int)
        
        rep = AccountModel.remove_favorite(current_user.id, rule_id)

        if rep:
            return jsonify({"success": True, "message": "Rule deleted!"})
        return jsonify({"success": False, "message": "Access denied"}), 403
    
