from flask import Blueprint, jsonify, render_template, request, url_for
from flask_restx import Api, Resource
from flask_login import login_user, logout_user, current_user, login_required
from flask import request
from flask_restx import Resource
from wtforms.validators import Email, ValidationError
from flask_restx import Resource
from flask import request
from flask_login import login_user
from wtforms.validators import  Email
from app.db_class.db import User
from app.account import account_core as AccountModel
from app.utils.utils import get_user_from_api
from ..rule import rule_core as RuleModel

api_account_blueprint = Blueprint('api_account', __name__)
api = Api(api_account_blueprint,
    title='Account API',
    description='Endpoints for user management (login, register, profile, etc)',
    default='Account API',
    version="1.0",
    doc='/doc/'
)

@api.route('/register')
@api.doc(description='Add new user')
class Register(Resource):
    @api.doc(params={
        'email': 'User email', 
        'password': 'Password', 
        'first_name': 'First name', 
        'last_name': 'Last name'
    })
    def post(self):
        data = request.get_json(silent=True)
        if not data:
            data = request.args.to_dict()
        required_fields = ["email", "password", "first_name", "last_name"]
        if not all(field in data for field in required_fields):
            return {"message": "Missing fields in request"}, 400

        # Validate email format using WTForms Email validator
        try:
            Email(message="Invalid email format")(None, type("DummyField", (), {"data": data.get("email")})())
        except ValidationError as e:
            return {"message": "Invalid email"}, 400

        if User.query.filter_by(email=data.get("email")).first():
            return {"message": "Email already exists"}, 409

        # verify the password strength
        password = data.get("password")
        if len(password) < 8 or len(password) > 64:
            return {"message": "Password must be between 8 and 64 characters."}, 400
        if not any(c.isupper() for c in password):
            return {"message": "Password must contain at least one uppercase letter."}, 400
        if not any(c.islower() for c in password):
            return {"message": "Password must contain at least one lowercase letter."}, 400
        if not any(c.isdigit() for c in password):
            return {"message": "Password must contain at least one digit."}, 400
        
        form_dict = {
            'email': data.get("email"),
            'password': data.get("password"),
            'first_name': data.get("first_name"),
            'last_name': data.get("last_name"),
        }

        user = AccountModel.add_user_core(form_dict)
        return {"message": "User registered successfully",
                "X-API-KEY": user.api_key
                }, 201

# curl -X POST http://127.0.0.1:7009/api/account/register \
#     -H "Content-Type: application/json" \
#     -d '{
#         "email": "test@example.com",
#         "password": "password!!1A@",
#         "first_name": "Test",
#         "last_name": "User"
#     }'


@api.route('/login')
@api.doc(description='Connect an user')
class Login(Resource):
    @api.doc(params={
        'email': 'User email',
        'password': 'User password',
        'remember_me': 'Boolean to keep the user logged in'
    })
    def post(self):
        data = request.get_json(silent=True)
        if not data:
            data = request.args.to_dict()

        required_fields = ["email", "password"]
        if not all(field in data for field in required_fields):
            return {"message": "Missing fields in request"}, 400

        email = data.get('email')
        password = data.get('password')
        remember_me = data.get('remember_me', False)

        try:
            Email(message="Invalid email format")(None, type("DummyField", (), {"data": email})())
        except ValidationError:
            return {"message": "Invalid email"}, 400

        if not isinstance(remember_me, bool):
            return {"message": "remember_me must be a boolean"}, 400

        user = User.query.filter_by(email=email).first()
        if user and user.verify_password(password):
            login_user(user, remember=remember_me)
            return {"message": "Logged in successfully"}, 200
        return {"message": "Invalid email or password"}, 401


@api.route('/logout')
@api.doc(description='Logout an user')
class Logout(Resource):
    @login_required
    def post(self):
        logout_user()
        return {"message": "You have been logged out."}, 200
    

@api.route('/edit')
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

@api.route("/favorite/get_rules_page_favorite")
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
    
@api.route("/favorite/delete_rule")
class RemoveRuleFavorite(Resource):
    @login_required 
    def post(self):
        rule_id = request.args.get('id', 1, type=int)
        
        rep = AccountModel.remove_favorite(current_user.id, rule_id)

        if rep:
            return jsonify({"success": True, "message": "Rule deleted!"})
        return jsonify({"success": False, "message": "Access denied"}), 403
    
@api.route('/favorite')
class Favorite(Resource):
    @login_required
    def get(self):
        """Return the favorite page for the user."""
        return render_template("account/favorite_user.html"), 200

@api.route("/profil")
class Profil(Resource):
    @login_required
    def get(self):
        """Return the profile page for the user."""
        return render_template("account/account_index.html", user=current_user) , 200

