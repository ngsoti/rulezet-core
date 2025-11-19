# ------------------------------------------------------------------------------------------------------------------- #
#                                               PUBLIC ENDPOINT                                                       #
# ------------------------------------------------------------------------------------------------------------------- #
from flask_restx import Namespace, Resource
from flask import request
from flask_login import login_user, logout_user, login_required
from wtforms.validators import Email, ValidationError


from app.db_class.db import User
from app.account import account_core as AccountModel
from flask_restx import Namespace, Resource

account_public_ns = Namespace(
    "Public account action ✅",
    description="Public account operations"
)

###################
#   TEST  public  #
###################


@account_public_ns.route('/register')
@account_public_ns.doc(description='Add new user')
class Register(Resource):
    @account_public_ns.doc(params={
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


@account_public_ns.route('/login')
@account_public_ns.doc(description='Connect an user')
class Login(Resource):
    @account_public_ns.doc(params={
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


@account_public_ns.route('/logout')
@account_public_ns.doc(description='Logout an user')
class Logout(Resource):
    @login_required
    def post(self):
        logout_user()
        return {"message": "You have been logged out."}, 200

