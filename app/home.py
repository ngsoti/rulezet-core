from datetime import datetime, timezone
from flask import Flask, Blueprint, Response, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask import get_flashed_messages
from flask_login import login_required, current_user


from app.comment.comment_core import add_comment_core, delete_comment, get_comment_by_id,  get_latest_comment_for_user_and_rule,  update_comment
from app.db_class.db import Rule, RuleFavoriteUser
from app.favorite.favorite_core import add_favorite




from app.rule.rule_form import EditRuleForm
from app.utils.utils import form_to_dict
from .rule import rule_core as RuleModel
from .favorite import favorite_core as FavoriteModel
from .comment import comment_core as CommentModel
from .request import request_core as RequestModel




home_blueprint = Blueprint(
    'home',
    __name__,
    template_folder='templates',
    static_folder='static'
)

#-----------------------------------------------------------Rules_pages_home-----------------------------------------------------------#

@home_blueprint.route("/request_to_check")
def inject_requests_to_validate():
    try:
        if current_user.is_admin():
            count = RequestModel.get_total_requests_to_check_admin()
        else:
            count = RequestModel.get_total_requests_to_check()
    except:
        count = 0
    return jsonify({"count": count})







@home_blueprint.route("/")
def home():
    # list all the rules
    get_flashed_messages()
    return render_template("home.html")


@home_blueprint.route("/get_last_rules", methods=['GET'])
def get_last_rules():
    rules = RuleModel.get_last_rules_from_db()
    return jsonify({'rules': [r.to_json() for r in rules]})

@home_blueprint.route("/get_current_user_connected", methods=['GET', 'POST'])
def get_current_user_connected():
    if current_user.is_authenticated:
        return jsonify({"is_authenticated": True, "user_id": current_user.id})
    else:
        print(current_user.is_authenticated)
        return jsonify({"is_authenticated": False})


#-----------------------------------------------------------request_part-----------------------------------------------------------#

@home_blueprint.route("/owner_request", methods=["POST", "GET"])
@login_required
def owner_request():
    rule_id = request.args.get('rule_id')
    if not rule_id:
        flash("No rule ID provided.", "danger")
        return redirect(url_for("home.home"))

    rule = RuleModel.get_rule(rule_id)
    if not rule:
        flash("Rule not found.", "danger")
        return redirect(url_for("home.home"))

    try:
        request_rule = RequestModel.create_request(rule, current_user.id, current_user)
        flash("Ownership request submitted successfully.", "success")
    except Exception as e:
        print(f"Error creating request: {e}")
        flash("An error occurred while submitting the request.", "danger")

    return redirect(url_for("home.home"))

@home_blueprint.route("/admin/request", methods=["POST", "GET"])
@login_required
def admin_requests():
    return render_template("admin/request.html")


@home_blueprint.route("/get_requests_page", methods=['GET'])
@login_required
def get_requests_page(): 
    page = request.args.get('page', 1, type=int)
    if current_user.is_admin():
        requests_paginated = RequestModel.get_requests_page(page)
    else:
        requests_paginated = RequestModel.get_requests_page_user(page)
    total_requests = RequestModel.get_total_requests_to_check_admin()

    if requests_paginated.items:
        requests_list = []
        
        for r in requests_paginated.items:
            user = AccountModel.get_username_by_id(r.user_id)
            request_data = r.to_json()  
            
            request_data['user_name'] = user
            requests_list.append(request_data)
        return {
            "requests_list": requests_list,
            "requests_pages": requests_paginated.pages,  
            "total_requests": total_requests
        }
    
    return {"message": "No requests found"}, 404

from .account import account_core as AccountModel





@home_blueprint.route("/update_request", methods=["POST", "GET"])
@login_required
def update_request_status():
    request_id = request.args.get('request_id')
    status = request.args.get('status')
    is_the_owner = RequestModel.is_the_owner(request_id)
    if current_user.is_admin() or is_the_owner:
        updated = RequestModel.update_request_status(request_id, status)
        
        if updated and status == "approved":
            ownership_request = RequestModel.get_request_by_id(request_id)
            rule_id_of_request = RequestModel.get_request_rule_id(request_id)
            user_id = RequestModel.get_request_user_id(request_id)

            if ownership_request:
                rule = RuleModel.get_rule(rule_id_of_request)
                if rule:
                    # modifie the owner of the rule by the admin
                    response = RuleModel.set_user_id(rule_id_of_request, user_id)


        return jsonify({"success": updated}), 200 if updated else 400
    else:
        return render_template("access_denied.html")



    