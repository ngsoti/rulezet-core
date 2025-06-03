import json
from flask import  Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask import get_flashed_messages
from flask_login import login_required, current_user
from .rule import rule_core as RuleModel
from .account import account_core as AccountModel


home_blueprint = Blueprint(
    'home',
    __name__,
    template_folder='templates',
    static_folder='static'
)

#####################
#   Alert section   #
#####################

@home_blueprint.route("/request_to_check")
def inject_requests_to_validate() -> jsonify:
    """Get the number of  request to validate"""
    try:
        if current_user.is_admin():
            count = AccountModel.get_total_requests_to_check_admin()
        else:
            count = AccountModel.get_total_requests_to_check()
    except:
        count = 0
    return jsonify({"count": count})

###################
#   Home section  #
###################

@home_blueprint.route("/")
def home() -> render_template:
    """Go to home page"""
    get_flashed_messages()
    return render_template("home.html")

@home_blueprint.route("/get_last_rules", methods=['GET'])
def get_last_rules() -> dict:
    """Get the last 10 rules create or update"""
    rules = RuleModel.get_last_rules_from_db()
    if rules :
        return {
            'rules': [r.to_json() for r in rules],
            'success': True
        } , 200
    return {
        "message": "No rules",
        'success': False
    }

@home_blueprint.route("/get_current_user_connected", methods=['GET'])
def get_current_user_connected() -> jsonify:
    """Is the current user an admin to vue JS"""
    if current_user.is_authenticated:
        return jsonify({"is_authenticated": True, "user_id": current_user.id})
    else:
        return jsonify({"is_authenticated": False})

######################
#   Request section  #
######################

@home_blueprint.route("/owner_request", methods=["POST", "GET"])
@login_required
def owner_request() -> redirect:
    """Get all the request to validate"""
    choice = request.args.get('choice', 1, type=int)
    if choice == 1:
        # one rule
        rule_id = request.args.get('rule_id')
        if not rule_id:
            flash("No rule ID provided.", "danger")
            return redirect(url_for("home.home"))
        try:
            AccountModel.create_request(rule_id=rule_id, source="")
            flash("Ownership request submitted successfully.", "success")
        except Exception as e:
            flash("An error occurred while submitting the request.", "danger")
        return redirect(url_for("home.home"))
    elif choice == 2:
        # with source
        source = request.args.get('source')
        if not source:
            flash("No source provided.", "danger")
            return redirect(url_for("/"))
        rules = RuleModel.get_rule_by_source(source)
        if not rules:
            flash("Rule not found.", "danger")
            return redirect(url_for("home.home"))
        try:
            
            AccountModel.create_request(rule_id=None, source=source)
            
            flash("Ownership request submitted successfully.", "success")
        except Exception as e:
            flash("An error occurred while submitting the request.", "danger")
        return redirect(url_for("home.home"))
    else:
        flash("An error occurred while submitting the request.", "danger")
        return redirect(url_for("home.home"))

    



@home_blueprint.route("/admin/request", methods=["POST", "GET"])
@login_required
def admin_requests() -> render_template:
    """Redirect to request section"""
    return render_template("admin/request.html")




@home_blueprint.route("/get_requests_page", methods=['GET'])
@login_required
def get_requests_page() -> json:
    """Get all the request in a page"""
    page = request.args.get('page', 1, type=int)
    if current_user.is_admin():
        requests_paginated = AccountModel.get_requests_page(page)
    else:
        requests_paginated = AccountModel.get_requests_page_user(page)
    total_requests = AccountModel.get_total_requests_to_check_admin()
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
    return {"message": "No requests found"}





@home_blueprint.route("/update_request", methods=["POST","GET" ])
@login_required
def update_request_status() -> jsonify:
    """Update the request for vue JS"""
    request_id = request.args.get('request_id')
    status = request.args.get('status')
    
    is_the_owner = AccountModel.is_the_owner(request_id)
    
    if current_user.is_admin() or is_the_owner:
        updated = AccountModel.update_request_status(request_id, status)
        if updated and status == "approved":
            ownership_request = AccountModel.get_request_by_id(request_id)

            if ownership_request.rule_source:
                # Request concerns a source
                # Get all rules for the specified source
                rules_from_source = RuleModel.get_rule_by_source(ownership_request.rule_source)
                if current_user.is_admin():
                    rules_from_source_of_reel_owner = RuleModel.get_rules_from_user(rules_from_source , ownership_request.user_id_to_send)
                    for rule in rules_from_source_of_reel_owner:
                        if rule.user_id == ownership_request.user_id_to_send:
                            
                            # The rule belongs to the current user, give rights to the request's user
                            rule.user_id = ownership_request.user_id
                else:
                    for rule in rules_from_source:
                        if rule.user_id == current_user.id:
                            # The rule belongs to the current user, give rights to the request's user
                            rule.user_id = ownership_request.user_id



            else:
                
                # request for a rule
                rule_id_of_request = AccountModel.get_request_rule_id(request_id)
                user_id = AccountModel.get_request_user_id(request_id)

                if ownership_request:
                    rule = RuleModel.get_rule(rule_id_of_request)
                    if rule:
                        RuleModel.set_user_id(rule_id_of_request, user_id)
        return jsonify({"success": updated}), 200 if updated else 400
    else:
        return render_template("access_denied.html")



    
