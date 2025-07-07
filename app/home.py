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
            return {"success": False, "message": "No rule with this id!" , "toast_class" : "danger"}, 200
        rule = RuleModel.get_rule(rule_id)
        if current_user.id != rule.user_id:
            request_ = AccountModel.create_request(rule_id=rule_id, source="")
            if request_:
                return {"success": True, "message": "Ownership request submitted successfully !" , "toast_class" : "success"}, 200
        return {"success": False, "message": "You can create a request for your own rule !" , "toast_class" : "danger"}, 200
    elif choice == 2:
        # with source
        source = request.args.get('source')
        if not source:
            return {"success": False, "message": "No Source given !" , "toast_class" : "danger"}, 200
        rules = RuleModel.get_rule_by_source(source)
        if not rules:
            return {"success": False, "message": "No rule with this source!" , "toast_class" : "danger"}, 200
        AccountModel.create_request(rule_id=None, source=source)
        return {"success": True, "message": "Ownership request submitted successfully !" , "toast_class" : "success"}, 200
    else:
        return {"success": False, "message": "Error system" , "toast_class" : "danger"}, 500

    



@home_blueprint.route("/admin/request", methods=["POST", "GET"])
@login_required
def admin_requests() -> render_template:
    """Redirect to request section"""
    return render_template("admin/request.html")


@home_blueprint.route("/requests/<int:id>", methods=[ "GET"])
@login_required
def requests(id) -> render_template:
    """Redirect to request section"""
    return render_template("account/request_detail.html" , request_id=id)


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
            "success": True,
            "pending_requests_list": requests_list,
            "pending_totalPages": requests_paginated.pages,  
        } , 200
    return {"message": "No requests found"}

@home_blueprint.route("/get_process_requests_page", methods=['GET'])
@login_required
def get_process_requests_page() -> json:
    """Get all the request in a page"""
    page = request.args.get('page', 1, type=int)
    if current_user.is_admin():
        requests_paginated = AccountModel.get_process_requests_page(page)
    else:
        requests_paginated = AccountModel.get_process_requests_page_user(page)

    if requests_paginated.items:
        requests_list = []
        for r in requests_paginated.items:
            user = AccountModel.get_username_by_id(r.user_id)
            request_data = r.to_json()  
            
            request_data['user_name'] = user
            requests_list.append(request_data)
        return {
            "success": True,
            "process_requests_list": requests_list,
            "process_totalPages": requests_paginated.pages,  
        } , 200
    return {"message": "No requests found"}


@home_blueprint.route("/get_request", methods=['GET'])
@login_required
def get_request() -> json:
    """Get the request """
    request_id = request.args.get('request_id', 1, type=int)
    request_ = AccountModel.get_request_by_id(request_id)
    if request_:
        if current_user.is_admin() or request_.user_id_to_send == current_user.id:
            return {
                "success": True,
                "current_request": request_.to_json() 
            } , 200
        else:
            return {
                "success": False,
                "current_request": None 
            } , 200
    return {"message": "No requests found"}

@home_blueprint.route("/get_concerned_rule", methods=['GET'])
@login_required
def get_concerned_rule() -> json:
    """Get all the get_concerned_rule in a page"""
    request_id = request.args.get('request_id', 1, type=int)
    page = request.args.get('page', 1, type=int)

    request_ = AccountModel.get_request_by_id(request_id)
    
    if current_user.is_admin():
        if request_.rule_source:
            concerned_rules_list = RuleModel.get_concerned_rules_admin_page(request_.rule_source, page , request_.user_id_to_send)
            nb_rules = RuleModel.get_concerned_rule_admin_count(request_.rule_source, page , request_.user_id_to_send)
        else:
            concerned_rules_list = []
            rule = RuleModel.get_rule(request_.rule_id)
            concerned_rules_list.append(rule)
            nb_rules = 1
    else:
        if request_.rule_source:
            concerned_rules_list = RuleModel.get_concerned_rules_page(request_.rule_source, page)
            nb_rules = RuleModel.get_concerned_rule_count(request_.rule_source, page , request_.user_id_to_send)
        else:
            concerned_rules_list = []
            rule = RuleModel.get_rule(request_.rule_id)
            concerned_rules_list.append(rule)


    if concerned_rules_list:
        return {
            "success": True,
            "concerned_rules_list": [rule.to_json() for rule in concerned_rules_list],
            "Rules_totalPages": concerned_rules_list.pages if request_.rule_source else 1,
            "total_rules": nb_rules
        } , 200
    else:
        return {
            "success": False,
            "concerned_rules_list": [] 
        } , 200


@home_blueprint.route("/get_all_concerned_rules", methods=["GET"])
@login_required
def get_all_concerned_rules():
    request_id = request.args.get("request_id", type=int)

    if not request_id:
        return jsonify({"error": "Missing request_id"}), 400

    request_ = AccountModel.get_request_by_id(request_id)
    try:
        if current_user.is_admin():
            rules = RuleModel.get_concerned_rules_admin(request_.rule_source , request_.user_id_to_send)
            if len(rules) == 0:
                # not with source but only one rule
                rule_concerned = RuleModel.get_rule(request_.rule_id)
                rules.append(rule_concerned)
            result = [rule.to_json() for rule in rules]
            return jsonify({"all_concerned_rules": result})
        else:
            rules = RuleModel.get_concerned_rules(request_.rule_source)
            result = [rule.to_json() for rule in rules]
            return jsonify({"all_concerned_rules": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500





@home_blueprint.route("/update_request", methods=["POST" ])
@login_required
def update_request_status() -> jsonify:
    """Update the request for vue JS"""
    # request_id = request.args.get('request_id') 
    # status = request.args.get('status')
    # rule_list_json = request.args.get('rule_list')

    data = request.get_json()

    request_id = data.get('request_id')
    status = data.get('status')
    rule_ids = data.get('rule_list')
    # rule_list_json
    # try:
    #     rule_ids = json.loads(rule_list_json)
    # except Exception as e:
    #     rule_ids = []
   
    rules = RuleModel.get_rules_by_ids(rule_ids)


    is_the_owner = AccountModel.is_the_owner(request_id)
    
    if current_user.is_admin() or is_the_owner:
        updated = AccountModel.update_request_status(request_id, status)
        if updated and status == "approved":
            ownership_request = AccountModel.get_request_by_id(request_id)
            for rule in rules:
                if rule.user_id == current_user.id or current_user.is_admin():
                    rule.user_id = ownership_request.user_id
                    requests_list_to_update = AccountModel.get_all_requests_with_rule_id(rule.id)
                    if requests_list_to_update:
                        for request_ in requests_list_to_update:
                            request_.user_id_to_send = ownership_request.user_id
                    requests_list_to_update_source = AccountModel.get_all_requests_with_source(ownership_request.rule_source)
                    if requests_list_to_update_source:
                            for request__ in requests_list_to_update_source:
                                request__.user_id_to_send = ownership_request.user_id   
                

            flash(f"Request Accepted! {len(rules)} rules are impacted", "success")
        else:
            flash('Request decline with success!', 'success')
        return jsonify({"success": updated}), 200 if updated else 400
    else:
        return jsonify({"success": False}), 500


