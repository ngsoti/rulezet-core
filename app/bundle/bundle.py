from flask import Blueprint, flash, redirect, render_template , request
from flask_login import current_user, login_required

from app.bundle.bundle_form import AddNewBundleForm, EditBundleForm
from app.utils.utils import form_to_dict
from . import bundle_core as BundleModel
from ..rule import rule_core as RuleModel

import io
import zipfile
import json
from flask import send_file, request

#############
#   Bundle  #
#############

bundle_blueprint = Blueprint(
    'bundle',
    __name__,
    template_folder='templates',    
    static_folder='static'
)

#############
#   Create  #
#############

@bundle_blueprint.route("/create", methods=['GET' , 'POST'])
@login_required
def create() :     
    """Create a bundle with form"""     
    form = AddNewBundleForm()
    if form.validate_on_submit():
        form_dict = form_to_dict(form)

        my_bundle = BundleModel.create_bundle(form_dict , current_user)
        if my_bundle:
            flash('Bundle created !', 'success')
            return render_template("bundle/edit_bundle.html", form=form, bundle=my_bundle )
        else:
            flash('Error to create', 'danger')
            return render_template("bundle/create_bundle.html", form=form )
        
    
    return render_template("bundle/create_bundle.html", form=form )

############
#   List   #
############

@bundle_blueprint.route("/list", methods=['GET' , 'POST'])
def list() :     
    """list all bundles"""     
    return render_template("bundle/list_bundle.html" )

@bundle_blueprint.route("/get_all_bundles", methods=['GET'])
def get_all_bundles() :     
    """get all bundles for pages"""     
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', type=str)
    bundles_list = BundleModel.get_all_bundles_page(page, search)
    total_bundles = BundleModel.get_total_bundles_count()
    if bundles_list:
        return {"bundle_list_": [r.to_json() for r in bundles_list],
                "total_pages": bundles_list.pages, 
                "total_bundles": total_bundles} , 200

    return {"message": "No Rule"} , 200

############
#  action  #
############

@bundle_blueprint.route("/delete", methods=['GET'])
@login_required
def delete() :     
    """Delete a bundle"""     
    bundle_id = request.args.get('id', 1, type=int)
    bundle = BundleModel.get_bundle_by_id(bundle_id)
    if current_user.id == bundle.user_id or current_user.is_admin():
        success_ = BundleModel.delete_bundle(bundle_id)
        if success_:
            return {"success": True, 
                    "message": "Bundle deleted !", 
                    "toast_class" : "success"}, 200
        return {"success": False, 
                    "message": "Deleted fail  !", 
                    "toast_class" : "danger"}, 500
    else:
        return {"success": False, 
                "message": "You don't have the permission to do that !", 
                "toast_class" : "danger"}, 401
    

@bundle_blueprint.route("/edit/<int:bundle_id>", methods=['GET' , 'POST'])
@login_required
def edit(bundle_id) :     
    """Edit a bundle"""     
    bundle = BundleModel.get_bundle_by_id(bundle_id)

    if current_user.id == bundle.user_id or current_user.is_admin():
        form = EditBundleForm(bundle_id=bundle_id)
        if form.validate_on_submit():
            form_dict = form_to_dict(form)
            BundleModel.update_bundle(bundle_id , form_dict)
            flash("Bundle modified with success!", "success")
            return redirect(request.referrer or '/')
        else:
            form.description.data = bundle.description
            form.name.data = bundle.name 

        return render_template("bundle/edit_bundle.html", form=form, bundle=bundle )
    else:
        return render_template("access_denied.html")
    
@bundle_blueprint.route("/detail/<int:bundle_id>", methods=['GET' , 'POST'])
def detail(bundle_id) :     
    """Go to detail of a bundle"""     
    return render_template("bundle/detail_bundle.html", bundle_id=bundle_id)
    

@bundle_blueprint.route("/get_all_rule", methods=['GET'])
def get_all_rule() :     
    """get all rule for a bundle"""     
    rules = RuleModel.get_rules()
    if rules:
        return {"success": True, 
                "rules": [r.to_json() for r in rules], 
                "toast_class" : "success"}, 200
    return {"success": False, 
                "message": "Deleted fail  !", 
                "toast_class" : "danger"}, 500


@bundle_blueprint.route("/add_rule_bundle", methods=['GET'])
@login_required
def add_rule_bundle() :     
    """Add a rule in a bundle"""     
    rule_id = request.args.get('rule_id',  type=int)
    bundle_id = request.args.get('bundle_id', type=int)
    description = request.args.get('description', type=str)

    bundle = BundleModel.get_bundle_by_id(bundle_id)

    if current_user.id == bundle.user_id or current_user.is_admin():
        if rule_id and bundle_id:
            success_ = BundleModel.add_rule_to_bundle(bundle_id , rule_id , description)
            if success_:
                return {"success": True, 
                        "message": "Rule added  !", 
                        "toast_class" : "success"}, 200
        return {"success": False, 
                    "message": "error no rule or bundle found  !", 
                    "toast_class" : "danger"}, 500
    return {"success": False, 
            "message": "You don't have the permission to do that !", 
            "toast_class" : "danger"}, 401


@bundle_blueprint.route("/remove", methods=['GET'])
@login_required
def remove() :     
    """Remove a rule in a bundle"""     
    rule_id = request.args.get('rule_id',  type=int)
    bundle_id = request.args.get('bundle_id', type=int)

    bundle = BundleModel.get_bundle_by_id(bundle_id)

    if current_user.id == bundle.user_id or current_user.is_admin():
        if rule_id and bundle_id:
            success_ = BundleModel.remove_rule_from_bundle(bundle_id , rule_id)
            if success_:
                return {"success": True, 
                        "message": "Rule removed  !", 
                        "toast_class" : "success"}, 200
        return {"success": False, 
                    "message": "error no rule or bundle found  !", 
                    "toast_class" : "danger"}, 500
    return {"success": False, 
            "message": "You don't have the permission to do that !", 
            "toast_class" : "danger"}, 401


@bundle_blueprint.route("/get_rules_page_from_bundle", methods=['GET'])
def get_rules_page_from_bundle() :     
    """get all the rule from the bundles for pages"""     
    page = request.args.get('page', 1, type=int)
    bundle_id = request.args.get('bundle_id',  type=int)
    rule_list = BundleModel.get_all_rule_bundles_page(page , bundle_id)
    total_rules = BundleModel.get_total_rule_from_bundle_count(bundle_id)
    if rule_list:
        return {"rules_list": [r.to_json() for r in rule_list],
                "total_pages": rule_list.pages, 
                "total_rules": total_rules,} , 200

    return {"message": "No Rule"} , 200

@bundle_blueprint.route("/get_bundle", methods=['GET'])
def get_bundle():
    """Get a bundle and all its associated rules with full info."""
    bundle_id = request.args.get('bundle_id', type=int)
    if not bundle_id:
        return {
            "message": "Missing bundle_id parameter",
            "success": False
        }, 400

    bundle = BundleModel.get_bundle_by_id(bundle_id)
    if not bundle:
        return {
            "message": f"No bundle found with id {bundle_id}",
            "success": False
        }, 404

    rules_ids_from_bundle = BundleModel.get_rule_ids_by_bundle(bundle_id)
    if isinstance(rules_ids_from_bundle, dict) and "error" in rules_ids_from_bundle:
        # no rules or error
        rules_info = []
    else:
        rules_info = []
        for rule_id in rules_ids_from_bundle:
            info = BundleModel.get_full_rule_bundle_info(rule_id)
            if info:
                rules_info.append(info)

    return {
        "bundle": bundle.to_json() if hasattr(bundle, 'to_json') else bundle,
        "rules": rules_info,
        "success": True,
        "message": "Bundle and associated rules found"
    }, 200

@bundle_blueprint.route("/change_description", methods=['GET'])
@login_required
def change_description():
    """Chamge the description of the association rule/bundle (the reason to the presence of the rule in the bundle)."""
    association_id = request.args.get('association_id', type=int)
    new_description = request.args.get('new_description', type=str)
    if not association_id:
        return {
            "message": "Missing association_id parameter",
            "success": False,
            "toast_class" : "danger"
        }, 400

    association = BundleModel.get_association_by_id(association_id)
    if not association:
        return {
            "message": f"No association found with id {association_id}",
            "success": False,
            "toast_class" : "danger"
        }, 404
    bundle = BundleModel.get_bundle_by_id(association.bundle_id)

    if bundle.user_id == current_user.id or current_user.is_admin():
        association.description = new_description
        return {
            "success": True,
            "message": "Description modified with success",
            "toast_class" : "success"
        }, 200
    else:
        return {
            "success": False,
            "message": "Access denied",
            "toast_class" : "danger"
        }, 401

#########################
#   Download section    #
#########################

@bundle_blueprint.route('/download', methods=['GET'])
def download_bundle():
    bundle_id = request.args.get("bundle_id", type=int)
    bundle = BundleModel.get_bundle_by_id(bundle_id)
    rules = BundleModel.get_rules_from_bundle(bundle_id)  

    if not rules or not bundle:
        return {
            "success": False,
            "message": "Error during download",
            "toast_class": "danger"
        }, 400

    EXTENSIONS_MAP = {
        "yara": "yara",
        "sigma": "yaml",
        "zeek": "zeek",
        "suricata": "rule",
    }

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        bundle_info_json = json.dumps(bundle.to_json(), indent=2)
        zip_file.writestr("bundle_info.txt", bundle_info_json)

        for rule in rules:
            ext = EXTENSIONS_MAP.get(rule.format.lower(), "txt") if rule.format else "txt"
            base_filename = f"{rule.title.replace(' ', '_')}_{rule.id}"

            code_filename = f"{base_filename}.{ext}"
            zip_file.writestr(code_filename, rule.to_string or "")

            json_filename = f"{base_filename}.txt"  # .json
            rule_json = json.dumps(rule.to_json(), indent=2)
            zip_file.writestr(json_filename, rule_json)

    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name=f"{bundle.name}.zip",
        mimetype='application/zip'
    ), 200

################
#  own bundle  #
################

@bundle_blueprint.route("/own", methods=['GET' , 'POST'])
@login_required
def own() :     
    """list all bundles"""     
    return render_template("bundle/own_bundle.html" )

@bundle_blueprint.route("/get_all_bundles_owner", methods=['GET'])
@login_required
def get_all_bundles_owner() :     
    """get all bundles own by the current user for pages"""     
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', type=str)
    bundles_list = BundleModel.get_all_bundles_own_page(page, search)
    total_bundles = BundleModel.get_total_bundles_count_own()
    if bundles_list:
        return {"bundle_list_": [r.to_json() for r in bundles_list],
                "total_pages": bundles_list.pages, 
                "total_bundles": total_bundles} , 200

    return {"message": "No Rule"} , 200

################################
#   Rule part of the bundle    #
################################

@bundle_blueprint.route("/get_bundle_list_rule_part_of", methods=['GET'])
def get_bundle_list_rule_part_of() :     
    """get all bundles where the rule is part of"""     
    rule_id = request.args.get('rule_id',  type=int)
    if not rule_id:
        return {"message": "No rule id provided"}, 400

    bundles = BundleModel.get_bundles_by_rule(rule_id)
    if bundles:
        return {"bundles": [b.to_json() for b in bundles]}, 200

    return {"message": "No bundles found for this rule"}, 200