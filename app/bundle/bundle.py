from flask import Blueprint, flash, jsonify, redirect, render_template , request, url_for
from flask_login import current_user, login_required

from app.bundle.bundle_form import AddNewBundleForm, EditBundleForm
from app.utils.utils import form_to_dict
from . import bundle_core as BundleModel
from ..rule import rule_core as RuleModel
from ..account import account_core as AccountModel

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
def create():     
    """Create a bundle with form"""     
    form = AddNewBundleForm()
    if form.validate_on_submit():
        form_dict = form_to_dict(form)
        
        my_bundle = BundleModel.create_bundle(form_dict, current_user)
        if my_bundle:
            flash('Bundle created !', 'success')
            return redirect(url_for("bundle.edit", bundle_id=my_bundle.id))
        else:
            flash('Error to create', 'danger')
            return render_template("bundle/create_bundle.html", form=form)
        
    return render_template("bundle/create_bundle.html", form=form)


############
#   List   #
############

@bundle_blueprint.route("/list", methods=['GET' , 'POST'])
def list() :     
    """list all bundles"""     
    return render_template("bundle/list_bundle.html" )

@bundle_blueprint.route("/get_all_bundles", methods=['GET'])
def get_all_bundles():     
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', type=str)
    
    # Existing Tags Logic
    tag_ids_raw = request.args.get('tag_ids', type=str) 
    tag_id_list = [int(tid) for tid in tag_ids_raw.split(',') if tid.strip()] if tag_ids_raw else []

    # New Vulnerability Logic
    vuln_raw = request.args.get('vulnerabilities', type=str)
    vuln_list = [v.strip() for v in vuln_raw.split(',') if v.strip()] if vuln_raw else []
    own = request.args.get('own', type=str)
    own = True if own == '1' else False 

    # Pass vuln_list to the model method
    bundles_pagination = BundleModel.get_all_bundles_page(page, search, own, tag_id_list, vuln_list)
    
    return {
        "bundle_list_": [r.to_json() for r in bundles_pagination.items],
        "total_pages": bundles_pagination.pages, 
        "total_bundles": bundles_pagination.total
    }, 200

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
            v_data = request.form.get('vulnerabilities')
            form_dict['vulnerabilities'] = v_data
            
            BundleModel.update_bundle(bundle_id , form_dict )
            flash("Bundle modified with success!", "success")
            return redirect(request.referrer or '/')
        else:
            form.description.data = bundle.description
            form.name.data = bundle.name 
            form.public.data = bundle.access

        return render_template("bundle/edit_bundle.html", form=form, bundle=bundle)
    else:
        return render_template("access_denied.html")
    
@bundle_blueprint.route("/detail/<int:bundle_id>", methods=['GET' , 'POST'])
def detail(bundle_id) :     
    """Go to detail of a bundle"""    
    bundle = BundleModel.get_bundle_by_id(bundle_id)
    if bundle: 
        if bundle.access or current_user.is_admin() or current_user.id == bundle.user_id:
            # add one to the wiew
            success = BundleModel.add_view(bundle_id)
            return render_template("bundle/detail_bundle.html", bundle_id=bundle_id)
        else:
            return render_template("access_denied.html"),403
    else:
        return render_template("404.html"), 404
    

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
# -----------------------------------------------------------------------------------------------------------------------------
@bundle_blueprint.route("/save_workspace/<int:bundle_id>", methods=['POST'])
@login_required
def save_workspace(bundle_id):
    data = request.json
    structure = data.get('structure') # The tree from Vue.js

    if not bundle_id:
        return {"success": False, "toast_class": "danger", "message": "Missing bundle_id or structure"}, 500
    
    # Check if the bundle exists
    bundle = BundleModel.get_bundle_by_id(bundle_id)
    if not bundle:
        return {"success": False, "toast_class": "danger", "message": "Bundle not found"}, 404
    
    # Check if the user has permission to save the workspace
    if current_user.id != bundle.user_id and not current_user.is_admin():
        return {"success": False, "toast_class": "danger", "message": "You don't have the permission to do that!"}, 401

    s = BundleModel.update_bundle_from_structure(bundle_id, structure)
    if not s:
        return {"success": False, "toast_class": "danger", "message": "Error updating rule view count"}, 500

    success = BundleModel.save_workspace(bundle_id, structure)

    if success:
        return {"success": True, "toast_class": "success", "message": "Workspace saved successfully"}, 200
    else:
        return {"success": False, "toast_class": "danger", "message": "Error saving workspace"}, 500

@bundle_blueprint.route("/get_bundle_json/<int:bundle_id>")
def get_bundle_json(bundle_id):
    # Fetch only top-level nodes (those without parents)
    root_nodes = BundleModel.get_only_root_nodes(bundle_id)
    
    # If the bundle is new and empty, return a default root
    if not root_nodes:
        structure = [{"id": "root", "name": "Main Bundle", "type": "folder", "children": []}]
    else:
        structure = [node.to_tree_json() for node in root_nodes]

    return jsonify({
        "success": True, 
        "structure": structure
    }), 200
# -----------------------------------------------------------------------------------------------------------------------------
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



# update_bundle_tags

@bundle_blueprint.route("/update_bundle_tags/<int:bundle_id>", methods=['POST'])
@login_required
def update_bundle_tags(bundle_id):
    data = request.json
    tag_ids = data.get('tag_ids', [])

    if not bundle_id:
        return {"success": False, "message": "Missing bundle_id"}, 400

    bundle = BundleModel.get_bundle_by_id(bundle_id)
    if not bundle:
        return {"success": False, "message": "Bundle not found"}, 404

    if current_user.id != bundle.user_id and not current_user.is_admin():
        return {"success": False, "message": "You don't have the permission to do that!"}, 401

    success = BundleModel.update_bundle_tags(bundle_id, tag_ids, current_user)
    if success:
        return {"success": True, "message": "Tags updated successfully"}, 200
    else:
        return {"success": False, "message": "Error updating tags"}, 500



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
    root_nodes = BundleModel.get_only_root_nodes(bundle_id)
    
    # If the bundle is new and empty, return a default root
    if not root_nodes:
        structure = [{"id": "root", "name": "Main Bundle", "type": "folder", "children": []}]
    else:
        structure = [node.to_tree_json() for node in root_nodes]
    return {
        "bundle": bundle.to_json() if hasattr(bundle, 'to_json') else bundle,
        "rules": rules_info,
        "success": True,
        "message": "Bundle and associated rules found",
        "structure": structure
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

@bundle_blueprint.route("/edit_access", methods=['GET'])
def edit_access():
    """Edit access to a bundle."""
    bundle_id = request.args.get('id', type=int)
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

    if not (bundle.user_id == current_user.id or current_user.is_admin()):
        return {
            "success": False,
            "message": "Access denied",
            "toast_class" : "danger"
        }, 401  
    access, message = BundleModel.toggle_bundle_accessibility(bundle_id)
    if access is None:
        return {
            "success": False,
            "message": "Error toggling access",
            "toast_class" : "danger"
        }, 500

    return {
        "success": True,
        "message": f"{message}",
        "new_access": access,
        "toast_class" : "success"
    }, 200


@bundle_blueprint.route("/evaluate", methods=['GET'])
@login_required
def evaluate():
    """Evaluate a bundle and return aggregated statistics."""
    bundle_id = request.args.get('bundleId', type=int)
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
    
    if not bundle.access and (not current_user.is_authenticated or (current_user.id != bundle.user_id and not current_user.is_admin())):
        return {
            "success": False,
            "message": "You don't have the permission to evaluate this bundle",
            "toast_class" : "danger"
        }, 401

    vote_type = request.args.get('voteType', type=str)
    if vote_type not in ['up', 'down']:
        return {
            "message": "Invalid voteType. Must be 'up' or 'down'.",
            "success": False
        }, 400

    already_vote, already_vote_type = BundleModel.has_already_vote(bundle_id, current_user.id)

     # update the gameifcation section
    profil_game_user = AccountModel.get_or_create_gamification_profile(current_user.id)
    if not profil_game_user:
        return jsonify({"message": "Error to update the gamification section"}), 500

    if vote_type == 'up':
        if not already_vote:
            BundleModel.increment_up(bundle_id)
            BundleModel.has_voted('up', bundle_id, current_user.id)

            _ = AccountModel.update_like_gamification(profil_game_user.id, "add_one_to_like")
        elif already_vote_type == 'up':
            BundleModel.remove_one_to_increment_up(bundle_id)
            BundleModel.remove_has_voted('up', bundle_id, current_user.id)

            _ = AccountModel.update_like_gamification(profil_game_user.id, "remove_one_to_like")
        elif already_vote_type == 'down':
            BundleModel.increment_up(bundle_id)
            BundleModel.remove_one_to_decrement_up(bundle_id)
            BundleModel.remove_has_voted('down', bundle_id, current_user.id)
            BundleModel.has_voted('up', bundle_id, current_user.id)

            _ = AccountModel.update_like_gamification(profil_game_user.id, "add_one_to_like")
            _ = AccountModel.update_like_gamification(profil_game_user.id, "remove_one_to_dislike")

    elif vote_type == 'down':
        if not already_vote:
            BundleModel.decrement_up(bundle_id)
            BundleModel.has_voted('down', bundle_id, current_user.id)

            _ = AccountModel.update_like_gamification(profil_game_user.id, "add_one_to_dislike")
        elif already_vote_type == 'down':
            BundleModel.remove_one_to_decrement_up(bundle_id)
            BundleModel.remove_has_voted('down', bundle_id, current_user.id)

            _ = AccountModel.update_like_gamification(profil_game_user.id, "remove_one_to_dislike")
        elif already_vote_type == 'up':
            BundleModel.decrement_up(bundle_id)
            BundleModel.remove_one_to_increment_up(bundle_id)
            BundleModel.remove_has_voted('up', bundle_id, current_user.id)
            BundleModel.has_voted('down', bundle_id, current_user.id)

            _ = AccountModel.update_like_gamification(profil_game_user.id, "add_one_to_dislike")
            _ = AccountModel.update_like_gamification(profil_game_user.id, "remove_one_to_like")

    return jsonify({
        "vote_up": bundle.vote_up,
        "vote_down": bundle.vote_down
    }), 200

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
            "message": "No rules on this bundle to download",
            "toast_class": "danger"
        }, 400
    
    if not bundle.access and (not current_user.is_authenticated or (current_user.id != bundle.user_id and not current_user.is_admin())):
        return {
            "success": False,
            "message": "You don't have the permission to download this bundle",
            "toast_class": "danger"
        }, 401

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        bundle_info_json = json.dumps(bundle.to_json(), indent=2)
        zip_file.writestr("bundle_info.txt", bundle_info_json)

        for rule in rules:
            ext = "txt" # Change into .yara .... for each format
            base_filename = f"{rule.title.replace(' ', '_')}_{rule.id}"

            code_filename = f"{base_filename}.{ext}"
            zip_file.writestr(code_filename, rule.to_string or "")

            json_filename = f"{base_filename}.txt"  # .json
            rule_json = json.dumps(rule.to_json(), indent=2)
            zip_file.writestr(json_filename, rule_json)

    # add 1 to download count
    BundleModel.increment_download_count(bundle_id)

    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name=f"{bundle.name}.zip",
        mimetype='application/zip'
    ), 200



EXTENSION_MAP = {
    'yara': '.yar',
    'sigma': '.yaml',
    'suricata': '.rules',
    'zeek': '.zeek',
    'wazuh': '.xml',
    'nse': '.nse',
    'nova': '.yaml',
    'crs': '.conf',
    'no format': '.txt'
}

def add_node_to_zip(zip_file, node, current_path=""):
    """
    Independent recursive function to build the ZIP directory tree.
    """
    if node.rule_id and node.rule:
        rule_format = node.rule.format.lower() if node.rule.format else 'no format'
        extension = EXTENSION_MAP.get(rule_format, '.txt')
        
        clean_title = node.rule.title.replace("/", "_").replace("\\", "_")
        filename = f"{clean_title}{extension}"
        content = node.rule.to_string
    else:
        filename = node.name
        content = node.custom_content or ""

    entry_path = f"{current_path}/{filename}".strip("/")

    if node.node_type == 'folder':
        if not node.children:
            zip_file.writestr(f"{entry_path}/", "")
        
        for child in node.children:
            add_node_to_zip(zip_file, child, entry_path)
    else:
        zip_file.writestr(entry_path, content)


@bundle_blueprint.route('/download_structure', methods=['GET'])
def download_bundle_structure():     
    bundle_id = request.args.get("bundle_id", type=int)
    bundle = BundleModel.get_bundle_by_id(bundle_id)

    if not bundle:
        return {
            "success": False,
            "message": "Bundle not found",
            "toast_class": "danger"
        }, 400

    # Permission check
    if not bundle.access and (not current_user.is_authenticated or (current_user.id != bundle.user_id and not current_user.is_admin())):
        return {
            "success": False,
            "message": "Unauthorized access",
            "toast_class": "danger"
        }, 401

    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        bundle_metadata = bundle.to_json()
        zip_file.writestr("bundle_metadata.json", json.dumps(bundle_metadata, indent=4))

        root_nodes = BundleModel.get_only_root_nodes(bundle_id)
        for root in root_nodes:
            add_node_to_zip(zip_file, root)

    zip_buffer.seek(0)
    
    safe_bundle_name = "".join([c for c in bundle.name if c.isalnum() or c in (' ', '_')]).strip().replace(' ', '_')
    
    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name=f"{safe_bundle_name}_structure.zip",
        mimetype='application/zip'
    )

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


###############################
#   Bundle by user section    #
###############################

@bundle_blueprint.route("/get_bundles_page_filter_with_id", methods=['GET'])
def get_bundles_page_filter_with_id():     
    """get all the bundles of a user for pages"""     
    user_id = request.args.get('user_id', type=int)
    page = request.args.get('page', 1, type=int)
    search = request.args.get("searchBundle", None)
    sort_by = request.args.get("sortByBundle", "newest")
    rule_type = request.args.get("ruleTypeBundle", "")

    if not user_id:
        return {"message": "No user id provided"}, 400

    bundles = BundleModel.get_bundles_of_user_with_id_page(user_id, page, search,sort_by, rule_type)
    
    if bundles.total > 0:
        return {
            "bundles_list": [r.to_json() for r in bundles.items],
            "total_pages": bundles.pages,
            "total_bundles": bundles.total
        }, 200

    return {"message": "No Bundle"}, 200



#############
#   Update  #
#############

# Transforme from BundleRuleAssociation to a structure compatible with the UI
@bundle_blueprint.route("/update_bundle_from_structure", methods=['GET'])
@login_required
def update_bundle_from_structure():
    bundle_id = request.args.get("id", type=int)
    if not bundle_id:
        return {"message": "No bundle id provided", "toast_class": "danger-subtle"}, 400
    if not current_user.is_admin():
        return {"message": "You don't have the permission to do that !", "toast_class": "danger-subtle"}, 401
   # take all the rule associate to ths bundle and create a structure with BundleNode (create one folder and put all the rule id in there)
    success, msg = BundleModel.update_bundle_from_rule_id_into_structure(bundle_id)

    if not success:
        return {"message": msg, "toast_class": "danger-subtle"}, 500

    return {"toast_class": "success-subtle", "message": "Bundle updated successfully"}, 200



#######################
#   Comment section   #
#######################

@bundle_blueprint.route("/add_comment", methods=['GET'])
def add_comment():
    """Add a comment to a bundle."""

    if not current_user.is_authenticated:
        return {"message": "You must be logged in to add a comment", "toast_class": "warning-subtle"}, 401

    bundle_id = request.args.get('bundle_id', type=int)
    content = request.args.get('content', type=str)
    parent_comment_id = request.args.get('parent_comment_id', type=int, default=None)

    if not bundle_id or not content:
        return {"message": "Missing bundle_id or content", "toast_class": "danger-subtle"}, 400

    bundle = BundleModel.get_bundle_by_id(bundle_id)
    if not bundle:
        return {"message": "Bundle not found", "toast_class": "danger-subtle"}, 404

    message, success = BundleModel.add_comment_to_bundle(bundle_id, current_user, content, parent_comment_id)
    if success:
        return {"message": message, "toast_class": "success-subtle"}, 200
    else:
        return {"message": message, "toast_class": "danger-subtle"}, 500


@bundle_blueprint.route("/get_comments", methods=['GET'])
def get_comments():
    """Get all comments for a bundle. (parents and children and pagginated)"""
    bundle_id = request.args.get('bundle_id', None)
    page = request.args.get('page', 1, type=int)
    if not bundle_id:
        return {"message": "Missing bundle_id", "toast_class": "danger-subtle"}, 400

    bundle = BundleModel.get_bundle_by_id(bundle_id)
    if not bundle:
        return {"message": "Bundle not found", "toast_class": "danger-subtle"}, 404

    comments = BundleModel.get_comments_for_bundle(bundle_id, page)

    return {
        "comments": [c.to_json() for c in comments.items],
        "total_pages": comments.pages,
        "total_comments": comments.total
    }, 200

# delete_comment

@bundle_blueprint.route("/delete_comment", methods=['GET'])
@login_required
def delete_comment():
    comment_id = request.args.get('comment_id', type=int)

    if not comment_id:
        return {"message": "Missing comment_id", "toast_class": "danger-subtle"}, 400

    comment = BundleModel.get_comment_bundle_by_id(comment_id)
    if not comment:
        return {"message": "Comment not found", "toast_class": "danger-subtle"}, 404

    if comment.user_id != current_user.id and not current_user.is_admin():
        return {"message": "You don't have the permission to do that !", "toast_class": "danger-subtle"}, 401


    success = BundleModel.delete_comment_bundle(comment_id)
    if success:
        return {"message": "Comment deleted.", "toast_class": "success-subtle"}, 200
    else:
        return {"message": "Not authorized or comment not found.", "toast_class": "danger-subtle"}, 403
    
# edit_comment

@bundle_blueprint.route("/edit_comment", methods=['GET'])
@login_required
def edit_comment():
    comment_id = request.args.get('comment_id', type=int)
    content = request.args.get('content', type=str)

    if not comment_id or not content:
        return {"message": "Missing comment_id or content", "toast_class": "danger-subtle"}, 400

    comment = BundleModel.get_comment_bundle_by_id(comment_id)
    if not comment:
        return {"message": "Comment not found", "toast_class": "danger-subtle"}, 404

    if comment.user_id != current_user.id and not current_user.is_admin():
        return {"message": "You don't have the permission to do that !", "toast_class": "danger-subtle"}, 401

    success = BundleModel.edit_comment_bundle(comment_id, content)
    if success:
        return {"message": "Comment edited.", "toast_class": "success-subtle"}, 200
    else:
        return {"message": "Not authorized or comment not found.", "toast_class": "danger-subtle"}, 403
    
@bundle_blueprint.route("/add_reaction", methods=['GET'])
@login_required
def add_reaction():
    """ Add a reaction to a comment."""
    comment_id = request.args.get('comment_id', type=int)
    reaction_type = request.args.get('reaction_type', type=str)
    bundle_id = request.args.get('bundle_id', type=int)

    if not comment_id or not reaction_type:
        return {"message": "Missing comment_id or reaction_type", "toast_class": "danger-subtle"}, 400

    comment = BundleModel.get_comment_bundle_by_id(comment_id)
    if not comment:
        return {"message": "Comment not found", "toast_class": "danger-subtle"}, 404

    success, message = BundleModel.add_reaction_to_comment(comment_id, current_user.id, reaction_type, bundle_id)
    if success:
        return {"message": message, "toast_class": "success-subtle"}, 200
    else:
        return {"message": message, "toast_class": "danger-subtle"}, 500
    


@bundle_blueprint.route('/get_bundle_tag_ids/<int:bundle_id>')
@login_required
def get_bundle_tag_ids(bundle_id):
    tag_ids = BundleModel.get_tag_ids_for_bundle(bundle_id)
    return jsonify({"success": True, "tag_ids": tag_ids})


@bundle_blueprint.route('/get_bundle_tags_display/<int:bundle_id>')
def get_bundle_tags_display(bundle_id):
    """Returns full tag objects associated with a bundle for display purposes."""
    try:
        tags = BundleModel.get_tags_for_bundle(bundle_id)
        
        return jsonify({
            "success": True, 
            "tags": [t.to_json() for t in tags],
            "total_tags": len(tags)

        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    
@bundle_blueprint.route('/get_bundle_vulnerabilities_display/<int:bundle_id>')
def get_bundle_vulnerabilities_display(bundle_id):
    """Returns the list of vulnerability identifier strings."""
    try:
        v_list = BundleModel.get_vulnerabilities_for_bundle(bundle_id)
        
        return jsonify({
            "success": True, 
            "vulnerabilities": v_list, 
            "total_vulnerabilities": len(v_list)
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@bundle_blueprint.route('/get_all_tags_usage')
def get_all_tags_usage():
    try:
        tags = BundleModel.get_all_used_tags_with_counts()
        return jsonify({
            "success": True,
            "tags": tags
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    
@bundle_blueprint.route('/get_all_vulnerabilities_usage')
def get_all_vulnerabilities_usage():
    try:
        vulnerabilities = BundleModel.get_all_vulnerabilities_with_counts()
        return jsonify({
            "success": True,
            "vulnerabilities": vulnerabilities
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    
@bundle_blueprint.route("/get_tags/<int:bundle_id>")
def get_bundle_tags(bundle_id):
    try:
        user_id = request.args.get('user_id', type=int)

        tags_data = BundleModel.get_tags_for_bundle_json(bundle_id, user_id)
        
        return jsonify({"tags": tags_data}), 200
    except Exception as e:
        print(f"Error fetching tags for bundle {bundle_id}: {e}")
        return jsonify({"tags": [], "error": str(e)}), 500
    

@bundle_blueprint.route('/vulnerabilities/<string:target_type>/<int:target_id>')
@login_required
def get_vulnerabilities(target_type, target_id):
    if target_type == 'bundle':
        item = BundleModel.get_bundle_by_id(target_id)
    else:
        return jsonify({"message": "Invalid target type", "vulnerability_identifiers": []}), 400
        
    return jsonify(item.to_json().get('vulnerability_identifiers', []))



@bundle_blueprint.route('/my-bundles')
@login_required
def my_bundles():
    bundles = BundleModel.get_bundles_by_user_id(current_user.id)
    
    bundle_data = []
    for b in bundles:
        root_nodes = BundleModel.get_only_root_nodes(b.id)
        
        json_bundle = b.to_json()
        
        json_bundle['tree'] = [node.to_tree_json() for node in root_nodes]
        bundle_data.append(json_bundle)

    return jsonify({
        "success": True,
        "bundles": bundle_data,
        "total_bundles": len(bundle_data)
    })


@bundle_blueprint.route("/get_bundle_page", methods=['GET'])
def get_bundle_page():
    """Get a bundle and its associated rules with pagination."""
    bundle_id = request.args.get('bundle_id', type=int)
    page = request.args.get('page', type=int, default=1)
    
    if not bundle_id:
        return {"message": "Missing bundle_id parameter", "success": False}, 400

    bundle = BundleModel.get_bundle_by_id(bundle_id)
    if not bundle:
        return {"message": f"No bundle found with id {bundle_id}", "success": False}, 404

   
    pagination = BundleModel.get_paginated_rules_info_by_bundle(bundle_id, page)
    
    
    root_nodes = BundleModel.get_only_root_nodes(bundle_id)
    if not root_nodes:
        structure = [{"id": "root", "name": "Main Bundle", "type": "folder", "children": []}]
    else:
        structure = [node.to_tree_json() for node in root_nodes]

    return {
        "success": True,
        "bundle": bundle.to_json() if hasattr(bundle, 'to_json') else bundle,
        "rules": pagination.items, 
        "pagination": {
            "current_page": pagination.page,
            "total_pages": pagination.pages,
            "total_rules": pagination.total,
            "has_next": pagination.has_next,
            "has_prev": pagination.has_prev
        },
        "structure": structure
    }, 200