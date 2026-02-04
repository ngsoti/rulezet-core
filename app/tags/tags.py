from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
import app.tags.tags_core as tags_core



tags_blueprint = Blueprint(
    'tags',
    __name__,
    template_folder='templates',    
    static_folder='static'
)

# false-positive / detection-engineering / tlp / PAP taxonomy

##################
#   Tags routes  #
##################

@tags_blueprint.route('/list', methods=['GET'])
@login_required
def list_tags():
    if not current_user.is_admin():
        flash('You need to be admin to access this page.', 'danger')
        return render_template("access_denied.html")
    return render_template('tags/list.html')

#################################
#  get, add, edit, delete tags  #
#################################
# get_tags
@tags_blueprint.route('/get_tags', methods=['GET'])
@login_required
def get_tags():
    if not current_user.is_admin():
        return {"status": "error", "message": "You need to be admin to access this page."}, 403
    tags = tags_core.get_tags(request.args)
    if tags:
        tags_lists = [tag.to_json() for tag in tags.items]
    
    return {"status": "success", "tags": tags_lists, "total_pages": tags.pages, "total_tags": tags.total}, 200

@tags_blueprint.route('/get_tags_misp', methods=['GET'])
@login_required
def get_tags_misp():
    if not current_user.is_admin():
        return {"status": "error", "message": "You need to be admin to access this page."}, 403
    result = tags_core.list_all_misp_taxonomies_meta(request.args)

    return {
        "status": "success",
        "tags": result["items"],
        "total_pages": result["pages"],
        "total_tags": result["total"],
        "page": result["page"]
    }, 200

@tags_blueprint.route('/add_tags_misp', methods=['GET'])
@login_required
def add_tag_misp(): 
    if not current_user.is_admin():
        return {"success": False, "message": "You need to be admin to access this page.", "toast_class": "danger-subtle"}, 403

    uuid = request.args.get("uuid")
    if not uuid:
        return {"success": False, "message": "UUID is required.", "toast_class": "danger-subtle"}, 400

    success, message = tags_core.add_tags_from_misp_taxonomy(uuid, created_by=current_user)
    if success:
        return {"success": True, "message": message, "toast_class": "success-subtle"}, 200
    else:
        return {"success": False, "message": message, "toast_class": "danger-subtle"}, 500

# remove_tag
@tags_blueprint.route('/remove_tag', methods=['GET'])
@login_required
def remove_tag():
    tag_id = request.args.get("tag_id")
    if not current_user.is_admin():
        return {"status": "error", "message": "You need to be admin to access this page."}, 403
    success, message = tags_core.remove_tag(tag_id)
    if success:
        return {"status": "success", "message": message, "toast_class": "success-subtle"}, 200
    else:
        return {"status": "error", "message": message, "toast_class": "danger-subtle"}, 500
    
# toggle_visibility

@tags_blueprint.route('/toggle_visibility', methods=['GET'])
@login_required
def toggle_visibility():
    if not current_user.is_admin():
        return {"status": "error", "message": "You need to be admin to access this page."}, 403
    tag_uuid = request.args.get("tag_uuid")

    if not tag_uuid:
        return {"status": "error", "message": "Tag UUID is required."}, 400

    success, message = tags_core.toggle_tag_visibility(tag_uuid)
    if success:
        return {"status": "success", "message": message, "toast_class": "success-subtle"}, 200
    else:
        return {"status": "error", "message": message, "toast_class": "danger-subtle"}, 500
    
# toggle_status

@tags_blueprint.route('/toggle_status', methods=['GET'])
@login_required
def toggle_status():
    if not current_user.is_admin():
        return {"status": "error", "message": "You need to be admin to access this page."}, 403
    tag_uuid = request.args.get("tag_uuid")

    if not tag_uuid:
        return {"status": "error", "message": "Tag UUID is required."}, 400

    success, message = tags_core.toggle_tag_status(tag_uuid)
    if success:
        return {"status": "success", "message": message, "toast_class": "success-subtle"}, 200
    else:
        return {"status": "error", "message": message, "toast_class": "danger-subtle"}, 500
    
# edit_tag
@tags_blueprint.route('/edit_tag/<int:tag_id>', methods=['POST'])
@login_required
def edit_tag(tag_id):
    if not current_user.is_admin():
        return {"status": "error", "message": "You need to be admin to access this page."}, 403
    
    if not tag_id:
        return {"status": "error", "message": "Tag ID is required."}, 400
    data = request.json
    success, message = tags_core.edit_tag(data, tag_id)
    if success:
        return {"status": "success", "message": message, "toast_class": "success-subtle"}, 200
    else:
        if not message:
            return {"status": "error", "message": "Error while updating tag", "toast_class": "danger-subtle"}, 500
        else:
            return {"status": "error", "message": message, "toast_class": "warning-subtle"}, 201
        


@tags_blueprint.route('/get_tags_bundle', methods=['GET'])
@login_required
def get_tags_bundle():
    tags = tags_core.get_tags_bundle(request.args)
    if tags:
        tags_lists = [tag.to_json() for tag in tags.items]
    
    return {"status": "success", "tags": tags_lists, "total_pages": tags.pages, "total_tags": tags.total}, 200