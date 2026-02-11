from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
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


@tags_blueprint.route('/create_tag', methods=['POST'])
@login_required
def create_tag():
    data = request.json
    if not data or not data.get('name'):
        return {"status": "error", "message": "Tag name is required."}, 400

    if 'visibility' not in data:
        data['visibility'] = 'private' 

    tag = tags_core.create_tag(data, current_user)
    
    if tag is False:
        return {"status": "error", "message": "A tag with this name already exists.", "toast_class": "warning-subtle"}, 201
    
    if tag is None:
        return {"status": "error", "message": "Error while creating tag", "toast_class": "danger-subtle"}, 500
    return {
        "status": "success", 
        "message": "Tag created successfully!", 
        "tag": {
            "id": tag.id,
            "uuid": tag.uuid,
            "name": tag.name,
            "color": tag.color
        },
        "toast_class": "success-subtle"
    }, 200

################
#   my_tags    #
################

@tags_blueprint.route('/my_tags', methods=['GET'])
@login_required
def my_tags():
    return render_template("tags/my_tags.html")

@tags_blueprint.route('/get_my_tags', methods=['GET'])
@login_required
def get_my_tags():
    my_tags = tags_core.get_my_tags()
    return jsonify([tag.to_json() for tag in my_tags])

@tags_blueprint.route('/delete_tag/<int:tag_id>', methods=['POST'])
@login_required
def delete_tag(tag_id):
    success , msg = tags_core.remove_tag(tag_id)
    if not success:
        return jsonify({"status": "error", "message": msg, "toast_class": "danger-subtle"}), 500
    return jsonify({"status": "success", "message": msg, "toast_class": "success-subtle"}), 200


# get_all_public_tags

@tags_blueprint.route('/get_all_tags', methods=['GET'])
@login_required
def get_all_tags():    
    tags = tags_core.get_all_tags(request.args)
    if tags:
        tags_lists = [tag.to_json() for tag in tags]
    
    return {"status": "success", "tags": tags_lists, "total_tags": len(tags)}, 200


# get_all_tags_by_type

@tags_blueprint.route('/get_all_tags_by_type', methods=['GET'])
@login_required
def get_all_tags_by_type():    
    tags = tags_core.get_all_tags_by_type(request.args)
    if tags:
        tags_lists = [tag.to_json() for tag in tags]
    
    return {"status": "success", "tags": tags_lists, "total_tags": len(tags)}, 200