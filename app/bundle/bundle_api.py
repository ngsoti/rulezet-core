
from flask import Blueprint, request
from flask_restx import Api , Resource
from app.bundle import bundle_core as BundleModel
from app.utils import utils
from app.utils.decorators import api_required



api_bundle_blueprint = Blueprint('api_bundle', __name__)

# Create the Flask-RESTx API
api = Api(api_bundle_blueprint,
    title='Rulezet API',
    description='API to manage a bundle management instance.',
    version='0.1',
    doc='/doc/'  
)

# ------------------------------------------------------------------------------------------------------------------- #
#                                       PRIVATE ENDPOINT (auth required)                                              # 
# ------------------------------------------------------------------------------------------------------------------- #

#############
#   Create  #
#############

@api.route('/create')
@api.doc(description='Create a new bundle')
class CreateBundle(Resource):
    @api.doc(params={
        'name': 'Bundle name',
        'description': 'Bundle description'
    })
    @api_required
    def post(self):
        user = utils.get_user_from_api(request.headers)

        data = request.get_json(silent=True)
        if not data:
            data = request.args.to_dict()

        my_bundle = BundleModel.create_bundle(data , user)
        if not my_bundle:
            return {"message": "Failed to create bundle"}, 500

        return {"message": "Bundle created successfully", "bundle_id": my_bundle.id}, 201
    
    # curl -X POST http://127.0.0.1:7009/api/bundle/create \
    # -H "Content-Type: application/json" \
    # -H "X-API-KEY: user_api_key" \
    # -d '{
    #     "name": "My Bundle Name",
    #     "description": "This is a test bundle created via API."
    # }'

#################
#   add rules   #
#################

@api.route('/add_rule_bundle')
@api.doc(description='Add a rule to a bundle')
class AddRuleToBundle(Resource):
    @api.doc(params={
        'rule_id': 'ID of the rule to add',
        'bundle_id': 'ID of the bundle to add the rule to',
        'description': 'Optional description for this rule in the bundle'
    })
    @api_required
    def get(self):
        """Add a rule to a bundle"""
        user = utils.get_user_from_api(request.headers)

        rule_id = request.args.get('rule_id', type=int)
        bundle_id = request.args.get('bundle_id', type=int)
        description = request.args.get('description', type=str)
        if not rule_id or not bundle_id or not description:
            return {
                "success": False,
                "message": "Missing rule_id or bundle_id or description",
                "toast_class": "danger"
            }, 400

        bundle = BundleModel.get_bundle_by_id(bundle_id)
        
        if not bundle:
            return {"success": False, "message": "Bundle not found", "toast_class": "danger"}, 404

        if user.id == bundle.user_id or user.is_admin():
            if rule_id and bundle_id:
                success_ = BundleModel.add_rule_to_bundle(bundle_id, rule_id, description)
                if success_:
                    return {
                        "success": True,
                        "message": "Rule added!",
                        "toast_class": "success"
                    }, 200

            return {
                "success": False,
                "message": "Missing rule_id or bundle_id",
                "toast_class": "danger"
            }, 400

        return {
            "success": False,
            "message": "You don't have the permission to do that!",
            "toast_class": "danger"
        }, 401

    # curl -X GET "http://127.0.0.1:7009/api/bundle/add_rule_bundle?rule_id=42&bundle_id=7&description=Important%20rule" \
    #     -H "X-API-KEY: user_api_key"

##################
# remove rules   #
##################

@api.route('/remove_rule_bundle')
@api.doc(description='Remove a rule from a bundle')
class RemoveRuleFromBundle(Resource):
    @api.doc(params={
        'rule_id': 'ID of the rule to remove',
        'bundle_id': 'ID of the bundle to remove the rule from'
    })
    @api_required
    def get(self):
        """Remove a rule from a bundle"""
        user = utils.get_user_from_api(request.headers)

        rule_id = request.args.get('rule_id', type=int)
        bundle_id = request.args.get('bundle_id', type=int)

        if not rule_id or not bundle_id:
            return {
                "success": False,
                "message": "Missing rule_id or bundle_id",
                "toast_class": "danger"
            }, 400

        bundle = BundleModel.get_bundle_by_id(bundle_id)

        if not bundle:
            return {
                "success": False,
                "message": "Bundle not found",
                "toast_class": "danger"
            }, 404

        if user.id == bundle.user_id or user.is_admin():
            success_ = BundleModel.remove_rule_from_bundle(bundle_id, rule_id)
            if success_:
                return {
                    "success": True,
                    "message": "Rule removed!",
                    "toast_class": "success"
                }, 200
            return {
                "success": False,
                "message": "Rule not found in this bundle or already removed",
                "toast_class": "danger"
            }, 500

        return {
            "success": False,
            "message": "You don't have the permission to do that!",
            "toast_class": "danger"
        }, 401

    # curl -X GET "http://127.0.0.1:7009/api/bundle/remove_rule_bundle?rule_id=123&bundle_id=456" \
    #  -H "X-API-KEY: user_api_key"

####################
#   Edit bundle    #
####################

@api.route('/edit_bundle/<int:bundle_id>')
@api.doc(description='Update a bundle (name and/or description)', params={
    'bundle_id': 'ID of the bundle'
})
class EditBundle(Resource):
    @api_required
    def post(self, bundle_id):
        """Update a bundle"""
        user = utils.get_user_from_api(request.headers)
        bundle = BundleModel.get_bundle_by_id(bundle_id)

        if not bundle:
            return {"success": False, "message": "Bundle not found"}, 404

        if user.id != bundle.user_id and not user.is_admin():
            return {"success": False, "message": "You don't have the permission to do that!"}, 401

        data = request.get_json()
        success = BundleModel.update_bundle(bundle_id, data)

        if success:
            return {
                "success": True,
                "message": "Bundle updated successfully",
                "toast_class": "success"
            }, 200

        return {
            "success": False,
            "message": "Update failed",
            "toast_class": "danger"
        }, 500

    # curl -X POST http://127.0.0.1:7009/api/bundle/edit_bundle/1 \
    #     -H "Content-Type: application/json" \
    #     -H "X-API-KEY: user_api_key" \
    #     -d '{"name": "Updated Bundle Name", "description": "New description here"}'
