# ------------------------------------------------------------------------------------------------------------------- #
#                                       PRIVATE ENDPOINT (auth required)                                              # 
# ------------------------------------------------------------------------------------------------------------------- #
from flask_restx import Namespace, Resource
from flask import  request
from app.bundle import bundle_core as BundleModel
from app.utils import utils
from app.utils.decorators import api_required

bundle_private_ns = Namespace(
    "Private action on Bundle 🔑 (with api key)",
    description="Private bundle operations"
)

#############
#   Create  #
#############

@bundle_private_ns.route('/create')
@bundle_private_ns.doc(
    description="""
Create a new bundle in the system. You must authenticate using your **API KEY**, which can be found in your personal profile on rulezet.org.

### Query Parameters

| Parameter    | Type    | Required | Description                                                                 | Constraints / Notes                            |
|-------------|---------|----------|-----------------------------------------------------------------------------|-------------------------------------------------|
| X-API-KEY   | string  | Yes      | Your personal API key for authentication                                     | Must be valid. Found in your user profile      |
| name        | string  | Yes      | Name of the bundle                                                          | Must be unique, non-empty                       |
| description | string  | No       | Description of the bundle                                                   | Optional. If not provided, defaults to empty    |
| public      | bool    | Yes      | Allow people to see your bundle or not                                      | Must be valid                                   |         

### Example cURL Request

```bash
curl -X POST /api/bundle/private/create \
-H "Content-Type: application/json" \
-H "X-API-KEY: <YOUR_API_KEY>" \
-d '{
    "name": "My Bundle Name",
    "description": "This is a test bundle created via API.",
    "public": true
}'

This endpoint allows authenticated users to create a new bundle for organizing rules. The name is required and must be unique, while description is optional.

"""
)
class CreateBundle(Resource):
    @api_required
    @bundle_private_ns.doc(params={
        "name": "Required. The name of the bundle. Must be a non-empty string.",
        "description": "Optional. Description of the bundle.",
        "public": "Optional. Boolean flag indicating if the bundle is public. Defaults to True."
    })
    def post(self):
        """Create a new bundle"""
        user = utils.get_user_from_api(request.headers)
        data = request.get_json(silent=True) or request.args.to_dict()

        # --- Validate name ---
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            return {"message": "Invalid bundle", "error": "'name' must be a non-empty string"}, 400
        name = name.strip()

        # --- Validate public (strict boolean only) ---
        public = data.get("public", True)
        if not isinstance(public, bool):
            return {"message": "Invalid bundle", "error": "'public' must be a boolean"}, 400

        # --- Validate description ---
        description = data.get("description", "")
        if description is not None and not isinstance(description, str):
            return {"message": "Invalid bundle", "error": "'description' must be a string"}, 400
        description = description.strip() if description else ""

        # --- Create bundle ---
        my_bundle = BundleModel.create_bundle(
            {"name": name, "description": description, "public": public},
            user
        )

        if not my_bundle:
            return {"message": "Failed to create bundle"}, 500

        return {
            "message": "Bundle created successfully",
            "bundle_id": my_bundle.id
        }, 200



#################
#   add rules   #
#################
@bundle_private_ns.route('/add_rule_bundle')
@bundle_private_ns.doc(
    description="""
Add a rule to an existing bundle. This operation requires authentication using your **API KEY**, which can be retrieved from your account profile.

### Query Parameters

| Parameter     | Type   | Required | Description                                                    | Constraints / Notes                              |
|---------------|--------|----------|----------------------------------------------------------------|--------------------------------------------------|
| X-API-KEY     | string | Yes      | Your personal API key for authentication                      | Must be valid. Provided in your user profile     |
| rule_id       | int    | Yes      | ID of the rule to add to the bundle                           | Must exist                                       |
| bundle_id     | int    | Yes      | ID of the bundle that will receive the rule                   | Must exist and you must own it (or be admin)     |
| description   | string | Yes      | A description or comment for this rule inside the bundle      | Must be non-empty string                         |

### Permission Requirements

You may add a rule to a bundle **only if**:
- You are the **owner** of the bundle, **or**
- You are an **administrator**

If you do not meet these conditions, the request will be rejected.

### Behavior

1. Validate query parameters  
2. Check if the bundle exists  
3. Check permissions  
4. Add the rule to the bundle  
5. Return success or error response  

### Example cURL Request

```bash
curl -X GET "/api/bundle/add_rule_bundle?rule_id=42&bundle_id=7&description=Important" \
     -H "X-API-KEY: <YOUR_API_KEY>"

"""
)
class AddRuleToBundle(Resource):
    @bundle_private_ns.doc(params={
    "rule_id": "Required. ID of the rule to add.",
    "bundle_id": "Required. ID of the bundle.",
    "description": "Required. Description for this rule within the bundle."
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
            return {
                "success": False,
                "message": "Bundle not found",
                "toast_class": "danger"
            }, 404

        if not (user.id == bundle.user_id or user.is_admin()):
            return {
                "success": False,
                "message": "You don't have the permission to do that!",
                "toast_class": "danger"
            }, 401

        success_ = BundleModel.add_rule_to_bundle(bundle_id, rule_id, description)
        if success_:
            return {
                "success": True,
                "message": "Rule added!",
                "toast_class": "success"
            }, 200

        return {
            "success": False,
            "message": "Failed to add rule to bundle",
            "toast_class": "danger"
        }, 500


    # curl -X GET "http://127.0.0.1:7009/api/bundle/add_rule_bundle?rule_id=42&bundle_id=7&description=Important" \
    #     -H "X-API-KEY: user_api_key"

##################
# remove rules   #
##################
@bundle_private_ns.route('/remove_rule_bundle')
@bundle_private_ns.doc(
    description="""
Remove a rule from a bundle.

This endpoint allows removing an existing rule from a specific bundle.
Only the bundle owner or an administrator is allowed to perform this action.

### Parameters
----------
The following query parameters must be provided:

| Parameter  | Type   | Required | Description                                                  |
|------------|--------|----------|--------------------------------------------------------------|
| rule_id    | int    | Yes      | ID of the rule to remove from the bundle.                    |
| bundle_id  | int    | Yes      | ID of the bundle from which the rule will be removed.        |


### Constraints
-----------
- Both parameters must be valid integers.
- The bundle must exist.
- The rule must exist inside the bundle.
- Only the bundle owner or an administrator is allowed to remove rules.

### Authorization
-------------
This endpoint requires a valid API key.
Only:
- The bundle owner
- An admin user
are authorized to remove rules.

### Example Request
---------------
```json
GET /api/bundle/remove_rule_bundle?rule_id=123&bundle_id=456
Header: X-API-KEY: your_api_key_here
""")
class RemoveRuleFromBundle(Resource):

    @bundle_private_ns.doc(params={
        'rule_id': 'ID of the rule to remove',
        'bundle_id': 'ID of the bundle to remove the rule from'
    })
    @api_required
    def get(self):
        """Remove a rule from a bundle"""
        user = utils.get_user_from_api(request.headers)

        rule_id = request.args.get('rule_id', type=int)
        bundle_id = request.args.get('bundle_id', type=int)

        # ---- Validate input ----
        if not rule_id or not bundle_id:
            return {
                "success": False,
                "message": "Missing rule_id or bundle_id",
                "toast_class": "danger"
            }, 400

        # ---- Lookup bundle ----
        bundle = BundleModel.get_bundle_by_id(bundle_id)
        if not bundle:
            return {
                "success": False,
                "message": "Bundle not found",
                "toast_class": "danger"
            }, 404

        # ---- Permission check ----
        if not (user.id == bundle.user_id or user.is_admin()):
            return {
                "success": False,
                "message": "You don't have the permission to do that!",
                "toast_class": "danger"
            }, 401

        # ---- Remove rule ----
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
    
####################
#   Edit bundle    #
####################

@bundle_private_ns.route('/edit_bundle/<int:bundle_id>')
@bundle_private_ns.doc(description='Update a bundle (name and/or description)', params={
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
