# ------------------------------------------------------------------------------------------------------------------- #
#                                       PRIVATE ENDPOINT (auth required)                                              # 
# ------------------------------------------------------------------------------------------------------------------- #

import asyncio
from flask_restx import Resource, Namespace

from app.api.utils.rule_validation import *
from app.db_class.db import Rule

from app.rule_format.main_format import extract_rule_from_repo, verify_syntax_rule_by_format
from app.rule_format.utils_format.utils_import_update import clone_or_access_repo, delete_existing_repo_folder, github_repo_metadata, valider_repo_github
from app.utils import utils
from app.utils.decorators import api_required
from ...rule import rule_core as RuleModel
from ...account import account_core as AccountModel
from flask_restx import Namespace, Resource
from flask import request

rule_private_ns = Namespace(
    "Private action on Rule 🔑 (with api key)",
    description="Private rule operations"
)


######################
#   TEST connection  #
######################

@rule_private_ns.route('/me')
@rule_private_ns.doc(
    description="""
Try to connect with your **API KEY**. You can found it in your personnal profil on rulezet.org .

### Query Parameters

| Parameter  | Type    | Description                                                                 |
|------------|---------|-----------------------------------------------------------------------------|
| search     | string  | Your api KEY ************************************************************   |

### Example cURL Request

```bash
curl -X GET http://127.0.0.1:7009/api/rule/private/me -H "X-API-KEY: ************************************************************ "
```
"""
)
class HelloPrivate(Resource):
    @api_required
    def get(self):
        """Get the current user information"""
        user = utils.get_user_from_api(request.headers)
        return {
            "message": f"Welcome {user.first_name}!",
            "user_id": user.id
        }

#####################
#   Create a rule   #
#####################
@rule_private_ns.route('/create')
@rule_private_ns.doc(
    description="""
Create a new detection rule in the system. You must authenticate using your **API KEY**, which can be found in your personal profile on rulezet.org.

### Query Parameters

| Parameter       | Type    | Required | Description                                                                                  | Constraints / Notes                                              |
|-----------------|---------|----------|----------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| X-API-KEY       | string  | Yes      | Your personal API key for authentication                                                     | Must be valid. Found in your user profile                        |
| title           | string  | Yes      | Title of the rule                                                                             | Must be unique, non-empty                                        |
| description     | string  | No       | Description of the rule                                                                       | Optional. If not provided, defaults to "No description provided"|
| version         | string  | Yes      | Version of the rule                                                                           | Must be non-empty                                                |
| format          | string  | Yes      | Rule format                                                                                   | Supported: yara, sigma, suricata, zeek, crs, nova, nse, wazuh   |
| license         | string  | Yes      | License applied to the rule                                                                   | Must be non-empty                                                |
| source          | string  | No       | Source or origin of the rule                                                                  | Optional. Defaults to the user's name                            |
| to_string       | string  | Yes      | String representation of the rule content                                                    | Must be valid syntax for the specified format                    |
| original_uuid   | string  | No       | Original UUID of the rule                                                                    | Optional. Only provide if preserving original UUID               |
| author          | string  | Auto     | Author of the rule                                                                            | Automatically filled from API key user                            |
| cve_id          | string  | No       | CVE ID associated with the rule                                                              | Must be a valid CVE ID format (e.g., CVE-2023-12345)            |

### Example cURL Request

```bash
curl -X POST http://127.0.0.1:7009/api/rule/private/create \
-H "Content-Type: application/json" \
-H "X-API-KEY: <YOUR_API_KEY>" \
-d '{
    "title": "My N Rule",
    "format": "yara",
    "version": "1.0",
    "to_string": "rule example { condition: true }",
    "license": "MIT",
    "original_uuid": "wd334sda",
    "description": "This is a test rule",
    "source": "unit-test",
    "cve_id": "CVE-2023-12345"
}'

"""
)
class CreateRule(Resource):
    @api_required
    @rule_private_ns.doc(params={
    "title": "Required. The title of the rule. Must be unique and non-empty.",
    "description": "Optional. Description of the rule. Defaults to 'No description provided'.",
    "version": "Required. Version of the rule. Must be non-empty.",
    "format": "Required. Rule format (e.g., yara, sigma, suricata, zeek, crs, nova, nse, wazuh).",
    "license": "Required. License applied to the rule. Must be non-empty.",
    "source": "Optional. Source or origin of the rule. Defaults to your name if not provided.",
    "to_string": "Required. String representation of the rule content. Must be valid syntax for the format.",
    "original_uuid": "Optional. Original UUID of the rule if you want to preserve it.",
    "author": "Automatically filled from the API key user.",
    "cve_id": "Optional. CVE ID associated with the rule. Must be a valid CVE format, e.g., CVE-2023-12345."
    })
    def post(self):
        """Create a new rule"""
        user = utils.get_user_from_api(request.headers)

        data = request.get_json(silent=True) or request.args.to_dict()

        # Required fields
        required_fields = ["title", "format", "version", "to_string", "license"]
        missing_fields = [f for f in required_fields if not data.get(f) or not str(data.get(f)).strip()]
        if missing_fields:
            return {"message": f"Missing or empty fields: {', '.join(missing_fields)}"}, 400

        title = data.get("title").strip()
        if Rule.query.filter_by(title=title).first():
            return {"message": "Rule already exists"}, 409

        cve_id = data.get("cve_id")
        if cve_id:
            valid, matches = utils.detect_cve(cve_id)
            if not valid:
                return {"message": "Invalid CVE ID format or not recognized"}, 400

        form_dict = {
            'title': title,
            'format': data.get("format").strip(),
            'description': data.get("description", "").strip() or "No description provided",
            'version': data.get("version").strip(),
            'source': data.get("source", "").strip() or f"{user.first_name}, {user.last_name}",
            'to_string': data.get("to_string").strip(),
            'license': data.get("license").strip(),
            'original_uuid': data.get("original_uuid") or None,
            'author': user.first_name,
            'cve_id': cve_id if cve_id else []
        }

        is_valid, error_msg = verify_syntax_rule_by_format(form_dict)
        if not is_valid:
            return {"message": "Invalid rule", "error": error_msg}, 400

        verif, msg = RuleModel.add_rule_core(form_dict, user)
        if isinstance(verif, Rule):
            return {"message": msg, "rule": verif.to_json()}, 200
        
        return {"message": msg}, 400

        
         

#####################
#   Delete a rule   #
#####################

@rule_private_ns.route('/delete')
@rule_private_ns.doc(
    description="""
Delete an existing rule by its **ID**. You must authenticate using your **API KEY**, which can be found in your personal profile on rulezet.org.

### Query Parameters

| Parameter   | Type    | Required | Description                                                                 | Constraints / Notes                                  |
|-------------|---------|----------|-----------------------------------------------------------------------------|-----------------------------------------------------|
| X-API-KEY   | string  | Yes      | Your personal API key for authentication                                     | Must be valid. Found in your user profile          |
| rule_id     | int     | Yes      | ID of the rule to delete                                                     | Must match an existing rule ID in the system       |

### Example cURL Request

```bash
curl -X POST http://127.0.0.1:7009/api/rule/private/delete \
-H "Content-Type: application/json" \
-H "X-API-KEY: <YOUR_API_KEY>" \
-d '{"rule_id": <RULE_ID>}'

"""
)
class DeleteRule(Resource):
    @api_required
    @rule_private_ns.doc(params={
    "rule_id": "Required. ID of the rule to delete. Must match an existing rule."
    })
    def post(self):
        """Delete a rule by ID"""
        user = utils.get_user_from_api(request.headers)
        if not user:
            return {
                "success": False,
                "message": "Unauthorized: invalid or missing API key"
            }, 401

        data = request.get_json(silent=True)
        if not data:
            return {
                "success": False,
                "message": "Missing JSON body"
            }, 400

        rule_id = data.get('rule_id')
        if not rule_id:
            return {
                "success": False,
                "message": "Missing or empty 'rule_id' parameter"
            }, 400

        # Ensure rule exists
        rule_owner_id = RuleModel.get_rule_user_id(rule_id)
        if rule_owner_id is None:
            return {
                "success": False,
                "message": f"No rule found with ID '{rule_id}'"
            }, 404

        # Permission check: owner or admin
        if user.id == rule_owner_id or user.is_admin():
            success = RuleModel.delete_rule_core(rule_id)
            if success:
                return {
                    "success": True,
                    "message": f"Rule with ID '{rule_id}' deleted successfully"
                }, 200
            else:
                return {
                    "success": False,
                    "message": "An error occurred while deleting the rule"
                }, 500
        else:
            return {
                "success": False,
                "message": "Access denied: you are not the owner or an admin"
            }, 403

######################
#   favorite  rule   #
######################

@rule_private_ns.route('/favorite/<int:rule_id>')
@rule_private_ns.doc(
    description="""
Add or remove a rule from the authenticated user's **favorites** list.  
If the rule is already in the user's favorites, it will be removed; otherwise, it will be added.

### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| rule_id   | int  | Yes      | ID of the rule to add or remove from favorites |

### Headers

| Header     | Type   | Required | Description |
|------------|--------|----------|-------------|
| X-API-KEY  | string | Yes      | Your personal API key for authentication (found in your profile) |

### Responses

- **200 OK** – Rule successfully added or removed from favorites.  
  ```json
  {"success": true, "message": "Rule added to favorites"}

{"success": true, "message": "Rule removed from favorites"}

    403 Forbidden – Invalid or missing API key.

    {"success": false, "message": "Unauthorized"}

Example cURL Request

curl -X GET http://127.0.0.1:7009/api/rule/private/favorite/4 \
-H "X-API-KEY: <YOUR_API_KEY>"

"""
)
class FavoriteRule(Resource):
    @api_required
    def get(self, rule_id):
        """Toggle favorite status of a rule for the authenticated user"""
        user = utils.get_user_from_api(request.headers)
        if not user:
            return {"success": False, "message": "Unauthorized"}, 403

        existing = AccountModel.is_rule_favorited_by_user(rule_id=rule_id, user_id=user.id)
        if existing:
            AccountModel.remove_favorite(rule_id=rule_id, user_id=user.id)
            return {"success": True, "message": "Rule removed from favorites"}, 200
        else:
            AccountModel.add_favorite(rule_id=rule_id, user_id=user.id)
            return {"success": True, "message": "Rule added to favorites"}, 200

###################################
#   Import rules from a github    #
###################################

@rule_private_ns.route('/import_rules_from_github')
@rule_private_ns.doc(
    description="""
Import detection rules of **any supported format** (e.g., YARA, Sigma, Suricata) from a **GitHub repository** into the system.  
**Only admin users** are allowed to perform this operation.

### Query Parameters

| Parameter | Type   | Required | Description |
|-----------|--------|----------|-------------|
| url       | string | Yes      | URL of the GitHub repository containing the rules to import. Must be a valid GitHub repository URL. |
| license   | string | Yes      | License to apply to the imported rules (e.g., MIT, GPL). |

### Headers

| Header     | Type   | Required | Description |
|------------|--------|----------|-------------|
| X-API-KEY  | string | Yes      | Your personal API key for authentication (must belong to an admin user). |

### Responses

- **200 OK** – Rules successfully imported.
  ```json
  {
    "success": true,
    "imported": 10,
    "skipped": 2,
    "failed": 0
  }


- **200 OK** Multi-Status – Some rules failed to import.
    ```json
    {
    "success": true,
    "imported": 8,
    "skipped": 2,
    "failed": 2
    }

- **400 Bad Request** – Invalid parameters or non-admin user.
    ```json
    {"success": false, "message": "Missing 'url' parameter"}

    {"success": false, "message": "You have to be an admin to import"}

- **500 Internal Server Error** – Error while cloning/accessing the repository or during rule extraction.
    ```json
    {
      "success": false,
      "message": "An error occurred while importing from: <repo_url>",
      "error": "<error details>"
    }

Example cURL Request

curl -X POST http://127.0.0.1:7009/api/rule/private/import_rules_from_github \
-H "Content-Type: application/json" \
-H "X-API-KEY: <ADMIN_API_KEY>" \
-d '{
    "url": "https://github.com/ecrou-exact/Test-pour-regle-yara-.git",
    "license": "MIT"
}'

"""
)
class ImportRulesFromGithub(Resource):
    @api_required
    @rule_private_ns.doc(params={
    "url": "Required. URL of the GitHub repository to import rules from",
    "license": "Required. License to apply to the imported rules (e.g., MIT, GPL)"
    })
    def post(self):
        """Import rules of any supported format from a GitHub repository (admin only)"""
        user = utils.get_user_from_api(request.headers)
        if not user:
            return {"success": False, "message": "Unauthorized"}, 403

        if not user.is_admin:
            return {"success": False, "message": "You have to be an admin to import"}, 400

        data = request.get_json(silent=True) or request.args.to_dict()
        repo_url = data.get('url')
        selected_license = data.get('license', '').strip()

        # Validation
        if not repo_url:
            return {"success": False, "message": "Missing 'url' parameter"}, 400
        if not selected_license:
            return {"success": False, "message": "Missing 'license' parameter"}, 400
        if not valider_repo_github(repo_url):
            return {"success": False, "message": "Invalid GitHub URL"}, 400

        # Clone or access repo
        repo_dir, exists = clone_or_access_repo(repo_url)
        if not repo_dir:
            return {"success": False, "message": "Failed to clone or access the repository"}, 500

        # Extract rules
        info = github_repo_metadata(repo_url, selected_license)
        try:
            bad_rules, imported, skipped = asyncio.run(extract_rule_from_repo(repo_dir, info , user))
            delete_existing_repo_folder("Rules_Github")
            response = {
                "success": True,
                "imported": imported,
                "skipped": skipped,
                "failed": bad_rules
            }

            return response, 200
        except Exception as e:
            return {
                "success": False,
                "message": f"An error occurred while importing from: {repo_url}",
                "error": str(e)
            }, 500

###################################
#   update rules from a github    #
###################################

# @rule_private_ns.route("/check_updates")
# @rule_private_ns.doc(
#     description="""
# Check if the selected rules have updates in their respective repositories.  
# This endpoint allows users to verify whether the rules they are tracking have been updated upstream.

# **Authentication:** Requires a valid **API Key** in the request headers.

# ### Query Parameters

# | Parameter | Type       | Required | Description |
# |-----------|------------|----------|-------------|
# | rules     | list[dict] | Yes      | A list of rules to check for updates. Each rule should be represented as an object containing `id` (integer, required) and optionally `title` (string). |

# ### Headers

# | Header     | Type   | Required | Description |
# |------------|--------|----------|-------------|
# | X-API-KEY  | string | Yes      | Your personal API key for authentication. |

# ### Responses

# - **200 OK** – Successfully checked updates.
#     ```json
#     {
#     "message": "Search completed successfully. All selected rules have been processed without issues.",
#     "nb_update": 3,
#     "results": [
#         {
#         "id": 2,
#         "title": "Example Rule 2",
#         "success": true,
#         "message": "Rule updated successfully",
#         "new_content": "rule example { condition: true }",
#         "old_content": "rule example { condition: false }",
#         "history_id": 101
#         }
#     ],
#     "success": true,
#     "toast_class": "success"
#     }

# - **403 Forbidden** – Missing or invalid API key.
#     ```json
#     {"success": false, "message": "Unauthorized"}

# - **400 Bad Request** – Invalid or missing rules parameter.
#     ```json
#     {"success": false, "message": "Missing or empty 'rules' parameter"}

# Example cURL Request

# curl -X POST http://127.0.0.1:7009/api/rule/private/check_updates \
# -H "Content-Type: application/json" \
# -H "X-API-KEY: <USER_API_KEY>" \
# -d '{
#     "rules": [
#         {"id": 2},{"id": 3}, {"id": 4},{"id": 5},{"id": 6},{"id": 7},{"id":8},{"id": 9},{"id": 10}
#     ]
# }'

# """
# )
# class RuleUpdateCheck(Resource):
#     @api_required
#     def post(self):
#         """Check updates for selected rules"""
#         user = utils.get_user_from_api(request.headers)
#         if not user:
#             return {"success": False, "message": "Unauthorized"}, 403

#         data = request.get_json()
#         rule_items = data.get("rules", [])
#         if not rule_items:
#             return {"success": False, "message": "Missing or empty 'rules' parameter"}, 400

#         results = []
#         for item in rule_items:
#             rule_id = item.get("id")
#             title = item.get("title", "Unknown Title")
#             rule = RuleModel.get_rule(rule_id)
#             message_dict, success, new_rule_content = Check_for_rule_updates(rule_id)

#             if success and new_rule_content:
#                 result = {
#                     "id": rule_id,
#                     "title": title,
#                     "success": success,
#                     "message": message_dict.get("message", "No message"),
#                     "new_content": new_rule_content,
#                     "old_content": rule.to_string if rule else "Error loading the rule"
#                 }

#                 history_id = RuleModel.create_rule_history(result)
#                 result["history_id"] = history_id if history_id is not None else None
#                 results.append(result)

#         return {
#             "message": "Search completed successfully. All selected rules have been processed without issues.",
#             "nb_update": len(results),
#             "results": results,
#             "success": True,
#             "toast_class": "success"
#         }, 200

#####################################################
#        dump of all the rules as open data         #
#####################################################
@rule_private_ns.route("/dumpRules")
@rule_private_ns.doc(
    description="""
Provide a complete structured JSON dump of all rules for analysis or integration.  
This endpoint is intended for advanced users, researchers, and analysts who want to access all rules as open data.

**Authentication:** Requires a valid **API Key** in the request headers.

### Headers

| Header     | Type   | Required | Description |
|------------|--------|----------|-------------|
| X-API-KEY  | string | Yes      | Your personal API key for authentication |

### Optional JSON Body Parameters

| Parameter       | Type                 | Required | Description |
|-----------------|--------------------|----------|-------------|
| format_name      | string or list      | No       | Filter rules by format(s). Example: `"yara"` or `["yara", "sigma"]`. Use `"all"` for all available formats. |
| created_after    | string (datetime)   | No       | Include rules created on or after this date. Format: `"YYYY-MM-DD"` or `"YYYY-MM-DD HH:MM"`. |
| created_before   | string (datetime)   | No       | Include rules created on or before this date. Format: `"YYYY-MM-DD"` or `"YYYY-MM-DD HH:MM"`. |
| updated_after    | string (datetime)   | No       | Include rules updated on or after this date. Format: `"YYYY-MM-DD"` or `"YYYY-MM-DD HH:MM"`. |
| updated_before   | string (datetime)   | No       | Include rules updated on or before this date. Format: `"YYYY-MM-DD"` or `"YYYY-MM-DD HH:MM"`. |
| top_liked        | integer             | No       | Return only the top N most liked rules. |
| top_disliked     | integer             | No       | Return only the top N most disliked rules. |

### Response

- **200 OK** – Successfully generated rules dump.
    ```json
    {
    "success": true,
    "message": "Rules dump successfully generated.",
    "filters_applied": {
        "format_name": ["yara", "sigma"],
        "created_after": "2025-10-01 00:00",
        "created_before": "2025-11-01 23:59",
        "updated_after": "2025-10-05",
        "updated_before": "2025-11-02",
        "top_liked": 10,
        "top_disliked": 5
    },
    "data": {
        "summary_by_format": {
        "yara": 120,
        "sigma": 75,
        "total_rules": 195
        },
        "rules": [
        {
            "id": 1,
            "title": "Example YARA Rule",
            "format": "yara",
            "author": "Alice",
            "created_at": "2025-10-02 15:30",
            "updated_at": "2025-10-20 12:00",
            "likes": 12,
            "dislikes": 0,
            "to_string": "rule example { condition: true }",
            "cve_id": "CVE-2025-1234"
        }
        ]
    }
    }

- **403 Forbidden** – Missing or invalid API key.
    ```json
    {"success": false, "message": "Unauthorized"}

- **400 Bad Request** – Invalid JSON body or filter parameters.
    ```json
    {"success": false, "message": "Invalid JSON body"}

- **404 Not Found** – No rules match the specified filters.
    ```json
    {"success": false, "message": "No rules found to dump."}

Example cURL Requests

- **Dump all rules :** 
    ```json
    curl -X POST http://127.0.0.1:7009/api/rule/private/dumpRules \
    -H "Content-Type: application/json" \
    -H "X-API-KEY: <USER_API_KEY>" \
    -d '{}'

- **Filter by multiple formats and date ranges :**
    ```json
    curl -X POST http://127.0.0.1:7009/api/rule/private/dumpRules \
    -H "Content-Type: application/json" \
    -H "X-API-KEY: <USER_API_KEY>" \
    -d '{
        "format_name": ["yara", "sigma"],
        "created_after": "2025-10-01 00:00",
        "created_before": "2025-11-01 23:59",
        "updated_after": "2025-10-05",
        "updated_before": "2025-11-02",
        "top_liked": 10,
        "top_disliked": 5
        }'

- **Dump all formats without filtering:**
    ```json
    curl -X POST http://127.0.0.1:7009/api/rule/private/dumpRules \
    -H "Content-Type: application/json" \
    -H "X-API-KEY: <USER_API_KEY>" \
    -d '{
        "format_name": ["all"]
        }'

"""
)
class DumpRules(Resource):
    @api_required

    def post(self):
        """Generate a full dump of all rules for analysis or integration"""
        user = utils.get_user_from_api(request.headers)
        if not user:
            return {"success": False, "message": "Unauthorized"}, 403

        data = request.get_json() or {}
        if not isinstance(data, dict):
            return {"success": False, "message": "Invalid JSON body"}, 400

        arg_dict = RuleModel.get_arg_filter_dump_rule(data)
        if arg_dict is None:
            return {"success": False, "message": "Failed to parse arguments"}, 400

        rules_data = RuleModel.get_all_rules_in_json_dump(arg_dict)
        if not rules_data or not rules_data.get("summary_by_format", {}).get("total_rules"):
            return {"success": False, "message": "No rules found to dump."}, 404

        safe_filters = RuleModel.make_json_safe(arg_dict)
        safe_data = RuleModel.make_json_safe(rules_data)

        return {
            "success": True,
            "message": "Rules dump successfully generated.",
            "filters_applied": safe_filters,
            "data": safe_data
        }, 200