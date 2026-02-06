# ------------------------------------------------------------------------------------------------------------------- #
#                                               PUBLIC ENDPOINT                                                       #
# ------------------------------------------------------------------------------------------------------------------- #

import json
from typing import Optional
from flask import request, url_for
from flask_restx import Resource, Namespace

from app.api.utils.rule_validation import *
from app.misp.misp_core import content_convert_to_misp_object
from app.utils import utils
from ...rule import rule_core as RuleModel
from ...account import account_core as AccountModel
from flask_restx import Namespace, Resource


rule_public_ns = Namespace(
    "Public action on Rule ✅",
    description="Public rule operations"
)

###################################
#       search rules Page         #
###################################

@rule_public_ns.route('/searchPage')
@rule_public_ns.doc(
    description="""
Search for rules by **title**, **description**, **UUID**, or **author**, with pagination support.

### Query Parameters

| Parameter  | Type    | Description                                                                 |
|------------|---------|-----------------------------------------------------------------------------|
| search     | string  | Keyword to search in rule title                                              |
| author     | string  | Filter rules by author                                                       |
| rule_type  | string  | Filter by rule type                                                          |
| sort_by    | string  | Sorting option: `newest`, `oldest`, `most_likes`, `least_likes`             |
| page       | integer | Page number (default=1)                                                     |
| per_page   | integer | Items per page (default=10)                                                 |

### Example cURL Request


```bash
curl -G "http://127.0.0.1:7009/api/rule/public/searchPage" \
--data-urlencode "search=detect" \
--data-urlencode "author=John" \
--data-urlencode "sort_by=newest" \
--data-urlencode "page=1" \
--data-urlencode "per_page=10"
```
"""
)
@rule_public_ns.route('/searchPage')
class SearchRulePage(Resource):

    @rule_public_ns.doc(params={
        "search": "Keyword to search in rule title",
        "author": "Filter rules by author",
        "rule_type": "Filter by rule type",
        "sort_by": "Sorting option: newest, oldest, most_likes, least_likes",
        "page": "Page number (default=1)",
        "per_page": "Items per page (default=10)"
    })
    def get(self):
        """
        Search and paginate rules.
        """

        # Get query params
        search = request.args.get("search")
        author = request.args.get("author")
        sort_by = request.args.get("sort_by")
        rule_type = request.args.get("rule_type")

        page = request.args.get("page", default=1, type=int)
        per_page = request.args.get("per_page", default=10, type=int)


        # ------------
        #  Validation
        # ------------

        try:
            validate_search_param(search)
            validate_author_param(author)
            validate_sort_by_param(sort_by, allowed_sort={"newest", "oldest", "most_likes", "least_likes"})
            verify_rule_format(rule_type)
            validate_page_param(page)
            validate_per_page_param(per_page)
        except ValueError as e:
            return {"error": str(e)}, 400

        # Query filtered rules
        query = RuleModel.filter_rules(search, author, sort_by, rule_type)
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        # Prepare base arguments (keep filters but remove pagination)
        args = request.args.to_dict(flat=False)
        args.pop("page", None)
        args.pop("per_page", None)

        # Dynamic endpoint (auto-detect)
        endpoint = request.endpoint

        # Build next/prev URLs
        next_url = (
            url_for(endpoint, page=pagination.next_num, per_page=per_page,
                    _external=True, **args)
            if pagination.has_next else None
        )

        prev_url = (
            url_for(endpoint, page=pagination.prev_num, per_page=per_page,
                    _external=True, **args)
            if pagination.has_prev else None
        )

        # Serialize results
        results = []
        for rule in pagination.items:
            results.append({
                "uuid": rule.uuid,
                "title": rule.title,
                "description": rule.description,
                "author": rule.author,
                "creation_date": rule.creation_date.isoformat(),
                "format": rule.format,
                "content": rule.to_string
            })

        # Final response
        return {
            "total_rules_found": pagination.total,
            "total_pages": pagination.pages,
            "pagination": {
                "prev_page": prev_url,
                "current_page": pagination.page,
                "next_page": next_url,
            },
            "results": results,
        }, 200



###################################
#   search rules (no pagination)  #
###################################
@rule_public_ns.route('/search')
@rule_public_ns.doc(
    description="""
Search for rules by **title**, **description**, **UUID**, or **author**, without pagination.

### Query Parameters

| Parameter  | Type    | Description                                                                 |
|------------|---------|-----------------------------------------------------------------------------|
| search     | string  | Keyword to search in rule title                                              |
| author     | string  | Filter rules by author                                                       |
| rule_type  | string  | Filter by rule type                                                          |
| sort_by    | string  | Sorting option: `newest`, `oldest`, `most_likes`, `least_likes`             |

### Example cURL Request

```bash
curl -G "http://127.0.0.1:7009/api/rule/public/search" \
     --data-urlencode "search=detect" \
     --data-urlencode "author=@malgamy12" \
     --data-urlencode "rule_type=malware" \
     --data-urlencode "sort_by=newest"

"""
)
class SearchRule(Resource):
    @rule_public_ns.doc(params={
    "search": "Keyword to search in rule title",
    "author": "Filter rules by author",
    "rule_type": "Filter by rule type",
    "sort_by": "Sorting option: newest, oldest, most_likes, least_likes",
    })
    def get(self):
        """
        Search rules without pagination.
        """
        # Retrieve query parameters
        search = request.args.get("search")
        author = request.args.get("author")
        sort_by = request.args.get("sort_by")
        rule_type = request.args.get("rule_type")


        # ------------
        #  Validation
        # ------------

        try:
            validate_search_param(search)
            validate_author_param(author)
            validate_sort_by_param(sort_by, allowed_sort={"newest", "oldest", "most_likes", "least_likes"})
            verify_rule_format(rule_type)
        except ValueError as e:
            return {"error": str(e)}, 400


        # Filter rules
        query = RuleModel.filter_rules(search, author, sort_by, rule_type)

        # Serialize results
        results = [
            {
                "uuid": rule.uuid,
                "title": rule.title,
                "description": rule.description,
                "author": rule.author,
                "creation_date": rule.creation_date.isoformat(),
                "format": rule.format,
                "content": rule.to_string
            }
            for rule in query
        ]

        # Return results
        return {
            "total_rules_found": len(results),
            "results": results,
        }, 200


##################################
#   search rules  convert MISP   #
##################################

@rule_public_ns.route('/Convert_MISP')
@rule_public_ns.doc(
    description="""
Search for rules by **title**, **description**, **UUID**, or **author** and convert them into MISP objects if possible.

### Query Parameters

| Parameter  | Type    | Description                                                                 |
|------------|---------|-----------------------------------------------------------------------------|
| search     | string  | Keyword to search in rule title                                             |
| author     | string  | Filter rules by author                                                      |
| rule_type  | string  | Filter by rule type                                                         |
| sort_by    | string  | Sorting option: `newest`, `oldest`, `most_likes`, `least_likes`             |

### Example cURL Request

```bash
curl -G "http://127.0.0.1:7009/api/rule/public/Convert_MISP" \
--data-urlencode "search=mars" \
--data-urlencode "author=John" \
--data-urlencode "rule_type=malware" \
--data-urlencode "sort_by=newest"
```
"""
)
class ConvertMISP(Resource):
    @rule_public_ns.doc(params={
    "search": "Keyword to search in rule title",
    "author": "Filter rules by author",
    "rule_type": "Filter by rule type",
    "sort_by": "Sorting option: newest, oldest, most_likes, least_likes"
    })
    def get(self):
        """
        Search rules and convert them to MISP objects if possible.
        """
        search = request.args.get("search")
        author = request.args.get("author")
        sort_by = request.args.get("sort_by")
        rule_type = request.args.get("rule_type")
        
        # ------------
        #  Validation
        # ------------

        try:
            validate_search_param(search)
            validate_author_param(author)
            validate_sort_by_param(sort_by, allowed_sort={"newest", "oldest", "most_likes", "least_likes"})
            verify_rule_format(rule_type)
        except ValueError as e:
            return {"error": str(e)}, 400

        query = RuleModel.filter_rules(search, author, sort_by, rule_type)

        def convert_rule(rule_id: int) -> Optional[dict]:
            try:
                misp_json = content_convert_to_misp_object(rule_id)
                return misp_json
            except Exception:
                return None

        results = []
        for rule in query:
            misp_obj = convert_rule(rule.id)
            results.append({
                "uuid": rule.uuid,
                "title": rule.title,
                "description": rule.description,
                "author": rule.author,
                "creation_date": rule.creation_date.isoformat(),
                "format": rule.format,
                "content": rule.to_string,
                "misp_object": misp_obj
            })

        return {
            "total_rules_found": len(results),
            "results": results,
        }, 200
    
#############################
#   Get all rule's info     #
#############################

@rule_public_ns.route('/detail/<int:rule_id>')
@rule_public_ns.doc(
    description="""
Retrieve the full details of a rule using its **unique rule ID**.

### Path Parameter

| Parameter | Type | Description                       |
|-----------|------|-----------------------------------|
| rule_id   | int  | The ID of the rule to retrieve    |

### Example cURL Request

```bash
curl -X GET "http://127.0.0.1:7009/api/rule/public/detail/6"
```
"""
)
class DetailRule(Resource):
    def get(self, rule_id):
        """
        Get the details of a rule by its ID.
        """
        # Retrieve rule
        rule = RuleModel.get_rule(rule_id)
        if not rule:
            return {"message": "Rule not found"}, 404

        # Retrieve author
        author = AccountModel.get_user(rule.user_id)
        if not author:
            return {"message": "User not found"}, 404

        # Return full rule details
        return {
            "id": rule.id,
            "title": rule.title,
            "format": rule.format,
            "version": rule.version,
            "to_string": rule.to_string,
            "description": rule.description or "No description for the rule",
            "source": rule.source or f"{rule.author.first_name}, {rule.author.last_name}",
            "license": rule.license,
            "cve_id": rule.cve_id,
            "original_uuid": rule.original_uuid,
            "user": {
                "id": author.id,
                "first_name": author.first_name,
                "last_name": author.last_name
            }
        }, 200

    #############################
    #   Get all rules by user   #
    #############################

@rule_public_ns.route('/all_by_user/<int:user_id>')
@rule_public_ns.doc(
    description="""
Retrieve **all rules authored by a specific user**, identified by their unique `user_id`.

### Path Parameter

| Parameter | Type | Description                           |
|-----------|------|---------------------------------------|
| user_id   | int  | The ID of the user whose rules to get |

### Example cURL Request

```bash
curl -X GET "http://127.0.0.1:7009/api/rule/public/all_by_user/4"
```
"""
)
class RulesByUser(Resource):
    def get(self, user_id):
        """
        Get all rules created by a specific user.
        """
        # Fetch user
        user = AccountModel.get_user(user_id)
        if not user:
            return {"message": "User not found"}, 404

        # Fetch rules authored by the user
        rules = RuleModel.get_all_rules_by_user(user_id)
        if not rules:
            return {
                "message": "No rules found for this user",
                "rules": [],
                "success": True
            }, 200

        # Serialize rules
        result = []
        for rule in rules:
            result.append({
                "id": rule.id,
                "title": rule.title,
                "format": rule.format,
                "version": rule.version,
                "to_string": rule.to_string,
                "description": rule.description or "No description for the rule",
                "source": rule.source or f"{user.first_name}, {user.last_name}",
                "license": rule.license,
                "cve_id": rule.cve_id,
                "original_uuid": rule.original_uuid,
                "user": {
                    "id": user.id,
                    "first_name": user.first_name,
                    "last_name": user.last_name
                }
            })

        return {
            "message": f"{len(result)} rules found for user {user.first_name} {user.last_name}",
            "rules": result,
            "success": True
        }, 200


    ##############################
    #   Get all rules by CVE id  #
    ##############################


@rule_public_ns.route('/search_rules_by_cve')
@rule_public_ns.doc(
    description="""
Search for all rules that match specific **CVE IDs** or **vulnerability identifiers** (GHSA, PYSEC, etc.).

This endpoint automatically detects and normalizes vulnerability patterns from the input string, then performs a broad search across the rules database.

### Query Parameter

| Parameter | Type   | Description                                                                 |
|-----------|--------|-----------------------------------------------------------------------------|
| cve_ids   | string | A comma-separated list or a raw string containing one or more vulnerability IDs |

### Example cURL Request

```bash
curl -G "http://127.0.0.1:7009/api/rule/public/search_rules_by_cve" \
    --data-urlencode "cve_ids=CVE-2021-44228,GHSA-j8v8-6h6r-m6pq"

""",
params={'cve_ids': 'One or more vulnerability identifiers (CVE, GHSA, etc.)'} ) 

class RulesByCVE(Resource): 
    def get(self): 
        """ Search rules by vulnerability identifiers """ 
        raw_input = request.args.get('cve_ids', '') 
        if not raw_input: 
            return {"error": "No IDs provided."}, 400
        # utils.detect_cve returns (True, '["CVE-XXXX"]')
        success, cve_json = utils.detect_cve(raw_input)
        
        if not success:
            return {"error": "Detection failed."}, 500

        # Load the JSON string into a Python list
        cve_patterns = json.loads(cve_json)
        
        if not cve_patterns:
            return {"error": "No valid identifiers detected."}, 404

        # Search the database using the cleaned list
        result = RuleModel.search_rules_by_cve_patterns(cve_patterns)

        return {
            "detected_patterns": cve_patterns, 
            "total_matches": result.get("total_all_rules", 0),
            "stats": result.get("totals", 0),
            "results": result.get("rules", []) 
        }, 200