import asyncio
from typing import Optional
from flask import Blueprint, request, url_for
from flask_restx import Api, Resource, Namespace

from app.db_class.db import Rule
from app.import_github_project.untils_import import clone_or_access_repo, delete_existing_repo_folder, git_pull_repo, github_repo_metadata, valider_repo_github
from app.import_github_project.update_github_project import Check_for_rule_updates
from app.misp.misp_core import content_convert_to_misp_object
from app.rule_type.main_format import extract_rule_from_repo, verify_syntax_rule_by_format
from app.utils import utils
from ..rule import rule_core as RuleModel
from ..account import account_core as AccountModel
from app.utils.decorators import api_required

# Create the blueprint
api_rule_blueprint = Blueprint('api_rule', __name__)
# rule_ns  = Namespace("rule", description="Endpoints to manage rules")

# https://rulezet.org/api/rule/doc/
# http://127.0.0.1:7009/api/rule/swagger.json

# Create the Flask-RESTx API
api = Api(api_rule_blueprint,
    title='Rulezet API',
    description='API to manage a rule management instance.',
    version='0.1',
    doc='/doc/'  
)

# Declare the two namespaces
public_ns = Namespace('public', description='Endpoints accessible without authentication')
private_ns = Namespace('private', description='Endpoints that require authentication')

# Register the namespaces
api.add_namespace(public_ns, path='/public')
api.add_namespace(private_ns, path='/private')

# ------------------------------------------------------------------------------------------------------------------- #
#                                               PUBLIC ENDPOINT                                                       #
# ------------------------------------------------------------------------------------------------------------------- #

###################
#   TEST  public  #
###################

@public_ns.route('/hello')
class HelloPublic(Resource):
    def get(self):
        return {"message": "Welcome to the public API!"}
    # curl -X GET http://127.0.0.1:7009/api/rule/public/hello

###################################
#   search rules Page    #
###################################

@public_ns.route('/searchPage')
@api.doc(description='Search for a rule by name, description, UUID, or author, with pagination support.')
class SearchRulePage(Resource):
    @api.doc(params={
        "search": "title for the rule",
        "author": "filter by author",
        "rule_type": "filter by rule type",
        "sort_by": "newest, oldest, most_likes, least_likes",
        "page": "page number (default=1)",
        "per_page": "items per page (default=10)"
    })
    def get(self):
        """
        Search and paginate rules.
        Query params:
          - search: keyword
          - author: filter by author
          - rule_type: filter by rule type
          - sort_by: newest, oldest, most_likes, least_likes
          - page: page number (default=1)
          - per_page: items per page (default=10)
        """
        search = request.args.get("search")
        author = request.args.get("author")
        sort_by = request.args.get("sort_by")
        rule_type = request.args.get("rule_type")
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 10, type=int)

        query = RuleModel.filter_rules(search, author, sort_by, rule_type)
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        # Build URLs for next and previous pages
        args = request.args.to_dict()  # convert ImmutableMultiDict to normal dict
        args.pop("page", None)
        args.pop("per_page", None)

        next_url = url_for("api_rule.public_search_rule_page", page=pagination.next_num, per_page=per_page, _external=True, **args) if pagination.has_next else None

        prev_url = url_for("api_rule.public_search_rule_page", page=pagination.prev_num, per_page=per_page, _external=True, **args) if pagination.has_prev else None



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
            for rule in pagination.items
        ]

        return {
            "total rule found": pagination.total,
            "pages": pagination.pages,
            "paggination":{
                "prev_page": prev_url,
                "current_page": pagination.page,
                "next_page": next_url,
            },
            "results": results,
        }, 200


# curl -G "http://127.0.0.1:7009/api/rule/publicsearchPage" \
#      --data-urlencode "search=detect" 

######################
#   search rules     #
######################

@public_ns.route('/search')
@api.doc(description='Search for a rule by name, description, UUID, or author, without pagination.')
class SearchRule(Resource):
    @api.doc(params={
        "search": "title for the rule",
        "author": "filter by author",
        "rule_type": "filter by rule type",
        "sort_by": "newest, oldest, most_likes, least_likes",
    })
    def get(self):
        """
        Search rules.
        Query params:
          - search: keyword
          - author: filter by author
          - rule_type: filter by rule type
          - sort_by: newest, oldest, most_likes, least_likes
        """
        # Récupération des paramètres
        search = request.args.get("search")
        author = request.args.get("author")
        sort_by = request.args.get("sort_by")
        rule_type = request.args.get("rule_type")
    
        # Filtrage des règles
        query = RuleModel.filter_rules(search, author, sort_by, rule_type)

        # Sérialisation de tous les résultats
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

        return {
            "total_rules_found": len(results),
            "results": results,
        }, 200
    
    # curl -G "http://127.0.0.1:7009/api/rule/public/search" \
    #  --data-urlencode "search=detect" \
    #  --data-urlencode "author=@malgamy12" \
    #  --data-urlencode "rule_type=malware" \
    #  --data-urlencode "sort_by=newest"

##################################
#   search rules  convert MISP   #
##################################

@public_ns.route('/Convert_MISP')
@api.doc(description='Search for a rule by name, description, UUID, or author and convert it into a MISP object if possible.')
class ConvertMISP(Resource):
    @api.doc(params={
        "search": "title for the rule",
        "author": "filter by author",
        "rule_type": "filter by rule type",
        "sort_by": "newest, oldest, most_likes, least_likes",
    })
    def get(self):
        """
        Search rules and convert them to MISP objects if possible.
        Query params:
          - search: keyword
          - author: filter by author
          - rule_type: filter by rule type
          - sort_by: newest, oldest, most_likes, least_likes
        """
        search = request.args.get("search")
        author = request.args.get("author")
        sort_by = request.args.get("sort_by")
        rule_type = request.args.get("rule_type")
    
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
    
    # curl -G "http://127.0.0.1:7009/api/rule/public/Convert_MISP" \
    #  --data-urlencode "search=mars" 
    
#############################
#   Get all rule's info     #
#############################

@public_ns.route('/detail/<int:rule_id>')
@api.doc(description='Detail of a rule')
class DetailRule(Resource):
    def get(self , rule_id):
        """Get the details of a rule by its ID"""
        rule = RuleModel.get_rule(rule_id)
        if not rule:
            return {"message": "Rule not found"}, 404
        
        author = AccountModel.get_user(rule.user_id)
        if not author:
            return {"message": "User not found"}, 404

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
            "original_uuid" : rule.original_uuid,
            "user_id": {
                "id": author.id,
                "first_name": author.first_name,
                "last_name": author.last_name
            }
        }, 200
    
    # curl -X GET http://127.0.0.1:7009/api/rule/public/detail/6

    #############################
    #   Get all rules by user   #
    #############################

    @public_ns.route('/all_by_user/<int:user_id>')
    @api.doc(description='Get all rules created by a specific user')
    class RulesByUser(Resource):
        def get(self, user_id):
            """Get all rules authored by a user"""
            user = AccountModel.get_user(user_id)
            if not user:
                return {"message": "User not found"}, 404
            
            

            rules = RuleModel.get_all_rules_by_user(user_id)
            if not rules:
                return {"message": "No rules found for this user", "rules": []}, 200
            
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
                    "original_uuid" : rule.original_uuid,
                    "user_id": {
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
        
        # curl -X GET http://127.0.0.1:7009/api/rule/public/all_by_user/4


    ##############################
    #   Get all rules by CVE id  #
    ##############################


    @public_ns.route('/search_rules_by_cve')
    @api.doc(description='Search all rules matching one or more CVE or vulnerability IDs')
    class RulesByCVE(Resource):
        @api.doc(params={
            "cve_ids": "title for the rule",
        })
        def get(self):
            """
            Query rules by CVE ID(s). 
            Accepts `cve_ids` as comma-separated string, e.g.:
            /search_rules_by_cve?cve_ids=CVE-2021-34567,GHSA-xy12-zw34-ab56,....
            """

            # Parse input CVE(s)
            raw_cve_ids = request.args.get('cve_ids', '')
            if not raw_cve_ids:
                return {"error": "No CVE IDs provided."}, 400

            success , cve_patterns = utils.detect_cve(raw_cve_ids) 

            if not success:
                return {"error": "No match for CVE id"}

            rules = RuleModel.search_rules_by_cve_patterns(cve_patterns)

            #  Build JSON response by cve patterns
            
            return {
                "count": len(rules),
                "cve_patterns": cve_patterns,
                "rules": rules
            }, 200

    # http://127.0.0.1:7009/api/rule/public/search_rules_by_cve?cve_ids=CVE-2021-34567,GHSA-xy12-zw34-ab56



# ------------------------------------------------------------------------------------------------------------------- #
#                                       PRIVATE ENDPOINT (auth required)                                              # 
# ------------------------------------------------------------------------------------------------------------------- #

######################
#   TEST connection  #
######################

@private_ns.route('/me')
class HelloPrivate(Resource):
    @api_required
    def get(self):
        """Get the current user information"""
        user = utils.get_user_from_api(request.headers)
        return {
            "message": f"Welcome {user.first_name}!",
            "user_id": user.id
        }
    # curl -X GET http://127.0.0.1:7009/api/rule/private/me -H "X-API-KEY: user_api_key"

#####################
#   Create a rule   #
#####################

@private_ns.route('/create')
@api.doc(description='Create a rule')
class CreateRule(Resource):
    @api_required
    @api.doc(params={
        "title": "Required. Title for the rule",
        "description": "Description of the rule",
        "version": "Version of the rule",
        "format": "Rule format (e.g., yara, sigma)",
        "license": "License applied to the rule",
        "source": "Origin/source of the rule",
        "to_string": "String representation of the rule content",
        "original_uuid" : "the reel uuid of the rule if you want to create it ",
        "cve_id ": "Optional. CVE ID associated with the rule"
    })
    def post(self):
        """Create a new rule"""
        user = utils.get_user_from_api(request.headers)

        data = request.get_json(silent=True)
        if not data:
            data = request.args.to_dict()

        # Champs obligatoires
        required_fields = ["title", "format", "version", "to_string", "license"]
        missing_fields = [field for field in required_fields if not data.get(field) or not str(data.get(field)).strip()]
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
            'description': data.get("description", "").strip() or "No description for the rule",
            'version': data.get("version").strip(),
            'source': data.get("source", "").strip() or " {user.first_name}, {user.last_name}",
            'to_string': data.get("to_string").strip(),
            'license': data.get("license").strip(),
            'original_uuid': data.get("original_uuid") or None,
            'author': user.first_name,
            'cve_id': data.get("cve_id") if cve_id else None
        }

        is_valid, error_msg = verify_syntax_rule_by_format(form_dict)
        if not is_valid:
            return {"message": "Invalid rule ", "error": error_msg}, 400  

        verif = RuleModel.add_rule_core(form_dict, user)
        if verif:
            return {"message": "Rule added successfully", "rule": verif.to_dict()}, 200
        return {"message": "Failed to add rule"}, 500 

    
    # curl -X POST http://127.0.0.1:7009/api/rule/private/create \
    # -H "Content-Type: application/json" \
    # -H "X-API-KEY: urW4F3wh93cAh18PIegFdFXOr8m09mH9sAq4sFK1ZKyAkaVx2wfVBIS1hU4b" \
    # -d '{
    #     "title": "My N Rule",
    #     "format": "yara",
    #     "version": "1.0",
    #     "to_string": "rule example { condition: true }",
    #     "license": "MIT",
    #     "original_uuid": "wd334sda",
    #     "description": "This is a test rule",
    #     "source": "unit-test",
    #     "cve_id": "CVE-2023-12345"
    # }'


        
         

#####################
#   Delete a rule   #
#####################

@private_ns.route('/delete')
@api.doc(description='Delete a rule')
class DeleteRule(Resource):
    @api_required
    @api.doc(params={
        "title": "Title of the rule to delete (required)"
    })
    def post(self):
        user = utils.get_user_from_api(request.headers)
        if not user:
            return {
                "success": False,
                "message": "Unauthorized: invalid or missing API key"
            }, 401
        data = request.get_json(silent=True)
        if data is None:
            return {
                "success": False,
                "message": "Missing JSON body"
            }, 400

        title = data.get('title', '').strip()
        if not title:
            return {
                "success": False,
                "message": "Missing or empty 'title' parameter"
            }, 400


        rule_id = RuleModel.get_rule_id_by_title(title)
        if not rule_id:
            return {
                "success": False,
                "message": f"No rule found with title '{title}'"    
            }, 404

        rule_owner_id = RuleModel.get_rule_user_id(rule_id)

        if rule_owner_id is None:
            return {
                "success": False,
                "message": "Rule owner not found"
            }, 404
        if user.id == rule_owner_id or user.is_admin():
            success = RuleModel.delete_rule_core(rule_id)
            if success:
                return {
                    "success": True,
                    "message": f"Rule '{title}' deleted successfully"
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

    # curl  -X POST http://127.0.0.1:7009/api/rule/private/delete \                                                                         
    # -H "Content-Type: application/json" \
    #       -H "X-API-KEY: user_api_key" \
    #       -d '{"title": "Theo"}'

###################
#   Edit a rule   #
###################

# @private_ns.route('/edit/<int:rule_id>')
# @api.doc(description="Edit a rule")
# class EditRule(Resource):
#     @api_required
#     def post(self, rule_id):
#         user = utils.get_user_from_api(request.headers)
#         if not user:
#             return {"success": False, "message": "Unauthorized"}, 403

#         rule = RuleModel.get_rule(rule_id)
#         if not rule:
#             return {"success": False, "message": "Rule not found"}, 404

#         user_id = RuleModel.get_rule_user_id(rule_id)
#         if user.id != user_id and not user.is_admin():
#             return {"success": False, "message": "Access denied"}, 403

#         data = request.get_json(silent=True)
#         if not data:
#             data = request.args.to_dict()


#         title = data.get("title", rule.title).strip()
#         format_ = data.get("format", rule.format).strip()
#         version = data.get("version", rule.version).strip()
#         to_string = data.get("to_string", rule.to_string).strip()
#         license_ = data.get("license", rule.license).strip()
#         description = data.get("description", rule.description or "").strip() or "No description for the rule"
#         source = data.get("source", rule.source or "").strip() or f"{user.first_name}, {user.last_name}"
#         cve_id = data.get("cve_id", rule.cve_id)

#         required_fields = {
#             "title": title,
#             "format": format_,
#             "version": version,
#             "to_string": to_string,
#             "license": license_,
#         }

#         missing_fields = [k for k, v in required_fields.items() if not v or not str(v).strip()]
#         if missing_fields:
#             return {"success": False, "message": f"Missing or empty fields: {', '.join(missing_fields)}"}, 400


#         existing_rule = Rule.query.filter_by(title=title).first()
#         if existing_rule and existing_rule.id != rule_id:
#             return {"success": False, "message": "Another rule with this title already exists"}, 409


#         if cve_id:
#             valid, matches = utils.detect_cve(cve_id)
#             if not valid:
#                 return {"success": False, "message": "Invalid CVE ID format or not recognized"}, 400

#         form_dict = {
#             'title': title,
#             'format': format_,
#             'description': description,
#             'version': version,
#             'source': source,
#             'to_string': to_string,
#             'license': license_,
#             'author': user.first_name,
#             'cve_id': cve_id if cve_id else None
#         }

#         external_vars = []

#         if format_ == 'yara':
#             valid, to_string, error = RuleModel.compile_yara(external_vars, form_dict)
#             if not valid:
#                 return {"success": False, "message": error}, 400
#         elif format_ == 'sigma':
#             valid, to_string, error = RuleModel.compile_sigma(form_dict)
#             if not valid:
#                 return {"success": False, "message": error}, 400
#         else:
#             return {"success": False, "message": "Unsupported rule format"}, 400

#         success , result = RuleModel.edit_rule_core(form_dict, rule_id)
#         if result:
#             return {"success": True, "message": "Rule updated successfully"}, 200
#         return {"success": False, "message": "Failed to update rule"}, 500

        # curl -X POST http://127.0.0.1:7009/api/rule/private/edit/3 \
        #   -H "Content-Type: application/json" \
        #   -H "X-API-KEY: user_api_key" \
        #   -d '{
        #     "title": "New Rule Title",
        #     "description": "Updated description only"
        #   }'

######################
#   favorite  rule   #
######################

@private_ns.route('/favorite/<int:rule_id>')
@api.doc(description="Add or remove a rule from user's favorites")
class FavoriteRule(Resource):
    @api_required
    def get(self, rule_id):
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
        
    # curl -X GET http://127.0.0.1:7009/api/rule/private/favorite/4 -H "X-API-KEY: user_api_key"

###################################
#   Import rules from a github    #
###################################

@private_ns.route('/import_rules_from_github')
@api.doc(description="Import YARA rules from a GitHub repository")
class ImportRulesFromGithub(Resource):
    @api_required
    @api.doc(params={
        "url": "Required. URL of the GitHub repository to import rules from",
        "license": "Optional. License to apply to the imported rules"
    })
    def post(self):
        user = utils.get_user_from_api(request.headers)
        if not user:
            return {"success": False, "message": "Unauthorized"}, 403

        if user.is_admin:
            data = request.get_json(silent=True) or request.args.to_dict()
            repo_url = data.get('url')
            if not repo_url:
                return {"success": False, "message": "Missing 'url' parameter"}, 400

            selected_license = data.get('license', '').strip()
            if not selected_license:
                return {"success": False, "message": "Missing 'license' parameter"}, 400


            if not valider_repo_github(repo_url):
                return {"success": False, "message": "Invalid GitHub URL"}, 400


            repo_dir, exists = clone_or_access_repo(repo_url)
            if not repo_dir:
                return {"success": False, "message": "Failed to clone or access the repository"}, 500


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

                if bad_rules > 0:
                    return response, 207  

                return response, 200

            except Exception as e:
                return {
                    "success": False,
                    "message": f"An error occurred while importing from: {repo_url}",
                    "error": str(e)
                }, 500
        else:
            return {"success": False, "message": "You have to be an admin to import"}, 400


    # curl -X POST http://127.0.0.1:7009/api/rule/private/import_rules_from_github \
    # -H "Content-Type: application/json" \
    # -H "X-API-KEY: user_api_key " \
    # -d '{
    #     "url": "https://github.com/ecrou-exact/Test-pour-regle-yara-.git",
    #     "license": "MIT"
    # }'

###################################
#   update rules from a github    #
###################################

@private_ns.route("/check_updates")
@api.doc(description="Check if selected rules have updates in their respective repositories")
class RuleUpdateCheck(Resource):
    @api_required
    def post(self):
        user = utils.get_user_from_api(request.headers)
        if not user:
            return {"success": False, "message": "Unauthorized"}, 403

        data = request.get_json()
        rule_items = data.get("rules", [])  # id only
        results = []

        # sources = RuleModel.get_sources_from_ids(rule_items)
        # for source in sources:
        #     repo_dir, exists = clone_or_access_repo(source)
        #     git_pull_repo(repo_dir)

        for item in rule_items:
            rule_id = item.get("id")
            title = item.get("title", "Unknown Title")
            rule = RuleModel.get_rule(rule_id)
            message_dict, success, new_rule_content = Check_for_rule_updates(rule_id)

            if success and new_rule_content:
                result = {
                    "id": rule_id,
                    "title": title,
                    "success": success,
                    "message": message_dict.get("message", "No message"),
                    "new_content": new_rule_content,
                    "old_content": rule.to_string if rule else "Error loading the rule"
                }

                history_id = RuleModel.create_rule_history(result)
                result["history_id"] = history_id if history_id is not None else None

                results.append(result)

        return {
            "message": "Search completed successfully. All selected rules have been processed without issues.",
            "nb_update": len(results),
            "results": results,
            "success": True,
            "toast_class": "success"
        }, 200

# curl -X POST http://127.0.0.1:7009/api/rule/private/check_updates \
#     -H "Content-Type: application/json" \
#     -H "X-API-KEY: user_api_key" \
#     -d '{
#         "rules": [
#             {"id": 2},{"id": 3}, {"id": 4},{"id": 5},{"id": 6},{"id": 7},{"id":8},{"id": 9},{"id": 10}
#         ]
#     }'


#####################################################
#        dump of all the rules as open data         #
#####################################################
@private_ns.route("/dumpRules")
@api.doc(description="Provide a complete dump of all rules as open data.")
class DumpRules(Resource):
    @api_required
    def post(self):
        """
        Provide a structured JSON dump of all rules for open data analysis.

        This endpoint allows exporting all existing rules in a structured JSON format
        suitable for research, data analytics, or external integrations.

        Optional JSON parameters for filtering:
          - format_name: string or list (e.g., "text" or ["text", "video"])
          - created_after: "YYYY-MM-DD HH:MM" or "YYYY-MM-DD"
          - created_before: "YYYY-MM-DD HH:MM" or "YYYY-MM-DD"
          - updated_after: "YYYY-MM-DD HH:MM" or "YYYY-MM-DD"
          - updated_before: "YYYY-MM-DD HH:MM" or "YYYY-MM-DD"
          - top_liked: integer (top N most liked rules)
          - top_disliked: integer (top N most disliked rules)

        Returns:
            JSON response containing all rules and summary statistics.
        """
        user = utils.get_user_from_api(request.headers)
        if not user:
            return {"success": False, "message": "Unauthorized"}, 403

        data = request.get_json() or {}
        if not isinstance(data, dict):
            return {"success": False, "message": "Invalid JSON body"}, 400

        # Parse filters (may contain datetime objects)
        arg_dict = RuleModel.get_arg_filter_dump_rule(data)
        if arg_dict is None:
            return {"success": False, "message": "Failed to parse arguments"}, 400

        # Generate JSON dump (rule.to_json should already return strings for dates)
        rules_data = RuleModel.get_all_rules_in_json_dump(arg_dict)
        if not rules_data or not rules_data.get("summary_by_format", {}).get("total_rules"):
            return {"success": False, "message": "No rules found to dump."}, 404

        # Make response JSON-safe: convert datetimes to strings
        safe_filters = RuleModel.make_json_safe(arg_dict)
        safe_data = RuleModel.make_json_safe(rules_data)

        return {
            "success": True,
            "message": "Rules dump successfully generated.",
            "filters_applied": safe_filters,
            "data": safe_data
        }, 200

    

# curl -X POST http://127.0.0.1:7009/api/rule/private/dumpRules \
#     -H "Content-Type: application/json" \
#     -H "X-API-KEY: user_api_key" \
#     -d '{}'


# curl -X POST http://127.0.0.1:7009/api/rule/private/dumpRules \
#      -H "Content-Type: application/json" \
#      -H "X-API-KEY: user_api_key" \
#      -d '{
#            "format_name": ["yara", "sigma"],
#            "created_after": "2025-10-01 00:00",
#            "created_before": "2025-11-01 23:59",
#            "updated_after": "2025-10-05",
#            "updated_before": "2025-11-02",
#            "top_liked": 10,
#            "top_disliked": 5
#          }'

# curl -X POST http://127.0.0.1:7009/api/rule/private/dumpRules \
#      -H "Content-Type: application/json" \
#      -H "X-API-KEY: user_api_key" \
#      -d '{
#            "format_name": ["all"]
#          }'