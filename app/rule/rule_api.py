import asyncio
from flask import Blueprint, request
from flask_restx import Api, Resource, Namespace, fields
from flask_login import current_user

from app.db_class.db import Rule
from app.import_github_project.import_github_Zeek import read_and_parse_all_zeek_scripts_from_folder
from app.import_github_project.import_github_sigma import load_rule_files
from app.import_github_project.import_github_suricata import parse_and_import_suricata_rules_async
from app.import_github_project.import_github_yara import parse_yara_rules_from_repo_async
from app.import_github_project.untils_import import clone_or_access_repo, delete_existing_repo_folder, extract_owner_repo, get_github_repo_author, get_license_name
from app.utils import utils
from ..rule import rule_core as RuleModel
from ..account import account_core as AccountModel
from app.utils.decorators import api_required

# Create the blueprint
api_rule_blueprint = Blueprint('api_rule', __name__)

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
            return {"message": "Author not found"}, 404

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
            "user_id": {
                "id": author.id,
                "first_name": author.first_name,
                "last_name": author.last_name
            }
        }, 200
    
    # curl -X GET http://127.0.0.1:7009/api/rule/public/detail/6

    

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
            'author': user.first_name,
            'cve_id': data.get("cve_id") if cve_id else None
        }

        external_vars = []  

        if form_dict['format'] == 'yara':
            valide, to_string, error = RuleModel.compile_yara(external_vars, form_dict)
            if not valide:
                return {"message": "Invalid YARA rule", "error": error}, 400  
        elif form_dict['format'] == 'sigma':
            valide, to_string, error = RuleModel.compile_sigma(form_dict)
            if not valide:
                return {"message": "Invalid Sigma rule", "error": error}, 400 

        verif = RuleModel.add_rule_core(form_dict, user)
        if verif:
            return {"message": "Rule added successfully", "rule": verif.to_dict()}, 200
        return {"message": "Failed to add rule"}, 500 

    
        # curl -X POST http://127.0.0.1:7009/api/rule/private/create   
        #       -H "Content-Type: application/json"   -H "X-API-KEY: user_api_key"   -d '{
        #     "title": "My N Rule",
        #     "format": "yara",
        #     "version": "1.0",
        #     "to_string": "rule example { condition: true }",
        #     "license": "MIT",
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
        print(rule_owner_id)
        print(user.id)
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

@private_ns.route('/edit/<int:rule_id>')
@api.doc(description="Edit a rule")
class EditRule(Resource):
    @api_required
    def post(self, rule_id):
        user = utils.get_user_from_api(request.headers)
        if not user:
            return {"success": False, "message": "Unauthorized"}, 403

        rule = RuleModel.get_rule(rule_id)
        if not rule:
            return {"success": False, "message": "Rule not found"}, 404

        user_id = RuleModel.get_rule_user_id(rule_id)
        if user.id != user_id and not user.is_admin():
            return {"success": False, "message": "Access denied"}, 403

        data = request.get_json(silent=True)
        if not data:
            data = request.args.to_dict()


        title = data.get("title", rule.title).strip()
        format_ = data.get("format", rule.format).strip()
        version = data.get("version", rule.version).strip()
        to_string = data.get("to_string", rule.to_string).strip()
        license_ = data.get("license", rule.license).strip()
        description = data.get("description", rule.description or "").strip() or "No description for the rule"
        source = data.get("source", rule.source or "").strip() or f"{user.first_name}, {user.last_name}"
        cve_id = data.get("cve_id", rule.cve_id)

        required_fields = {
            "title": title,
            "format": format_,
            "version": version,
            "to_string": to_string,
            "license": license_,
        }

        missing_fields = [k for k, v in required_fields.items() if not v or not str(v).strip()]
        if missing_fields:
            return {"success": False, "message": f"Missing or empty fields: {', '.join(missing_fields)}"}, 400


        existing_rule = Rule.query.filter_by(title=title).first()
        if existing_rule and existing_rule.id != rule_id:
            return {"success": False, "message": "Another rule with this title already exists"}, 409


        if cve_id:
            valid, matches = utils.detect_cve(cve_id)
            if not valid:
                return {"success": False, "message": "Invalid CVE ID format or not recognized"}, 400

        form_dict = {
            'title': title,
            'format': format_,
            'description': description,
            'version': version,
            'source': source,
            'to_string': to_string,
            'license': license_,
            'author': user.first_name,
            'cve_id': cve_id if cve_id else None
        }

        external_vars = []

        if format_ == 'yara':
            valid, to_string, error = RuleModel.compile_yara(external_vars, form_dict)
            if not valid:
                return {"success": False, "message": error}, 400
        elif format_ == 'sigma':
            valid, to_string, error = RuleModel.compile_sigma(form_dict)
            if not valid:
                return {"success": False, "message": error}, 400
        else:
            return {"success": False, "message": "Unsupported rule format"}, 400

        result = RuleModel.edit_rule_core(form_dict, rule_id)
        if result:
            return {"success": True, "message": "Rule updated successfully"}, 200
        return {"success": False, "message": "Failed to update rule"}, 500

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
@api.doc(description="Import rules from a GitHub repository")
class ImportRulesFromGithub(Resource):
    @api_required
    @api.doc(params={
        "url": "Required. URL of the GitHub repository to import rules from",
        "license": "Optional. License to apply to the imported rules",
        "fields[]": "Optional. External variables to parse, e.g., fields[0][type]=string&fields[0][name]=filename"
    })
    def post(self):
        user = utils.get_user_from_api(request.headers)
        if not user:
            return {"success": False, "message": "Unauthorized"}, 403

        data = request.get_json(silent=True)
        if not data:
            data = request.args.to_dict()

        repo_url = data.get('url')
        if not repo_url:
            return {"success": False, "message": "Missing 'url' parameter"}, 400

        selected_license = data.get('license', '').strip()
        if not selected_license:
            return {"success": False, "message": "Missing 'license' parameter"}, 400

        # Parse external variables (if any)
        external_vars = []
        index = 0
        while True:
            var_type = data.get(f'fields[{index}][type]')
            var_name = data.get(f'fields[{index}][name]')
            if var_type and var_name:
                external_vars.append({'type': var_type, 'name': var_name})
                index += 1
            else:
                break

        try:
            info = get_github_repo_author(repo_url)
            repo_dir, exists = clone_or_access_repo(repo_url)
            if not repo_dir:
                return {"success": False, "message": "Failed to clone or access the repository"}, 500

            owner, repo = extract_owner_repo(repo_url)
            license_from_github = selected_license or get_license_name(owner, repo)

            # --- Import YARA ---
            yara_imported, yara_skipped, yara_failed, bad_rules_yara = asyncio.run(
                parse_yara_rules_from_repo_async(repo_dir, license_from_github, repo_url , user)
            )

            # --- Import Sigma ---
            bad_rule_dicts_sigma, nb_bad_rules_sigma, imported_sigma, skipped_sigma = asyncio.run(
                load_rule_files(repo_dir, license_from_github, repo_url, user)
            )

            # --- Import Zeek ---
            rule_dicts_zeek = read_and_parse_all_zeek_scripts_from_folder(repo_dir, repo_url, license_from_github, info)
            imported_zeek = 0
            skipped_zeek = 0
            if rule_dicts_zeek:
                for rule in rule_dicts_zeek:
                    success = RuleModel.add_rule_core(rule, user)
                    if success:
                        imported_zeek += 1
                    else:
                        skipped_zeek += 1

            # --- Import Suricata ---
            imported_suricata, suricata_skipped = asyncio.run(
                parse_and_import_suricata_rules_async(repo_dir, license_from_github, repo_url, info, user)
            )

            # Clean temporary files if needed
            # success = delete_existing_repo_folder("app/rule/output_rules/Yara")
            # if not success:
            #     return {"success": False, "message": "Failed to clean temporary YARA folder"}, 500

            # Save invalid rules to database
            if bad_rules_yara:
                RuleModel.save_invalid_rules(bad_rules_yara, "YARA", repo_url, license_from_github)

            if bad_rule_dicts_sigma:
                RuleModel.save_invalid_rules(bad_rule_dicts_sigma, "Sigma", repo_url, license_from_github)

            # Final response
            return {
                "success": True,
                "summary": {
                    "imported": {
                        "yara": yara_imported,
                        "sigma": imported_sigma,
                        "suricata": imported_suricata,
                        "zeek": imported_zeek,
                        "total": yara_imported + imported_sigma + imported_suricata + imported_zeek
                    },
                    "skipped": {
                        "yara": yara_skipped,
                        "sigma": skipped_sigma,
                        "suricata": suricata_skipped,
                        "zeek": skipped_zeek,
                        "total": yara_skipped + skipped_sigma + suricata_skipped + skipped_zeek
                    },
                    "failed": {
                        "yara": len(bad_rules_yara),
                        "sigma": nb_bad_rules_sigma,
                        "total": len(bad_rules_yara) + nb_bad_rules_sigma
                    }
                },
                "invalid_rules": {
                    "yara": bad_rules_yara,         # List of invalid YARA rules with errors
                    "sigma": bad_rule_dicts_sigma   # List of invalid Sigma rules with errors
                }
            }, 200

        except Exception as e:
            return {
                "success": False,
                "message": f"An error occurred while importing from: {repo_url}",
                "error": str(e)
            }, 500

    # curl -X POST http://127.0.0.1:7009/api/rule/private/import_rules_from_github \
    #     -H "Content-Type: application/json" \
    #     -H "X-API-KEY: user_api_key" \
    #     -d '{
    #             "url": "https://github.com/ecrou-exact/Test-pour-regle-yara-.git",
    #             "license": "MIT",
    #             "fields[0][type]": "string",
    #             "fields[0][name]": "filename",
    #             "fields[1][type]": "int",
    #             "fields[1][name]": "filesize"
    #         }'
