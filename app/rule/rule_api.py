from dataclasses import fields
from flask import Blueprint, request
from flask_restx import Api, Resource
from sqlalchemy import true

from app.db_class.db import Rule
from app.utils import utils
from ..rule import rule_core as RuleModel
from app.utils.decorators import api_required

api_rule_blueprint = Blueprint('api_rule', __name__)


api = Api(api_rule_blueprint,
          title='Rulezet API',
          description='API to manage a rule management instance.',
          version='0.1',
          default='Rules API',
          default_label='rules / bad_rule  API',
          doc='/doc/') 


@api.route('/create_rule')
@api.doc(description='Create a rule')
class CreateRule(Resource):
    method_decorators = [api_required]  

    @api.doc(params={
        "title": "Required. Title for the rule",
        "description": "Description of the rule",
        "version": "Version of the rule",
        "format": "Rule format (e.g., yara, sigma)",
        "license": "License applied to the rule",
        "source": "Origin/source of the rule",
        "author": "Real author of the rule",
        "to_string": "String representation of the rule content",
    })
    def post(self):

        user = utils.get_user_from_api(request.headers)

        data = request.get_json(silent=True)
        if not data:
            data = request.args.to_dict()
        required_fields = ["title", "format", "description", "version", "source", "to_string", "license"]
        if not all(field in data for field in required_fields):
            return {"message": "Missing fields in request"}, 400
        form_dict = {
            'title': data.get("title"),
            'format': data.get("format"),
            'description': data.get("description"),
            'version': data.get("version"),
            'source': data.get("source"),
            'to_string': data.get("to_string"),
            'license': data.get("license")
        }
        external_vars = []

        form_dict['author'] = "test"
        if form_dict['description'] == '':
            form_dict['description'] = "No description for the rule"
        if form_dict['source'] == '':
            form_dict['source'] = "test"

        if form_dict['format'] == 'yara' :
            valide , to_string , error = RuleModel.compile_yara(external_vars,form_dict)
            if valide == False:
                return {"message": "Rule invalide"}, 401
        elif form_dict['format'] == 'sigma':
            valide , to_string , error = RuleModel.compile_sigma(form_dict)
            if valide == False:
                return {"message": "Rule invalide"}, 401

        if Rule.query.filter_by(title=data.get("title")).first():
            return {"message": "Rule already exists"}, 402

        verif = RuleModel.add_rule_core(form_dict , user)
        if verif:
            if verif == True:
                return {"message": "Rule add successfully"}, 200
            
        return {"message": "no rule added"}, 500      
   
@api.route('/delete_rule')
@api.doc(description='Delete a rule')
class DeleteRule(Resource):
    method_decorators = [api_required]
    @api.doc(params={
        "title": "Title of the rule to delete"
    })
    def post(self):
        user = utils.get_user_from_api(request.headers)
        
        if user is None:
            return {"success": False, "message": "Unauthorized because of "}, 402

        data = request.get_json(silent=True)
        if not data or 'title' not in data:
            return {"success": False, "message": "Missing 'title' parameter"}, 400

        rule_id = RuleModel.get_rule_id_by_title(data['title'])
        if not rule_id:
            return {"success": False, "message": "Rule not found"}, 404
        rule_owner_id = RuleModel.get_rule_user_id(rule_id)



        if user.id == rule_owner_id or user.is_admin():
            success = RuleModel.delete_rule_core(rule_id)
            if success:
                return {"success": True, "message": "Rule deleted!"}, 200
            else:
                return {"success": False, "message": "Failed to delete rule"}, 500

        return {"success": False, "message": "Access denied"}, 403

@api.route('/vote_rule')
@api.doc(description='Vote for a rule (up or down)', params={
    'id': 'ID of the rule',
    'vote_type': "'up' or 'down'",
})
class VoteRule(Resource):
    method_decorators = [api_required]

    def get(self):
        user = utils.get_user_from_api(request.headers)
        if user is None:
            return {"success": False, "message": "Unauthorized"}, 401

        rule_id = request.args.get('id', type=int)
        vote_type = request.args.get('vote_type', type=str)

        if rule_id is None or vote_type not in ['up', 'down']:
            return {"success": False, "message": "Invalid parameters"}, 400

        rule = RuleModel.get_rule(rule_id)
        if not rule:
            return {"success": False, "message": "Rule not found"}, 404

        already_voted, already_vote_type = RuleModel.has_already_vote(rule_id, user.id)

        if vote_type == 'up':
            if not already_voted:
                RuleModel.increment_up(rule_id)
                RuleModel.has_voted('up', rule_id, user.id)
            elif already_vote_type == 'up':
                RuleModel.remove_one_to_increment_up(rule_id)
                RuleModel.remove_has_voted('up', rule_id, user.id)
            elif already_vote_type == 'down':
                RuleModel.increment_up(rule_id)
                RuleModel.remove_one_to_decrement_up(rule_id)
                RuleModel.remove_has_voted('down', rule_id, user.id)
                RuleModel.has_voted('up', rule_id, user.id)

        elif vote_type == 'down':
            if not already_voted:
                RuleModel.decrement_up(rule_id)
                RuleModel.has_voted('down', rule_id, user.id)
            elif already_vote_type == 'down':
                RuleModel.remove_one_to_decrement_up(rule_id)
                RuleModel.remove_has_voted('down', rule_id, user.id)
            elif already_vote_type == 'up':
                RuleModel.decrement_up(rule_id)
                RuleModel.remove_one_to_increment_up(rule_id)
                RuleModel.remove_has_voted('up', rule_id, user.id)
                RuleModel.has_voted('down', rule_id, user.id)

        return {
            'vote_up': rule.vote_up,
            'vote_down': rule.vote_down
        }, 200

@api.route('/edit_rule/<int:rule_id>')
@api.doc(description="Edit a rule")
class EditRule(Resource):
    method_decorators = [api_required]
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

        data = request.get_json()
        if not data:
            data = request.args.to_dict()

        if data['format'] == 'yara':
            valide, to_string, error = RuleModel.compile_yara([], data)
            if not valide:
                return {"success": False, "message": error}, 401
        elif data['format'] == 'sigma':
            valide, to_string, error = RuleModel.compile_sigma(data)
            if not valide:
                return {"success": False, "message": error}, 401
        else:
            return {"success": False, "message": "Unknown format"}, 400

        RuleModel.edit_rule_core(data, rule_id)
        return {"success": True, "message": "Rule updated"}, 200
