from flask import Blueprint, request
from flask_restx import Api, Resource

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
        "uuid": "Unique identifier (UUID) of the rule",
        "source": "Origin/source of the rule",
        "author": "Real author of the rule",
        "to_string": "String representation of the rule content",
        "creation_date": "Date of creation (ISO 8601)",
        "last_modif": "Last modification date (ISO 8601)",
        "vote_up": "Number of upvotes",
        "vote_down": "Number of downvotes",
        "user_id": "ID of the user who imported the rule"
    })
    def get(self):
        print("goood")
        return {"message": "Rule endpoint is accessible"}
