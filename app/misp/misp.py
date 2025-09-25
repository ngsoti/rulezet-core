from flask import Blueprint, Response, jsonify, render_template
import json
from flask_login import login_required
from pymisp import MISPEvent, MISPObject

from app.misp.misp_core import content_convert_to_misp_object
from ..rule import rule_core as RuleModel

misp_blueprint = Blueprint(
    'misp',
    __name__,
    template_folder='templates',
    static_folder='static'
)



@misp_blueprint.route("/", methods=['GET'])
@login_required
def misp():
    return render_template("misp/misp.html")


