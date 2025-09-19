from flask import Blueprint, jsonify, render_template
from flask_login import login_required

from app.misp.misp_connect import test_misp_connection

misp_blueprint = Blueprint(
    'misp',
    __name__,
    template_folder='templates',    
    static_folder='static'
)

##################
#    Misp path   #
##################

@misp_blueprint.route("/" , methods=['GET'])
@login_required
def misp():
    return render_template("misp/misp.html" )

@misp_blueprint.route("/connect", methods=["GET"])
@login_required
def connect():
    try:
        success = test_misp_connection()
        if success:
            return jsonify({"status": "success", "message": "Connection with misp instance create with success", "toast_class" : "success"}), 200
        else:
            return jsonify({"status": "error", "message": "Error during connection ", "toast_class" : "danger"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "toast_class" : "danger"}), 500