from flask_restx import Namespace, Resource

account_private_ns = Namespace(
    "AccountPrivate",
    description="Private account operations"
)

@account_private_ns.route("/list")
class AccountPrivateList(Resource):
    def get(self):
        return {"message": "rule private list"}
