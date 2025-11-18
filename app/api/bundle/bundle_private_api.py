from flask_restx import Namespace, Resource

bundle_private_ns = Namespace(
    "BundlePrivate",
    description="Private bundle operations"
)

@bundle_private_ns.route("/list")
class BundlePrivateList(Resource):
    def get(self):
        return {"message": "rule private list"}
