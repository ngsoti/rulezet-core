from flask_restx import Namespace, Resource

bundle_public_ns = Namespace(
    "Public action on Bundle ✅",
    description="Public bundle operations"
)

@bundle_public_ns.route("/list")
class BundlePublicList(Resource):
    def get(self):
        return {"message": "rule public list"}
