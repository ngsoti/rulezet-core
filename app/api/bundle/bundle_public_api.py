from flask import request
from flask_restx import Namespace, Resource
from ...bundle import bundle_core as BundleModel

bundle_public_ns = Namespace(
    "Public action on Bundle ✅",
    description="Public bundle operations"
)

#######################
#   search bundles    #
#######################
@bundle_public_ns.route('/search')
@bundle_public_ns.doc(
    description="""
Search for bundle by **title**, **description**, **UUID**, or **author**, without pagination.

### Query Parameters

| Parameter  | Type    | Description                                                                 |
|------------|---------|-----------------------------------------------------------------------------|
| search     | string  | Keyword to search in rule title                                             |

### Example cURL Request

```bash
curl -G "http://127.0.0.1:7009/api/bundle/public/search" --data-urlencode "search=detect" 
"""
)
class SearchBundle(Resource):
    @bundle_public_ns.doc(params={
        "search": "Keyword to search in bundle name"
    })
    def get(self):
        """
        Search bundles without pagination.
        """
        search = request.args.get("search")

        if not search:
            return {"message": "args search is missing"}, 400

        bundles_list = BundleModel.get_all_bundles(search, None)

        return {
            "message": f"{bundles_list['total']} bundle(s) found",
            "bundle_list": [b.to_json() for b in bundles_list["items"]],
        }, 200

       