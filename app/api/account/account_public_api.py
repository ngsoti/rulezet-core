# ------------------------------------------------------------------------------------------------------------------- #
#                                               PUBLIC ENDPOINT                                                       #
# ------------------------------------------------------------------------------------------------------------------- #

from flask_restx import Namespace, Resource

account_public_ns = Namespace(
    "AccountPublic",
    description="Public account operations"
)

###################
#   TEST  public  #
###################

@account_public_ns.route("/list")
class AccountPublicList(Resource):
    def get(self):
        return {"message": "rule public list"}


