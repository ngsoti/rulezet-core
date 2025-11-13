from flask_restx import Namespace, Resource

public_ns = Namespace(
    "Rule public",
    description="Endpoints publics pour la gestion et la recherche de règles."
)

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