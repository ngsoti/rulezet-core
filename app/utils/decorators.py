from functools import wraps
from flask import abort, request
from app.utils.utils import verif_api_key




def verification_required():
    """Restrict API access to users without a valid key"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.path.startswith("/api/"):
                if not verif_api_key(request.headers): 
                    abort(403)  
            return f(*args, **kwargs)

        return decorated_function

    return decorator





def api_required(f):
    return verification_required()(f)