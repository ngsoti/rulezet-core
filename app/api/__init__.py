from flask import Blueprint
from flask_restx import Api

from app.api.namespace_loader import register_namespaces


api_blueprint = Blueprint("api", __name__, url_prefix="/api")

api = Api(
    api_blueprint,
    title="Rulezet API",
    version="1.0",
    description="Rulezet — Modular Detection Rule API (Public & Private).",
    doc="/doc/",
)

register_namespaces(api)
