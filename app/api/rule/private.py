from flask_restx import Namespace

private_ns = Namespace(
    "private",
    description="Endpoints private for rule."
)
