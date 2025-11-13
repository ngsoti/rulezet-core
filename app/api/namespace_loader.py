from .rule.public import public_ns as rule_public_ns
from .rule.private import private_ns as rule_private_ns

def register_namespaces(api):
    """Déclare tous les namespaces dans l'API."""
    api.add_namespace(rule_public_ns, path="/rule/public")
    api.add_namespace(rule_private_ns, path="/rule/private")

