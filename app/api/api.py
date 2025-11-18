import os
from flask import Blueprint
from flask_restx import Api

# -------------------------------------------------------------
# Blueprint: Main API entrypoint
# -------------------------------------------------------------
api_blueprint = Blueprint(
    "api",
    __name__,
    url_prefix="/api"
)

# -------------------------------------------------------------
# Load application version
# -------------------------------------------------------------
def version() -> str:
    """Read the application version from the 'version' file."""
    version_file = os.path.join(os.getcwd(), "version")
    with open(version_file, "r") as f:
        return f.readline().strip()


# -------------------------------------------------------------
# Create the main API object
# -------------------------------------------------------------
api = Api(
    api_blueprint,
    title="Rulezet API",
    version=version(),
    description="""
# Welcome to the Rulezet API

The **Rulezet API** provides full programmatic access to your Rulezet instance, including:

- **Rules**: manage detection rules  
- **Bundles**: organize and distribute rule bundles  
- **Account**: manage users and API keys

---

## Access Levels

The API is divided into **public** and **private** namespaces:

### ✅ Public Namespaces
- Free access
- No API key required
- Ideal for retrieving metadata, listing rules, and fetching bundles
- Safe for dashboards, scripts, or external integrations

### 🔑 Private Namespaces
- Require a **personal API key**
- Used for operations that modify data or access sensitive information
- Includes creating, updating, or deleting rules and bundles, managing accounts
- API key can be found in your profile page

---

## Usage
- Public endpoints: accessible directly  
- Private endpoints: include your API key in request headers

Explore all endpoints and try them out using the Swagger UI below.
""",
    doc="/",  # Swagger UI root
)



# -------------------------------------------------------------
# Import all namespaces (organized by module)
# -------------------------------------------------------------

# Rule namespaces
from .rule.rule_public_api import rule_public_ns
from .rule.rule_private_api import rule_private_ns

# Bundle namespaces
from .bundle.bundle_public_api import bundle_public_ns
from .bundle.bundle_private_api import bundle_private_ns

# Account namespaces
from .account.account_public_api import account_public_ns
from .account.account_private_api import account_private_ns


# -------------------------------------------------------------
# Register namespaces in hierarchical paths
# (This produces a clean tree-like structure in Swagger)
# -------------------------------------------------------------

# Rule API

api.add_namespace(rule_public_ns,  path="/rule/public")
api.add_namespace(rule_private_ns, path="/rule/private")

# Bundle API
api.add_namespace(bundle_public_ns,  path="/bundle/public")
api.add_namespace(bundle_private_ns, path="/bundle/private")

# Account API
api.add_namespace(account_public_ns,  path="/account/public")
api.add_namespace(account_private_ns, path="/account/private")
