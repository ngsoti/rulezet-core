import json
import os
from flask import Blueprint, request as freq, jsonify
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

def _hide_ns(ns):
    """Hide all resources in a namespace from the Swagger UI."""
    for route in ns.resources:
        ns.doc(False)(route.resource)

# Sync / Federation API
from .connector.connector_sync_api import sync_ns  # noqa
_hide_ns(sync_ns)
api.add_namespace(sync_ns, path="/sync")

# Instance registry (phone-home)
from .instance.instance_api import instance_ns  # noqa
_hide_ns(instance_ns)
api.add_namespace(instance_ns, path="/instance")

# User config / Theme Studio
from .config.config_api import config_ns  # noqa
_hide_ns(config_ns)
api.add_namespace(config_ns, path="/config")

# Unified comment thread
from .comment.comment_api import comment_ns  # noqa
_hide_ns(comment_ns)
api.add_namespace(comment_ns, path="/comments")

# Activity log (admin only)
from .log.log_api import log_ns  # noqa
_hide_ns(log_ns)
api.add_namespace(log_ns, path="/log")

# Tags
from .tags.tags_private_api import tags_private_ns  # noqa
api.add_namespace(tags_private_ns, path="/tags/private")

# Rule Tester — hidden from Swagger: this is the same backend the in-app
# Rule Tester UI itself calls (RuleTesterPanel.js, BulkTesterPanel.js,
# TestHistoryPanel.js, MyTestsPanel.js), not a separate public API surface,
# so the routes stay live — only the docs listing is suppressed.
from .rule_tester.public_ns import rule_tester_public_ns  # noqa
from .rule_tester.private_ns import rule_tester_private_ns  # noqa
_hide_ns(rule_tester_public_ns)
_hide_ns(rule_tester_private_ns)
api.add_namespace(rule_tester_public_ns,  path="/rule_tester/public")
api.add_namespace(rule_tester_private_ns, path="/rule_tester/private")


# ─── CSRF enforcement for session-authenticated API calls ────────────────────
# csrf.exempt(api_blueprint) is set in create_app() to allow external API-key
# consumers.  This hook re-enforces CSRF for logged-in browser sessions that
# don't carry an API key — those are the calls an attacker could forge.
@api_blueprint.before_request
def _enforce_csrf_for_session_api():
    if freq.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
        return

    from flask import current_app
    if not current_app.config.get('WTF_CSRF_ENABLED', True):
        return  # CSRF globally disabled (e.g. testing environment)

    from app.core.utils.utils import get_user_from_api
    if get_user_from_api(freq.headers):
        return  # API-key request — immune to CSRF

    from flask_login import current_user as _cu
    if not _cu.is_authenticated:
        return  # anonymous/server-to-server — no session to forge

    from flask_wtf.csrf import validate_csrf, ValidationError
    token = (freq.headers.get('X-CSRFToken')
             or freq.headers.get('X-CSRF-Token')
             or '')
    try:
        validate_csrf(token)
    except ValidationError:
        return jsonify({'message': 'CSRF token missing or invalid',
                        'error': 'csrf'}), 400


# ─── API request audit hook ──────────────────────────────────────────────────

# Paths excluded from API request logging (high-volume or self-referential)
_LOG_SKIP_PREFIXES = ("/api/sync/", "/api/instance/", "/api/log/", "/api/config/",
                      "/api/swaggerui/", "/api/rule/public/search_rules_by_cve")

@api_blueprint.after_request
def _log_api_request(response):
    """Log every API call with its HTTP status and JSON payload."""
    try:
        path   = freq.path
        method = freq.method

        # skip non-mutating verbs and noisy/internal paths
        if method not in ("POST", "PUT", "PATCH", "DELETE"):
            return response
        if any(path.startswith(p) for p in _LOG_SKIP_PREFIXES):
            return response
        if path in ("/api/", "/api/swagger.json"):
            return response

        status_code = response.status_code
        level = "success" if status_code < 300 else ("warning" if status_code < 500 else "error")

        # request body (truncated)
        req_preview = None
        try:
            body = freq.get_json(silent=True, force=True)
            if body:
                req_preview = json.dumps(body, default=str)[:500]
        except Exception:
            pass

        # response body (truncated) — consume before returning
        resp_preview = None
        try:
            resp_preview = response.get_data(as_text=True)[:500]
        except Exception:
            pass

        # resolve actor: API key takes priority, then session user
        user_id  = None
        username = None
        try:
            from app.core.utils.utils import get_user_from_api
            api_user = get_user_from_api(freq.headers)
            if api_user:
                user_id  = api_user.id
                username = api_user.get_username()
        except Exception:
            pass
        if not user_id:
            try:
                from flask_login import current_user
                if current_user.is_authenticated:
                    user_id  = current_user.id
                    username = current_user.get_username()
            except Exception:
                pass

        # write audit entry — use a fresh session state to avoid dirty-session issues
        try:
            import uuid as _uuid
            from app import db
            from app.core.db_class.db import ActivityLog

            # reset any uncommitted/failed transaction left by the view
            try:
                db.session.rollback()
            except Exception:
                pass

            entry = ActivityLog(
                uuid        = str(_uuid.uuid4()),
                user_id     = user_id,
                action      = "api.request",
                title       = f"API {method} {path}",
                description = f"{method} {path} → {status_code}",
                category    = "api",
                level       = level,
                ip_address  = freq.remote_addr,
                url         = path,
                method      = method,
                user_agent  = (freq.headers.get("User-Agent") or "")[:256] or None,
                target_type = None,
                target_id   = None,
                target_uuid = None,
                extra       = {
                    "method":    method,
                    "path":      path,
                    "status":    status_code,
                    "request":   req_preview,
                    "response":  resp_preview,
                    "user":      username,
                },
                is_public   = False,
                icon        = "fa-solid fa-code",
            )
            db.session.add(entry)
            db.session.commit()
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass

    except Exception:
        pass
    return response
