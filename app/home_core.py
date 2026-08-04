from flask_login import current_user

from .features.rule import rule_core as RuleModel
from .features.bundle import bundle_core as BundleModel
from .features.account import account_core as AccountModel


def global_search(query: str) -> dict:
    """Aggregate results for the main nav search box.

    Rules are always public (matches the existing /rule/data_table
    behavior). Bundles follow the same visibility rules as the bundle
    list page. Users are only searched for authenticated visitors —
    anonymous callers get an empty users list, never a query against
    the User table.
    """
    query = (query or "").strip()
    if not query:
        return {"rules": [], "bundles": [], "users": []}

    users = AccountModel.search_users_lite(query) if current_user.is_authenticated else []

    return {
        "rules": RuleModel.search_rules_lite(query),
        "bundles": BundleModel.search_bundles_lite(query),
        "users": users,
    }
