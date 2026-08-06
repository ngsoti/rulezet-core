import datetime
import json
import subprocess
import uuid
from pathlib import Path
from flask_login import current_user

from app.features.account.account_core import get_admin_user
from ..db_class.db import FormatRule, Rule, User, db
from .utils import generate_api_key


############
############

def show_admin_first_connection(admin , raw_password):
    """Show the admin element"""
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    NUMBER = 120
    print("\n" + "=" * NUMBER)
    print(f"{GREEN}✅ Admin account created successfully!{RESET}")
    print(f"🔑 {YELLOW}API Key     :{RESET} {admin.api_key} ( Unique secret key )")
    print(f"👤 {YELLOW}Username    :{RESET} admin@admin.admin")
    print(f"🔐 {YELLOW}Password    :{RESET} {raw_password}   (⚠️ Change it after first login)")
    print("=" * NUMBER + "\n")
    print(f"{YELLOW}🚀 You can now launch the application using:{RESET} ./launch.sh -l\n")
    print("=" * NUMBER + "\n")
    
#############################
#   For the reel web site   #
#############################

def create_admin():
    raw_password = generate_api_key()
    
    existing = User.query.filter_by(email="admin@admin.admin").first()
    if existing:
        # delete the existing admin
        db.session.delete(existing)
        db.session.commit()
    if not raw_password:
        raw_password = "admin"

    user = User(
        first_name="admin",
        last_name="admin",
        email="admin@admin.admin",
        password=raw_password,
        admin=True,
        api_key=generate_api_key(),
        is_verified=True
    )
    db.session.add(user)
    db.session.commit()
    return user, raw_password

def create_default_user():
    existing = User.query.filter_by(email="default@default.default").first()
    if existing:
        return existing

    user = User(
        first_name="no editor",
        last_name="no editor",
        email="default@default.default",
        password= generate_api_key(),
        admin=False,
        api_key = generate_api_key(),
        is_verified=True
    )
    db.session.add(user)
    db.session.commit()
    return user

###############
#   For test  #
###############

def create_user_test():
    user = User(
        first_name="Matrix",
        last_name="Bot",
        email="neo@admin.admin",
        password=generate_api_key(),
        api_key = "user_api_key",
        is_verified=True
    )
    db.session.add(user)
    db.session.commit()

    user2 = User(
        first_name="theo",
        last_name="theo",
        email="t@t.t",
        password="password1@A",
        admin=False,
        api_key = "api_key_user_rule",
        is_verified=True
    )
    db.session.add(user2)
    db.session.commit()

def create_admin_test():
    # Admin user
    user = User(
        first_name="admin",
        last_name="admin",
        email="admin@admin.admin",
        password= "admin",
        admin=True,
        api_key = "admin_api_key",
        is_verified=True
    )
    db.session.add(user)
    db.session.commit()

def insert_default_formats():
    formats = [
        {"name": "yara", "can_be_execute": True},
        {"name": "sigma", "can_be_execute": True},
        {"name": "zeek", "can_be_execute": False},
        {"name": "suricata", "can_be_execute": False},
        {"name": "crs", "can_be_execute": False},
        {"name": "nova", "can_be_execute": False},
        # {"name": "elastic", "can_be_execute": True},
        {"name": "nse", "can_be_execute": True},
        {"name": "no format", "can_be_execute": False},
        {"name": "wazuh", "can_be_execute": False},
        {"name": "kql", "can_be_execute": False}
    ]

    user_admin = get_admin_user()
    for fmt in formats:
        existing = FormatRule.query.filter_by(name=fmt["name"]).first()
        if not existing:
            new_format = FormatRule(
                user_id = user_admin.id,
                name=fmt["name"],
                can_be_execute=fmt["can_be_execute"],
                creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
            )
            db.session.add(new_format)

    db.session.commit()


def seed_default_tags(admin_user):
    """Initialize MISP taxonomy submodule and import seed namespaces from config/default_tags.json."""
    from app.features.tags.tags_core import (
        add_tags_from_misp_taxonomy,
        get_all_taxonomy_uuids_from_disk,
    )

    W  = "\033[93m"   # yellow
    G  = "\033[92m"   # green
    R  = "\033[0m"    # reset
    N  = 60

    print("\n" + "─" * N)
    print("  Default tag setup")
    print("─" * N)

    # Init the taxonomy submodule (safe to call even if already initialized)
    try:
        result = subprocess.run(
            ["git", "submodule", "update", "--init", "app/modules/misp-taxonomies"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"  {G}submodule{R}  misp-taxonomies  OK")
        else:
            print(f"  {W}submodule{R}  warning: {(result.stderr or result.stdout).strip()[:80]}")
    except Exception as e:
        print(f"  {W}submodule{R}  could not init: {e}")

    config_path = Path("config/default_tags.json")
    try:
        with open(config_path) as f:
            config = json.load(f)
    except Exception:
        config = {}

    seed_namespaces = [s["namespace"] for s in config.get("seed_on_init", [])]
    if not seed_namespaces:
        print("  no seed namespaces configured")
        print("─" * N + "\n")
        return

    # Build namespace → uuid map from disk (case-insensitive lookup)
    namespace_to_uuid = {ns.lower(): (uid, ns) for uid, ns in get_all_taxonomy_uuids_from_disk()}

    for namespace in seed_namespaces:
        hit = namespace_to_uuid.get(namespace.lower())
        if not hit:
            print(f"  {W}not found{R}   {namespace}")
            continue
        uid, real_ns = hit
        ok, msg = add_tags_from_misp_taxonomy(uid, admin_user)
        # Summarise: extract just the tag count from the message
        count = ""
        if ok and "Imported" in msg:
            count = msg.split("Imported")[1].split("tags")[0].strip() + " tags"
        elif "already" in msg:
            count = "already imported"
        else:
            count = msg
        marker = G if ok else W
        print(f"  {marker}{'imported' if ok else 'skipped '}{R}   {real_ns}  ({count})")

    print("─" * N + "\n")


def create_rule_test():
    editor = User.query.filter_by(email="t@t.t").first()
    if editor :
        rule = Rule(
            format="yara",
            title="test",
            license="test",
            description="test",
            uuid=str(uuid.uuid4()),
            source="test",
            author="test",
            version=1,
            user_id=editor.id,
            creation_date = datetime.datetime.now(tz=datetime.timezone.utc),
            last_modif = datetime.datetime.now(tz=datetime.timezone.utc),
            vote_up=0,
            vote_down=0,
            to_string = " rule test { condition: 1}"
        )
        db.session.add(rule)
        db.session.commit()