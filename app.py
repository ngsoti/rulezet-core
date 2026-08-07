import threading

from dotenv import load_dotenv
from app import create_app, db
import argparse
from flask import render_template, request, Response
import json
import os


from app.features.rule.rule_format.utils_format.utils_import_update import delete_existing_repo_folder
from app.core.utils.init_db import create_admin, create_default_user, insert_default_formats, insert_default_platform_tag_configs, seed_default_tags, show_admin_first_connection
from app.features.connector.connector_core import seed_official_connector
from app import _init_instance_config




parser = argparse.ArgumentParser()

parser.add_argument("-i", "--init_db", help="Initialise the db if it not exist", action="store_true")
parser.add_argument("-r", "--recreate_db", help="Delete and initialise the db", action="store_true")
parser.add_argument("-d", "--delete_db", help="Delete the db", action="store_true")
parser.add_argument("--seed-defaults", help="Idempotently (re)seed default data (formats, platform-tag configs) on an existing DB — run after 'manage.py update' on an already-deployed instance", action="store_true")
args = parser.parse_args()



os.environ.setdefault('FLASKENV', 'development')

load_dotenv()

_cli_mode = args.init_db or args.recreate_db or args.delete_db or args.seed_defaults
app = create_app(start_worker=not _cli_mode)

@app.errorhandler(404)
def error_page_not_found(e):
    if request.path.startswith('/api/'):
        return Response(json.dumps({"status": "error", "reason": "404 Not Found"}, indent=2, sort_keys=True), mimetype='application/json'), 404
    return render_template('404.html'), 404
    

if args.init_db:
    with app.app_context():
        db.create_all()
        admin, raw_password = create_admin()
        editor = create_default_user()
        insert_default_formats()
        insert_default_platform_tag_configs()
        seed_official_connector()
        _init_instance_config(app)
        seed_default_tags(admin)
        show_admin_first_connection(admin, raw_password)

elif args.recreate_db:
    with app.app_context():
        db.drop_all()
        db.create_all()
        delete_existing_repo_folder("Rules_Github")
        admin, raw_password = create_admin()
        editor = create_default_user()
        insert_default_formats()
        insert_default_platform_tag_configs()
        seed_official_connector()
        _init_instance_config(app)
        seed_default_tags(admin)
        show_admin_first_connection(admin, raw_password)
elif args.delete_db:
    with app.app_context():
        db.drop_all()
        print("DB delete with success")
elif args.seed_defaults:
    with app.app_context():
        insert_default_formats()
        insert_default_platform_tag_configs()
        print("Default data seeded (idempotent — existing rows untouched).")
else:
    port = int(os.environ.get("PORT", app.config.get("FLASK_PORT", 7009)))
    # threaded=True — without it Werkzeug's dev server handles one request at a
    # time, so any single slow request (a status poll waiting on a background
    # session to finalize, a git clone/pull, ...) blocks every other request,
    # including the page's own other AJAX calls, until it's done.
    app.run(host=app.config.get("FLASK_URL"), port=port, threaded=True)
    
