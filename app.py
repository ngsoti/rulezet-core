import threading
from app import create_app, db
import argparse
from flask import render_template, request, Response
import json
import os

from app.import_github_project.cron_check_updates import run_scheduler, set_app
from app.utils.init_db import create_admin, create_default_user, create_rule_test, create_user_test




parser = argparse.ArgumentParser()
parser.add_argument("-i", "--init_db", help="Initialise the db if it not exist", action="store_true")
parser.add_argument("-r", "--recreate_db", help="Delete and initialise the db", action="store_true")
parser.add_argument("-d", "--delete_db", help="Delete the db", action="store_true")
args = parser.parse_args()

os.environ.setdefault('FLASKENV', 'development')

app = create_app()
set_app(app)

@app.errorhandler(404)
def error_page_not_found(e):
    if request.path.startswith('/api/'):
        return Response(json.dumps({"status": "error", "reason": "404 Not Found"}, indent=2, sort_keys=True), mimetype='application/json'), 404
    return render_template('404.html'), 404
    

if args.init_db:
    with app.app_context():
        db.create_all()
        create_admin()
        create_user_test()
        #create_rule_test()
        create_default_user()

        



elif args.recreate_db:
    with app.app_context():
        db.drop_all()
        db.create_all()
        create_admin()
        create_user_test()
        create_rule_test()
        create_default_user()
elif args.delete_db:
    with app.app_context():
        db.drop_all()
else:
    threading.Thread(target=run_scheduler,  daemon=True).start()
    app.run(host=app.config.get("FLASK_URL"), port=app.config.get("FLASK_PORT"))
    
