import threading
from app import create_app, db
import argparse
from flask import render_template, request, Response
import json
import os

from app.import_github_project.cron_check_updates import run_scheduler, set_app
from app.utils.init_db import create_admin, create_default_user, create_user_test




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
        admin, raw_password = create_admin()
        editor = create_default_user()

        # create_user_test()
        # create_rule_test()

        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        RESET = "\033[0m"

        print("\n" + "=" * 100)
        print(f"{GREEN}✅ Admin account created successfully!{RESET}")
        print(f"🔑 {YELLOW}API Key     :{RESET} {admin.api_key} ( Unique secret key )")
        print(f"👤 {YELLOW}Username    :{RESET} admin@admin.admin")
        print(f"🔐 {YELLOW}Password    :{RESET} {raw_password}   (⚠️ Change it after first login)")
        print("=" * 100 + "\n")






elif args.recreate_db:
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin , raw_password = create_admin()
        

        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        RESET = "\033[0m"

        print("\n" + "=" * 100)
        print(f"{GREEN}✅ Admin account created successfully!{RESET}")
        print(f"🔑 {YELLOW}API Key     :{RESET} {admin.api_key} ( Unique secret key ) ")
        print(f"👤 {YELLOW}Username    :{RESET} admin@admin.admin")
        print(f"🔐 {YELLOW}Password    :{RESET} {raw_password}   (⚠️ Change it after first login)")
        print("=" * 100 + "\n")

        #create_user_test()
        #create_rule_test()
        editor = create_default_user()
elif args.delete_db:
    with app.app_context():
        print("DB delete with success")
        db.drop_all()
else:
    threading.Thread(target=run_scheduler,  daemon=True).start()
    app.run(host=app.config.get("FLASK_URL"), port=app.config.get("FLASK_PORT"))
    
