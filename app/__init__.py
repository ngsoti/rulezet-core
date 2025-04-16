import shutil
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_session import Session

from app.rule.import_licenses.rule_licence import fetch_and_save_licenses
from config import config as Config
import os


db = SQLAlchemy()
csrf = CSRFProtect()
migrate = Migrate()
login_manager = LoginManager()
sess = Session()

def create_app():
    app = Flask(__name__)
    config_name = os.environ.get("FLASKENV")

    app.config.from_object(Config[config_name])

    Config[config_name].init_app(app)

    db.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)
    login_manager.login_view = "account.login"
    login_manager.init_app(app)
    app.config["SESSION_SQLALCHEMY"] = db
    sess.init_app(app)

    # take all the licenses 
    fetch_and_save_licenses()

    # remove the previous rule
   #  REPO_DIR = "Rules_Github"
   #  if os.path.exists(REPO_DIR):
   #     shutil.rmtree(REPO_DIR)

    

    from .home import home_blueprint
    from .account.account import account_blueprint
    from .rule.rule import rule_blueprint   
    app.register_blueprint(home_blueprint, url_prefix="/")
    app.register_blueprint(account_blueprint, url_prefix="/account")
    app.register_blueprint(rule_blueprint, url_prefix="/rule")
   
    

    return app
    
