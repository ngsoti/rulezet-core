from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_session import Session
from sqlalchemy.orm import sessionmaker
from config import config as Config
import os


db = SQLAlchemy()
csrf = CSRFProtect()
migrate = Migrate()
login_manager = LoginManager()
sess = Session()
ThreadLocalSession = None

def create_app():
    app = Flask(__name__)
    global ThreadLocalSession
    
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


    with app.app_context():
        ThreadLocalSession = sessionmaker(bind=db.engine)

    

    #delete_existing_repo_folder("Rules_Github")

    # take all the licenses 
    #fetch_and_save_licenses()

    # remove the previous rule
    #  REPO_DIR = "Rules_Github"
    #  if os.path.exists(REPO_DIR):
    #     shutil.rmtree(REPO_DIR)

    from .home import home_blueprint
    from .account.account import account_blueprint
    from .rule.rule import rule_blueprint  
    from .bundle.bundle import bundle_blueprint
    from .tags.tags import tags_blueprint


    app.register_blueprint(home_blueprint, url_prefix="/")
    app.register_blueprint(account_blueprint, url_prefix="/account")
    app.register_blueprint(rule_blueprint, url_prefix="/rule")
    app.register_blueprint(bundle_blueprint, url_prefix="/bundle")
    app.register_blueprint(tags_blueprint, url_prefix="/tags")

    from app.api.api import api_blueprint

    csrf.exempt(api_blueprint)
   
    app.register_blueprint(api_blueprint, url_prefix="/api")

    return app
    
    