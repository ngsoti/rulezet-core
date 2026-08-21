from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_session import Session
from sqlalchemy.orm import sessionmaker
from config import config as Config
import os
from flask_mail import Mail, Message

load_dotenv()

db = SQLAlchemy()
csrf = CSRFProtect()
migrate = Migrate()
login_manager = LoginManager()
sess = Session()
ThreadLocalSession = None
mail = Mail()

def create_app(start_worker=True):
    load_dotenv()

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

    mail.init_app(app)

    from .home import home_blueprint

    from .features.account.account import account_blueprint
    from .features.rule.rule import rule_blueprint  
    from .features.bundle.bundle import bundle_blueprint
    from .features.tags.tags import tags_blueprint
    from app.features.jobs.jobs import jobs_blueprint
    from app.features.connector.connector import connector_blueprint
    from app.features.velociraptor.velociraptor import velociraptor_blueprint
    from app.features.misp.misp import misp_blueprint
    from app.features.rule.rule_from_github.sync_schedule.sync_schedule_routes import sync_schedule_blueprint
    from app.features.rule.rule_from_github.proposal.proposal_routes import github_proposal_blueprint
    from app.features.rule.rule_quality.quality_score import quality_blueprint
    from app.features.notification.notification import notification_blueprint
    from app.features.report.report import report_blueprint
    from app.features.attack.attack import attack_blueprint
    from app.features.workspace.workspace import workspace_blueprint
    from app.features.blog.blog import blog_blueprint
    from app.features.community.community import community_blueprint
    from app.features.rule_tester.rule_tester import rule_tester_blueprint
    from app.features.dashboard.dashboard import dashboard_blueprint
    from app.features.docs.docs import docs_blueprint
    from app.features.chatbot.chatbot import chatbot_blueprint
    from app.features.roles.roles import roles_blueprint

    app.register_blueprint(home_blueprint, url_prefix="/")
    app.register_blueprint(account_blueprint, url_prefix="/account")
    app.register_blueprint(rule_blueprint, url_prefix="/rule")
    app.register_blueprint(bundle_blueprint, url_prefix="/bundle")
    app.register_blueprint(tags_blueprint, url_prefix="/tags")
    app.register_blueprint(jobs_blueprint, url_prefix='/jobs')
    app.register_blueprint(connector_blueprint, url_prefix='/connector')
    app.register_blueprint(velociraptor_blueprint, url_prefix='/velociraptor')
    app.register_blueprint(misp_blueprint, url_prefix='/misp')
    app.register_blueprint(sync_schedule_blueprint, url_prefix='/rule/github')
    app.register_blueprint(github_proposal_blueprint, url_prefix='/rule/github_proposal')
    app.register_blueprint(quality_blueprint, url_prefix='/rule/quality')
    app.register_blueprint(notification_blueprint, url_prefix='/notifications')
    app.register_blueprint(report_blueprint, url_prefix='/report')
    app.register_blueprint(attack_blueprint, url_prefix='/attack')
    app.register_blueprint(workspace_blueprint, url_prefix='/workspace')
    app.register_blueprint(blog_blueprint, url_prefix='/blog')
    app.register_blueprint(community_blueprint, url_prefix='/community')
    app.register_blueprint(rule_tester_blueprint)
    app.register_blueprint(dashboard_blueprint, url_prefix='/dashboard')
    app.register_blueprint(docs_blueprint, url_prefix='/docs')
    app.register_blueprint(chatbot_blueprint, url_prefix='/chatbot')
    app.register_blueprint(roles_blueprint, url_prefix='/admin/roles')

    from app.api.api import api_blueprint

    # Blanket-exempt the API blueprint from Flask-WTF's automatic CSRF check.
    # External API-key consumers can't supply a CSRF token, so we can't enforce
    # it globally.  A before_request hook in app/api/api.py re-enforces it
    # selectively for session-authenticated browser calls.
    csrf.exempt(api_blueprint)

    app.register_blueprint(api_blueprint, url_prefix="/api")


    from app.features.config.config import config_blueprint
    app.register_blueprint(config_blueprint, url_prefix='/')

    from app.features.pivotick.pivotick import pivotick_blueprint
    app.register_blueprint(pivotick_blueprint, url_prefix='/')

    @app.after_request
    def set_security_headers(response):
        # Stops a browser from ever re-interpreting a served file (e.g. a
        # blog attachment) as HTML/SVG based on sniffed content instead of
        # its declared Content-Type — a backstop against stored-XSS-via-upload
        # regardless of what mimetype ends up attached to a file.
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    from app.features.jobs import job_handlers  # noqa
    if start_worker:
        from app.features.jobs.job_worker import start_worker as _start_worker
        _start_worker(app)

    if start_worker and config_name != 'testing':
        try:
            from app.features.chatbot.ollama_launcher import ensure_ollama_running
            ensure_ollama_running(app.config.get('OLLAMA_URL', 'http://localhost:11434'))
        except Exception as e:
            print(f"[chatbot] Ollama auto-start check failed: {e}")

    with app.app_context():
        try:
            from app.features.connector.connector_core import seed_official_connector
            seed_official_connector()
        except Exception:
            pass
        try:
            from app.features.config.config_core import seed_default_themes
            seed_default_themes()
        except Exception:
            pass
        try:
            from app.features.roles.roles_core import seed_default_permissions_and_roles
            seed_default_permissions_and_roles()
        except Exception:
            pass

    @app.context_processor
    def inject_user_config():
        from flask_login import current_user as _cu
        from app.features.config.config_core import get_user_config, get_all_custom_themes
        config = None
        themes_js = []
        if _cu.is_authenticated:
            try:
                config = get_user_config()
                themes = get_all_custom_themes(admin_view=_cu.is_admin())
                themes_js = [{'css_key': t.css_key, 'is_dark': t.is_dark, 'name': t.name} for t in themes if not t.is_builtin]
            except Exception:
                pass
        return {
            'user_config': config,
            'custom_themes_for_js': themes_js,
            'is_admin': _cu.is_authenticated and _cu.is_admin(),
        }

    @app.context_processor
    def inject_globals():
        from flask import current_app
        from app.core.db_class.db import InstanceConfig
        chatbot_enabled = True
        try:
            cfg = InstanceConfig.query.first()
            if cfg is not None:
                chatbot_enabled = cfg.chatbot_enabled
        except Exception:
            pass  # table may not exist yet (fresh install before migrations run)
        return {
            'app_version': current_app.config.get('APP_VERSION', 'unknown'),
            'is_official': current_app.config.get('IS_OFFICIAL_INSTANCE', False),
            'chatbot_enabled': chatbot_enabled,
        }

    def admin_jobs_running_count():
        """Count of pending/running background jobs — used for the Jobs badge
        on the admin nav panel (macros/admin_nav.html), available to every
        template regardless of import context."""
        from flask_login import current_user as _cu
        if not (_cu.is_authenticated and _cu.is_admin()):
            return 0
        try:
            from app.core.db_class.db import BackgroundJob
            return BackgroundJob.query.filter(
                BackgroundJob.status.in_(('pending', 'running'))
            ).count()
        except Exception:
            return 0

    app.jinja_env.globals['admin_jobs_running_count'] = admin_jobs_running_count

    def pending_update_info():
        """Admin-only: {version, url} of a newer GitHub release than this
        instance's local `version` file, or None — used by base.html to show
        the update banner. Backed by the cache _start_update_checker() keeps
        in app.config['LATEST_RELEASE'], never a live network call from a
        request (that cache is refreshed on its own background thread)."""
        from flask_login import current_user as _cu
        if not (_cu.is_authenticated and _cu.is_admin()):
            return None
        info = app.config.get('LATEST_RELEASE')
        if not info or not info.get('update_available'):
            return None
        return info

    app.jinja_env.globals['pending_update_info'] = pending_update_info

    @app.errorhandler(403)
    def forbidden(e):
        # API consumers and fetch() calls get JSON; browsers get the page
        if request.path.startswith('/api/') or request.accept_mimetypes.best == 'application/json':
            return jsonify({"error": "Forbidden."}), 403
        return render_template('access_denied.html'), 403

    @app.errorhandler(404)
    def page_not_found(e):
        if request.path.startswith('/api/') or request.accept_mimetypes.best == 'application/json':
            return jsonify({"error": "Not found."}), 404
        return render_template('404.html'), 404

    _init_instance_config(app)
    if start_worker:
        _start_telemetry(app)
        _start_update_checker(app)
        from app.features.rule.rule_from_github.sync_schedule.scheduler_engine import start_scheduler
        start_scheduler(app)

    return app


def _init_instance_config(app):
    """Create or refresh the single InstanceConfig row on every boot.

    cfg.uuid is the stable registry UUID — uuid5(NAMESPACE_URL, reported_url).
    It matches the UUID sent in telemetry pings and shown in RegisteredInstance.
    """
    import uuid as _uuid_mod
    import datetime
    from app.core.db_class.db import InstanceConfig
    with app.app_context():
        try:
            cfg = InstanceConfig.query.first()
            reported_url = (
                app.config.get('INSTANCE_PUBLIC_URL') or
                f"http://{app.config.get('FLASK_URL', '127.0.0.1')}"
                f":{app.config.get('FLASK_PORT', 7009)}"
            )
            stable_uuid = str(_uuid_mod.uuid5(_uuid_mod.NAMESPACE_URL, reported_url))
            if not cfg:
                cfg = InstanceConfig(
                    uuid              = stable_uuid,
                    telemetry_enabled = True,
                    public_url        = app.config.get('INSTANCE_PUBLIC_URL'),
                )
                db.session.add(cfg)
                db.session.flush()
            else:
                cfg.uuid       = stable_uuid
                cfg.public_url = app.config.get('INSTANCE_PUBLIC_URL') or cfg.public_url
            cfg.version         = app.config.get('APP_VERSION', 'unknown')
            cfg.last_started_at = datetime.datetime.utcnow()
            db.session.commit()
        except Exception:
            pass


def _start_telemetry(app):
    """Daemon thread: ping rulezet.org every 24 h so the community can see this instance."""
    import threading
    import time
    import uuid as _uuid_mod
    import requests as _req
    from app.core.db_class.db import InstanceConfig, Rule, Bundle

    PING_URL      = os.environ.get('TELEMETRY_URL', 'https://rulezet.org/api/instance/register')
    STARTUP_DELAY = int(os.environ.get('TELEMETRY_STARTUP_DELAY', 90))
    INTERVAL      = int(os.environ.get('TELEMETRY_INTERVAL',      86400))

    def _read_version():
        try:
            vp = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'version')
            with open(vp) as _f:
                return _f.read().strip()
        except OSError:
            return app.config.get('APP_VERSION', 'unknown')

    def _loop():
        time.sleep(STARTUP_DELAY)
        while True:
            try:
                with app.app_context():
                    cfg = InstanceConfig.query.first()
                    if cfg and cfg.telemetry_enabled:
                        reported_url = cfg.public_url or (
                            f"http://{app.config.get('FLASK_URL', '127.0.0.1')}"
                            f":{app.config.get('FLASK_PORT', 7009)}"
                        )
                        # Always recompute from URL — never trust in-memory cfg.uuid
                        # which may be stale if the code was updated without restarting.
                        ping_uuid = str(_uuid_mod.uuid5(_uuid_mod.NAMESPACE_URL, reported_url))
                        # Re-read version file each ping so version updates without restart
                        current_version = _read_version()
                        app.config['APP_VERSION'] = current_version
                        _req.post(PING_URL, json={
                            'uuid':          ping_uuid,
                            'url':           reported_url,
                            'version':       current_version,
                            'rules_count':   Rule.query.filter_by(is_deleted=False).count(),
                            'bundles_count': Bundle.query.count(),
                        }, timeout=8)
            except Exception:
                pass
            time.sleep(INTERVAL)

    t = threading.Thread(target=_loop, daemon=True, name='rulezet-telemetry')
    t.start()


def _read_local_version():
    try:
        vp = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'version')
        with open(vp) as f:
            return f.read().strip()
    except OSError:
        return 'unknown'


def _start_update_checker(app):
    """Daemon thread: check GitHub for a release newer than this instance's
    local `version` file, so admins see an in-app notice instead of finding
    out by accident. Read-only (GitHub releases API, no auth needed) and
    entirely best-effort — any failure just means no banner shows, never a
    crash or a blocked request (the result is cached in app.config and read
    from there by every request, this thread is the only thing that hits
    the network)."""
    import threading
    import time
    import requests as _req

    CHECK_URL     = os.environ.get('UPDATE_CHECK_URL', 'https://api.github.com/repos/rulezet/rulezet-core/releases/latest')
    STARTUP_DELAY = int(os.environ.get('UPDATE_CHECK_STARTUP_DELAY', 15))
    INTERVAL      = int(os.environ.get('UPDATE_CHECK_INTERVAL',      86400))

    YELLOW, GREEN, RESET = "\033[93m", "\033[92m", "\033[0m"

    def _loop():
        time.sleep(STARTUP_DELAY)
        while True:
            try:
                local_version = (app.config.get('APP_VERSION') or _read_local_version()).lstrip('v')
                resp = _req.get(CHECK_URL, timeout=8, headers={'Accept': 'application/vnd.github+json'})
                if resp.ok:
                    data = resp.json()
                    latest_version = (data.get('tag_name') or '').lstrip('v')
                    update_available = bool(latest_version) and latest_version != local_version
                    already_flagged = (app.config.get('LATEST_RELEASE') or {}).get('update_available')
                    app.config['LATEST_RELEASE'] = {
                        'version': latest_version,
                        'url': data.get('html_url') or 'https://github.com/rulezet/rulezet-core/releases/latest',
                        'update_available': update_available,
                    }
                    # Quiet when there's nothing to do — only announce a newly
                    # detected update, once, not on every subsequent 24h check.
                    if update_available and not already_flagged:
                        print(f"\n{YELLOW}A new Rulezet version is available: v{latest_version} "
                              f"(you're on v{local_version}){RESET}")
                        print(f"{GREEN}  → Run: python3 manage.py update{RESET}\n")
            except Exception:
                pass
            time.sleep(INTERVAL)

    t = threading.Thread(target=_loop, daemon=True, name='rulezet-update-checker')
    t.start()
    
    