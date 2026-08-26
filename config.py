import os

from dotenv import load_dotenv

# Read version from the project root 'version' file once at import time
_version_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'version')
try:
    with open(_version_file) as _vf:
        _APP_VERSION = _vf.read().strip()
except OSError:
    _APP_VERSION = 'unknown'


class Config:
    load_dotenv()

    APP_VERSION = _APP_VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY')

    FLASK_URL = os.environ.get('FLASK_URL', '127.0.0.1')
    FLASK_PORT = int(os.environ.get('FLASK_PORT', 7009))
    INSTANCE_PUBLIC_URL  = os.environ.get('INSTANCE_PUBLIC_URL')   # e.g. https://myinstance.example.com
    IS_OFFICIAL_INSTANCE = os.environ.get('IS_OFFICIAL_INSTANCE', 'false').lower() == 'true'

    # Self-hosted Ollama instance backing the in-app chatbot prototype.
    # Run one locally with e.g. `ollama serve` (and `ollama pull qwen2.5:1.5b`) —
    # no API key, no billing, everything stays on this machine.
    # qwen2.5:1.5b over the 3b version: on CPU-only hardware the 3b model was
    # taking 30-100+s per reply once the action-dispatch prompt grew to cover
    # search/navigate/format rules — 1.5b answers in a few seconds instead.
    # If you have a GPU (or more patience), qwen2.5:3b follows the multi-rule
    # instructions slightly more reliably; set OLLAMA_MODEL to switch back.
    OLLAMA_URL   = os.environ.get('OLLAMA_URL', 'http://localhost:11434')
    OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'qwen2.5:1.5b')
    # How many concurrent requests this process sends to Ollama at once — see
    # app/features/ai/ai_core.py's concurrency governor. 2 was measured
    # (production hardware, 24 physical cores) to give genuine partial
    # parallelism without either request slowing down too much.
    OLLAMA_MAX_CONCURRENT = int(os.environ.get('OLLAMA_MAX_CONCURRENT', 2))

    MAIL_SERVER   = os.environ.get('MAIL_SERVER',   'smtp.gmail.com')
    MAIL_PORT     = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS  = os.environ.get('MAIL_USE_TLS',  'true').lower() == 'true'
    MAIL_USE_SSL  = os.environ.get('MAIL_USE_SSL',  'false').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', os.environ.get('MAIL_USERNAME', ''))
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
   
    



class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql:///rulezet')
    SESSION_COOKIE_NAME = os.environ.get('SESSION_COOKIE_NAME', 'session')

    

    SESSION_TYPE = "sqlalchemy"
    SESSION_SQLALCHEMY_TABLE = "flask_sessions"
    
    @classmethod
    def init_app(cls, app):
        print('THIS APP IS IN DEBUG MODE. YOU SHOULD NOT SEE THIS IN PRODUCTION.')

class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = "testing-secret-key-do-not-use-in-production"
    SQLALCHEMY_DATABASE_URI = "sqlite:///rulezet-test.sqlite"
    WTF_CSRF_ENABLED = False

    
    SESSION_TYPE = "filesystem" # else error with session

    @classmethod
    def init_app(cls, app):
        print('THIS APP IS IN TESTING MODE. YOU SHOULD NOT SEE THIS IN PRODUCTION.')

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "postgresql:///rulezet"
    SESSION_TYPE = "sqlalchemy"
    SESSION_SQLALCHEMY_TABLE = "flask_sessions"
    SESSION_COOKIE_SECURE   = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    @classmethod
    def init_app(cls, app):
        print('APP IS IN PRODUCTION MODE.')




config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
