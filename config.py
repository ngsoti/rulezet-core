import os

from dotenv import load_dotenv


class Config:
    load_dotenv()

    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    FLASK_URL = '127.0.0.1'
    FLASK_PORT = 7009

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'rulezet.org@gmail.com'
    MAIL_DEFAULT_SENDER = 'rulezet.org@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
   
    



class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "postgresql:///rulezet"

    

    SESSION_TYPE = "sqlalchemy"
    SESSION_SQLALCHEMY_TABLE = "flask_sessions"
    
    @classmethod
    def init_app(cls, app):
        print('THIS APP IS IN DEBUG MODE. YOU SHOULD NOT SEE THIS IN PRODUCTION.')

class TestingConfig(Config):
    TESTING = True
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

    @classmethod
    def init_app(cls, app):
        print('APP IS IN PRODUCTION MODE.')




config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
