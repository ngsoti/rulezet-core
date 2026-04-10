import os
from dotenv import load_dotenv

load_dotenv()
os.environ.setdefault('FLASKENV', 'development')

from app import create_app
app = create_app()