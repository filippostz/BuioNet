import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
SECRET_KEY = os.environ.get('SECRET_KEY', 'buionet-secret-key-change-in-production')
MAIN_DB = os.path.join(DATA_DIR, 'main.db')
MAX_UPLOAD_MB = 50
