import sys
from pathlib import Path

# Ensure the root project folder is in Python search path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import the Flask application instance
from web_app import app

# Vercel Serverless Function entry point
app = app
