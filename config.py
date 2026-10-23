"""
Configuration settings for Secure Network File Transfer system.
Supports local SQLite and cloud MongoDB Atlas storage backends.
"""

import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
RECEIVED_DIR = BASE_DIR / "received"
SENDER_FILES_DIR = BASE_DIR / "sender_files"

# SQLite Database and Logging paths
DB_PATH = DATA_DIR / "transfers.db"
LOG_FILE = LOGS_DIR / "transfer.log"

# Storage Backend configuration: 'mongodb' or 'sqlite'
STORAGE_BACKEND = os.environ.get("NFT_STORAGE_BACKEND", "mongodb").lower()

# MongoDB Atlas configuration
DEFAULT_MONGO_URI = (
    "mongodb+srv://sasipopuri007_db_user:v1F103CfS5CXXqc1@cluster0.o9543g6.mongodb.net/"
    "?retryWrites=true&w=majority&appName=Cluster0"
)
MONGODB_URI = os.environ.get("NFT_MONGODB_URI", DEFAULT_MONGO_URI)
MONGODB_DB_NAME = os.environ.get("NFT_MONGODB_DB", "hash_checker")
MONGODB_COLLECTION = "transfers"

# Network settings
DEFAULT_HOST = os.environ.get("NFT_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("NFT_PORT", "9999"))

# Transfer & buffer limits
BUFFER_SIZE = int(os.environ.get("NFT_BUFFER_SIZE", 64 * 1024))  # 64 KB chunk size
MAX_METADATA_SIZE = 512 * 1024  # 512 KB limit for JSON metadata header (supports Block Power Index)
MAX_FILE_SIZE = int(os.environ.get("NFT_MAX_FILE_SIZE", 10 * 1024 * 1024 * 1024))  # 10 GB limit

# Security & Authentication
AUTH_TOKEN = os.environ.get("NFT_AUTH_TOKEN", "secure-transfer-token-xyz")


def init_directories():
    """Ensure required runtime directories exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
    SENDER_FILES_DIR.mkdir(parents=True, exist_ok=True)
