"""
Configuration settings for Secure Network File Transfer system.
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

# Network settings
DEFAULT_HOST = os.environ.get("NFT_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("NFT_PORT", "9999"))

# Transfer & buffer limits
BUFFER_SIZE = int(os.environ.get("NFT_BUFFER_SIZE", 64 * 1024))  # 64 KB chunk size
MAX_METADATA_SIZE = 64 * 1024  # 64 KB limit for JSON metadata header
MAX_FILE_SIZE = int(os.environ.get("NFT_MAX_FILE_SIZE", 10 * 1024 * 1024 * 1024))  # 10 GB limit

# Security & Authentication
# If AUTH_TOKEN is non-empty, sender must include this token in metadata
AUTH_TOKEN = os.environ.get("NFT_AUTH_TOKEN", "secure-transfer-token-xyz")

# Ensure required runtime directories exist
def init_directories():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
    SENDER_FILES_DIR.mkdir(parents=True, exist_ok=True)
