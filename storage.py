"""
Persistence module for tracking transfers, metadata, and verification statuses.
Supports MongoDB Atlas cloud database and local SQLite storage with automatic fallback.
"""

from datetime import datetime, timezone
import logging
from pathlib import Path
import sqlite3
from typing import Dict, List, Optional, Any

import config

logger = logging.getLogger("Storage")


class SQLiteTransferStorage:
    """Manages SQLite storage for file transfer history and verification logs."""

    def __init__(self, db_path: Path = config.DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.backend_name = "sqlite"
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Initialize the SQLite database schema if not already present."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS transfers (
                    transfer_id TEXT PRIMARY KEY,
                    original_filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    expected_hash TEXT NOT NULL,
                    received_hash TEXT,
                    stored_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    verified_at TEXT,
                    error_message TEXT
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_transfers_filename
                ON transfers(original_filename);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_transfers_status
                ON transfers(status);
            """)
            conn.commit()

    def record_transfer(
        self,
        transfer_id: str,
        original_filename: str,
        file_size: int,
        expected_hash: str,
        stored_path: str,
        status: str = "INCOMPLETE",
        received_hash: Optional[str] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Insert or replace initial record of an incoming transfer."""
        created_at = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO transfers (
                    transfer_id, original_filename, file_size, expected_hash,
                    received_hash, stored_path, status, created_at, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                transfer_id,
                original_filename,
                file_size,
                expected_hash,
                received_hash,
                str(stored_path),
                status,
                created_at,
                error_message
            ))
            conn.commit()

    def update_verification(
        self,
        transfer_id: str,
        received_hash: Optional[str],
        status: str,
        error_message: Optional[str] = None
    ) -> bool:
        """Update the verification result and received hash for a transfer record."""
        verified_at = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE transfers
                SET received_hash = ?,
                    status = ?,
                    verified_at = ?,
                    error_message = ?
                WHERE transfer_id = ?;
            """, (received_hash, status, verified_at, error_message, transfer_id))
            conn.commit()
            return cursor.rowcount > 0

    def get_transfer(self, transfer_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a transfer record by its unique transfer ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM transfers WHERE transfer_id = ?;", (transfer_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_transfers(
        self,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """List transfers, optionally filtered by verification status."""
        query = "SELECT * FROM transfers"
        params: List[Any] = []

        if status:
            query += " WHERE status = ?"
            params.append(status.upper())

        query += " ORDER BY created_at DESC LIMIT ?;"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def get_by_filename(self, filename: str) -> List[Dict[str, Any]]:
        """Retrieve all transfers matching a specific original filename."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM transfers WHERE original_filename = ? ORDER BY created_at DESC;",
                (filename,)
            ).fetchall()
            return [dict(r) for r in rows]


class MongoTransferStorage:
    """Manages MongoDB Atlas storage for file transfer history and verification logs."""

    def __init__(
        self,
        uri: str = config.MONGODB_URI,
        db_name: str = config.MONGODB_DB_NAME,
        collection_name: str = config.MONGODB_COLLECTION
    ):
        from pymongo import MongoClient
        self.uri = uri
        self.db_name = db_name
        self.collection_name = collection_name
        self.backend_name = "mongodb"

        # Initialize client with timeout
        self.client = MongoClient(self.uri, serverSelectionTimeoutMS=8000)
        # Test connection
        self.client.admin.command("ping")
        self.db = self.client[self.db_name]
        self.collection = self.db[self.collection_name]
        self._init_indexes()
        logger.info(f"Connected to MongoDB Atlas: {self.db_name}.{self.collection_name}")

    def _init_indexes(self) -> None:
        """Create helpful indexes for query performance."""
        try:
            self.collection.create_index("transfer_id", unique=True)
            self.collection.create_index("original_filename")
            self.collection.create_index("status")
            self.collection.create_index([("created_at", -1)])
        except Exception as e:
            logger.warning(f"Failed to create MongoDB indexes: {e}")

    def record_transfer(
        self,
        transfer_id: str,
        original_filename: str,
        file_size: int,
        expected_hash: str,
        stored_path: str,
        status: str = "INCOMPLETE",
        received_hash: Optional[str] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Insert or replace initial record of an incoming transfer in MongoDB."""
        created_at = datetime.now(timezone.utc).isoformat()
        doc = {
            "_id": transfer_id,
            "transfer_id": transfer_id,
            "original_filename": original_filename,
            "file_size": file_size,
            "expected_hash": expected_hash,
            "received_hash": received_hash,
            "stored_path": str(stored_path),
            "status": status,
            "created_at": created_at,
            "verified_at": None,
            "error_message": error_message
        }
        self.collection.replace_one({"_id": transfer_id}, doc, upsert=True)

    def update_verification(
        self,
        transfer_id: str,
        received_hash: Optional[str],
        status: str,
        error_message: Optional[str] = None
    ) -> bool:
        """Update the verification result and received hash for a transfer record."""
        verified_at = datetime.now(timezone.utc).isoformat()
        res = self.collection.update_one(
            {"_id": transfer_id},
            {"$set": {
                "received_hash": received_hash,
                "status": status,
                "verified_at": verified_at,
                "error_message": error_message
            }}
        )
        return res.matched_count > 0

    def get_transfer(self, transfer_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a transfer record by its unique transfer ID."""
        doc = self.collection.find_one({"_id": transfer_id})
        if doc:
            doc.pop("_id", None)
            return doc
        return None

    def list_transfers(
        self,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """List transfers, optionally filtered by verification status."""
        query = {}
        if status:
            query["status"] = status.upper()

        cursor = self.collection.find(query).sort("created_at", -1).limit(limit)
        results = []
        for doc in cursor:
            doc.pop("_id", None)
            results.append(doc)
        return results

    def get_by_filename(self, filename: str) -> List[Dict[str, Any]]:
        """Retrieve all transfers matching a specific original filename."""
        cursor = self.collection.find({"original_filename": filename}).sort("created_at", -1)
        results = []
        for doc in cursor:
            doc.pop("_id", None)
            results.append(doc)
        return results


def get_storage(backend: Optional[str] = None, **kwargs) -> Any:
    """
    Factory to retrieve storage instance based on configuration.
    Defaults to MongoDB Atlas with seamless fallback to SQLite if offline.
    """
    if "db_path" in kwargs:
        return SQLiteTransferStorage(**kwargs)

    selected_backend = (backend or config.STORAGE_BACKEND).lower()

    if selected_backend == "mongodb":
        try:
            return MongoTransferStorage(**kwargs)
        except Exception as e:
            logger.warning(
                f"Could not connect to MongoDB Atlas ({e}). Falling back to local SQLite storage."
            )
            return SQLiteTransferStorage()

    return SQLiteTransferStorage(**kwargs)


class TransferStorage:
    """
    Default storage interface class that forwards calls to the active storage engine
    (MongoDB Atlas or SQLite).
    """

    def __init__(self, backend: Optional[str] = None, **kwargs):
        self._engine = get_storage(backend=backend, **kwargs)
        self.backend_name = self._engine.backend_name

    def record_transfer(self, *args, **kwargs):
        return self._engine.record_transfer(*args, **kwargs)

    def update_verification(self, *args, **kwargs):
        return self._engine.update_verification(*args, **kwargs)

    def get_transfer(self, *args, **kwargs):
        return self._engine.get_transfer(*args, **kwargs)

    def list_transfers(self, *args, **kwargs):
        return self._engine.list_transfers(*args, **kwargs)

    def get_by_filename(self, *args, **kwargs):
        return self._engine.get_by_filename(*args, **kwargs)
