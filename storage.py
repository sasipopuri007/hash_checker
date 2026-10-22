"""
SQLite persistence module for tracking transfers, metadata, and verification statuses.
Stores transfer UUIDs, original filenames, file sizes, expected/received hashes,
file paths, timestamps, and verification states.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

import config


class TransferStorage:
    """Manages SQLite storage for file transfer history and verification logs."""

    def __init__(self, db_path: Path = config.DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
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
