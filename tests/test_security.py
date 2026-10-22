"""
Tests for security protections:
1. Path traversal attacks
2. Malformed or invalid metadata
3. Authentication token verification
4. File size limit enforcement
"""

from pathlib import Path
import socket
import threading
import time

import protocol
from receiver import ReceiverServer
from storage import TransferStorage


def test_path_traversal_sanitized(tmp_path: Path):
    """Path traversal in original_filename must be stripped to base name and kept inside UUID dir."""
    save_dir = tmp_path / "received"
    db_path = tmp_path / "data" / "transfers.db"
    storage = TransferStorage(db_path=db_path)

    server = ReceiverServer(
        host="127.0.0.1",
        port=0,
        save_dir=save_dir,
        storage=storage,
        auth_token="sec-token"
    )

    server_thread = threading.Thread(target=lambda: server.start(once=True), daemon=True)
    server_thread.start()
    time.sleep(0.1)

    transfer_id = "traversal-uuid-999"
    payload = b"Malicious content payload"
    import hashlib
    h = hashlib.sha256(payload).hexdigest()

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", server.port))

    # Attempt directory traversal filename
    metadata = {
        "transfer_id": transfer_id,
        "original_filename": "../../../../../etc/passwd",
        "file_size": len(payload),
        "sha256": h,
        "auth_token": "sec-token"
    }

    try:
        protocol.send_metadata(client_sock, metadata)
        client_sock.sendall(payload)
        resp = protocol.recv_response(client_sock)
        assert resp["status"] == "VERIFIED"
    finally:
        client_sock.close()

    server.stop()
    server_thread.join(timeout=2.0)

    # Check that file was saved SAFELY inside save_dir / transfer_id / passwd
    record = storage.get_transfer(transfer_id)
    saved_file = Path(record["stored_path"])
    assert saved_file.name == "passwd"
    assert saved_file.resolve().parent == (save_dir / transfer_id).resolve()
    assert saved_file.exists()


def test_invalid_auth_token_rejected(tmp_path: Path):
    """Client sending incorrect auth token must be rejected."""
    save_dir = tmp_path / "received"
    db_path = tmp_path / "data" / "transfers.db"
    storage = TransferStorage(db_path=db_path)

    server = ReceiverServer(
        host="127.0.0.1",
        port=0,
        save_dir=save_dir,
        storage=storage,
        auth_token="super-secret-password"
    )

    server_thread = threading.Thread(target=lambda: server.start(once=True), daemon=True)
    server_thread.start()
    time.sleep(0.1)

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", server.port))

    metadata = {
        "transfer_id": "auth-fail-uuid",
        "original_filename": "secret.txt",
        "file_size": 10,
        "sha256": "a" * 64,
        "auth_token": "wrong-token-value"
    }

    try:
        protocol.send_metadata(client_sock, metadata)
        resp = protocol.recv_response(client_sock)
        assert resp["status"] == "FAILED"
        assert "Authentication failed" in resp.get("error", "")
    finally:
        client_sock.close()

    server.stop()
    server_thread.join(timeout=2.0)


def test_oversized_file_rejected(tmp_path: Path):
    """Transfers exceeding configured max_file_size must be rejected."""
    save_dir = tmp_path / "received"
    db_path = tmp_path / "data" / "transfers.db"
    storage = TransferStorage(db_path=db_path)

    server = ReceiverServer(
        host="127.0.0.1",
        port=0,
        save_dir=save_dir,
        storage=storage,
        auth_token="sec-token",
        max_file_size=1024  # 1 KB limit
    )

    server_thread = threading.Thread(target=lambda: server.start(once=True), daemon=True)
    server_thread.start()
    time.sleep(0.1)

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", server.port))

    metadata = {
        "transfer_id": "oversize-uuid",
        "original_filename": "bigfile.dat",
        "file_size": 1024 * 1024,  # 1 MB exceeds 1 KB limit
        "sha256": "b" * 64,
        "auth_token": "sec-token"
    }

    try:
        protocol.send_metadata(client_sock, metadata)
        resp = protocol.recv_response(client_sock)
        assert resp["status"] == "FAILED"
        assert "exceeds allowed limit" in resp.get("error", "")
    finally:
        client_sock.close()

    server.stop()
    server_thread.join(timeout=2.0)
