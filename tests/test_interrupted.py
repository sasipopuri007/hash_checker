"""
Tests for interrupted or incomplete transfers.
Verifies that if transfer is dropped mid-stream, status is marked FAILED,
and incomplete files are never marked VERIFIED.
Also tests empty file transfers.
"""

from pathlib import Path
import socket
import threading
import time

import protocol
from receiver import ReceiverServer
from sender import send_file
from storage import TransferStorage


def test_interrupted_transfer_marks_failed(tmp_path: Path):
    """If sender disconnects prematurely, transfer must be recorded as FAILED."""
    save_dir = tmp_path / "received"
    db_path = tmp_path / "data" / "transfers.db"
    storage = TransferStorage(db_path=db_path)

    server = ReceiverServer(
        host="127.0.0.1",
        port=0,
        save_dir=save_dir,
        storage=storage,
        auth_token="drop-token"
    )

    server_thread = threading.Thread(target=lambda: server.start(once=True), daemon=True)
    server_thread.start()
    time.sleep(0.1)

    transfer_id = "drop-test-uuid-12345"
    declared_size = 50000
    fake_hash = "0" * 64

    # Connect client and send metadata for 50,000 bytes
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", server.port))

    metadata = {
        "transfer_id": transfer_id,
        "original_filename": "aborted_file.dat",
        "file_size": declared_size,
        "sha256": fake_hash,
        "auth_token": "drop-token"
    }

    try:
        protocol.send_metadata(client_sock, metadata)
        # Send only 1,000 bytes out of 50,000 bytes, then abruptly close socket
        client_sock.sendall(b"X" * 1000)
    finally:
        client_sock.close()

    # Wait for receiver to process interruption
    time.sleep(0.5)
    server.stop()
    server_thread.join(timeout=2.0)

    # Check database record
    record = storage.get_transfer(transfer_id)
    assert record is not None
    assert record["status"] == "FAILED"
    assert record["status"] != "VERIFIED"

    # Verify no file is stored as a valid verified file
    target_path = Path(record["stored_path"])
    assert not target_path.exists()

    # The partial file was renamed to .incomplete
    incomplete_path = target_path.with_suffix(target_path.suffix + ".incomplete")
    assert incomplete_path.exists()
    assert incomplete_path.stat().st_size == 1000


def test_empty_file_transfer(tmp_path: Path):
    """Empty files (0 bytes) must transfer correctly and verify against empty SHA-256."""
    save_dir = tmp_path / "received"
    db_path = tmp_path / "data" / "transfers.db"
    storage = TransferStorage(db_path=db_path)

    server = ReceiverServer(
        host="127.0.0.1",
        port=0,
        save_dir=save_dir,
        storage=storage,
        auth_token="empty-token"
    )

    server_thread = threading.Thread(target=lambda: server.start(once=True), daemon=True)
    server_thread.start()
    time.sleep(0.1)

    empty_file = tmp_path / "empty_test.txt"
    empty_file.touch()

    try:
        res = send_file(
            filepath=empty_file,
            host="127.0.0.1",
            port=server.port,
            auth_token="empty-token",
            quiet=True
        )
        assert res["status"] == "VERIFIED"
        assert res["file_size"] == 0

        record = storage.get_transfer(res["transfer_id"])
        assert record["status"] == "VERIFIED"
        assert record["file_size"] == 0

        stored = Path(record["stored_path"])
        assert stored.exists()
        assert stored.stat().st_size == 0
    finally:
        server.stop()
        server_thread.join(timeout=2.0)
