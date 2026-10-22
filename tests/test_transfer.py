"""
End-to-end integration tests for normal file transfer.
Verifies sender and receiver SHA-256 hashes match and status is VERIFIED.
"""

from pathlib import Path
import threading
import time

from receiver import ReceiverServer
from sender import send_file
from storage import TransferStorage


def test_normal_file_transfer(tmp_path: Path):
    """Test transferring a normal file from sender to receiver."""
    save_dir = tmp_path / "received"
    db_path = tmp_path / "data" / "transfers.db"
    storage = TransferStorage(db_path=db_path)

    # Create receiver server bound to dynamic port
    server = ReceiverServer(
        host="127.0.0.1",
        port=0,
        save_dir=save_dir,
        storage=storage,
        auth_token="test-token"
    )

    server_thread = threading.Thread(target=lambda: server.start(once=True), daemon=True)
    server_thread.start()
    time.sleep(0.1)

    # Create a test file to send
    source_file = tmp_path / "test_doc.txt"
    source_content = b"Content for testing end-to-end secure file transfer verification."
    source_file.write_bytes(source_content)

    try:
        result = send_file(
            filepath=source_file,
            host="127.0.0.1",
            port=server.port,
            auth_token="test-token",
            quiet=True
        )

        assert result["status"] == "VERIFIED"
        assert result["sender_hash"] == result["received_hash"]

        # Check DB record
        record = storage.get_transfer(result["transfer_id"])
        assert record is not None
        assert record["status"] == "VERIFIED"
        assert record["file_size"] == len(source_content)
        assert record["original_filename"] == "test_doc.txt"

        # Check file on disk
        stored_file = Path(record["stored_path"])
        assert stored_file.exists()
        assert stored_file.read_bytes() == source_content

    finally:
        server.stop()
        server_thread.join(timeout=2.0)
