"""
Tests for handling duplicate filenames across transfers.
Verifies that multiple files sharing the exact same filename:
1. Are stored in separate directories partitioned by UUID (received/<uuid>/<filename>)
2. Do not overwrite each other
3. Retain independent expected hashes and verification statuses in SQLite.
"""

from pathlib import Path
import threading
import time

from receiver import ReceiverServer
from sender import send_file
from storage import TransferStorage


def test_duplicate_filenames_isolated(tmp_path: Path):
    """Two files with the same name are stored in distinct directories and tracked separately."""
    save_dir = tmp_path / "received"
    db_path = tmp_path / "data" / "transfers.db"
    storage = TransferStorage(db_path=db_path)

    server = ReceiverServer(
        host="127.0.0.1",
        port=0,
        save_dir=save_dir,
        storage=storage,
        auth_token="dup-test-token"
    )

    server_thread = threading.Thread(
        target=lambda: server.start(max_transfers=2), daemon=True
    )
    server_thread.start()
    time.sleep(0.1)

    # First file with name 'report.pdf'
    dir1 = tmp_path / "client1"
    dir1.mkdir()
    file1 = dir1 / "report.pdf"
    content1 = b"%PDF-1.4 Report Version 1: Initial Draft"
    file1.write_bytes(content1)

    # Second file also with name 'report.pdf' but different contents
    dir2 = tmp_path / "client2"
    dir2.mkdir()
    file2 = dir2 / "report.pdf"
    content2 = b"%PDF-1.4 Report Version 2: Final Signed Copy with Amendments"
    file2.write_bytes(content2)

    try:
        res1 = send_file(
            filepath=file1,
            host="127.0.0.1",
            port=server.port,
            auth_token="dup-test-token",
            quiet=True
        )
        assert res1["status"] == "VERIFIED"

        res2 = send_file(
            filepath=file2,
            host="127.0.0.1",
            port=server.port,
            auth_token="dup-test-token",
            quiet=True
        )
        assert res2["status"] == "VERIFIED"

        # Transfer IDs must be distinct
        uuid1 = res1["transfer_id"]
        uuid2 = res2["transfer_id"]
        assert uuid1 != uuid2

        # Check SQLite records
        rec1 = storage.get_transfer(uuid1)
        rec2 = storage.get_transfer(uuid2)
        assert rec1 is not None and rec2 is not None

        assert rec1["original_filename"] == "report.pdf"
        assert rec2["original_filename"] == "report.pdf"
        assert rec1["expected_hash"] != rec2["expected_hash"]

        # Check paths on disk
        path1 = Path(rec1["stored_path"])
        path2 = Path(rec2["stored_path"])
        assert path1 != path2
        assert path1.exists()
        assert path2.exists()

        # Check contents are intact without overwriting
        assert path1.read_bytes() == content1
        assert path2.read_bytes() == content2

        # Confirm directory isolation structure: received/<uuid>/report.pdf
        assert path1.parent.name == uuid1
        assert path2.parent.name == uuid2

        # Query by filename from storage
        matching = storage.get_by_filename("report.pdf")
        assert len(matching) == 2

    finally:
        server.stop()
        server_thread.join(timeout=2.0)
