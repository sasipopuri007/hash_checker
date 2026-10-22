"""
Tests for detecting tampered or modified files.
Verifies that manual hash check reports MISMATCH if file contents are altered after receipt.
"""

from pathlib import Path
import threading
import time

from hash_checker import verify_transfer
from receiver import ReceiverServer
from sender import send_file
from storage import TransferStorage


def test_tampered_file_reports_mismatch(tmp_path: Path):
    """If a received file is modified on disk, manual re-verification must report MISMATCH."""
    save_dir = tmp_path / "received"
    db_path = tmp_path / "data" / "transfers.db"
    storage = TransferStorage(db_path=db_path)

    server = ReceiverServer(
        host="127.0.0.1",
        port=0,
        save_dir=save_dir,
        storage=storage,
        auth_token="tamper-token"
    )

    server_thread = threading.Thread(target=lambda: server.start(once=True), daemon=True)
    server_thread.start()
    time.sleep(0.1)

    source_file = tmp_path / "sensitive_contract.pdf"
    original_data = b"Original contract agreement terms: Price is $100."
    source_file.write_bytes(original_data)

    try:
        res = send_file(
            filepath=source_file,
            host="127.0.0.1",
            port=server.port,
            auth_token="tamper-token",
            quiet=True
        )
        assert res["status"] == "VERIFIED"
        transfer_id = res["transfer_id"]

        # Now simulate tampering: alter file bytes on disk
        record = storage.get_transfer(transfer_id)
        stored_file = Path(record["stored_path"])
        assert stored_file.exists()

        # Modify content (e.g. malicious edit or disk corruption)
        tampered_data = b"Tampered contract agreement terms: Price is $9999999!"
        stored_file.write_bytes(tampered_data)

        # Run manual hash check via hash_checker
        check_res = verify_transfer(transfer_id, storage=storage)

        assert check_res["status"] == "MISMATCH"
        assert check_res["expected_hash"] == record["expected_hash"]
        assert check_res["calculated_hash"] != record["expected_hash"]

        # Check that DB was updated with MISMATCH status
        updated_rec = storage.get_transfer(transfer_id)
        assert updated_rec["status"] == "MISMATCH"

    finally:
        server.stop()
        server_thread.join(timeout=2.0)
