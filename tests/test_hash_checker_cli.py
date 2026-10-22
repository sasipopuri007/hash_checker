"""
Tests for hash_checker.py CLI operations and audit utility.
"""

from pathlib import Path
import pytest
from hash_checker import verify_transfer, check_file, cmd_list
from hash_utils import calculate_sha256
from storage import TransferStorage


def test_check_file_standalone(tmp_path: Path):
    """Test standalone check_file helper against valid and mismatch hashes."""
    sample = tmp_path / "hello.txt"
    sample.write_text("Hello World", encoding="utf-8")
    expected_hash = calculate_sha256(sample)

    # Valid check
    res_valid = check_file(sample, expected_hash)
    assert res_valid["status"] == "VERIFIED"

    # Mismatch check
    res_mismatch = check_file(sample, "0" * 64)
    assert res_mismatch["status"] == "MISMATCH"

    # Non-existent file
    res_not_found = check_file(tmp_path / "not_existing.bin", expected_hash)
    assert res_not_found["status"] == "FAILED"


def test_verify_transfer_missing_record(tmp_path: Path):
    """Verifying a non-existent transfer ID must return FAILED."""
    db_path = tmp_path / "transfers.db"
    storage = TransferStorage(db_path=db_path)

    res = verify_transfer("non-existent-uuid", storage=storage)
    assert res["status"] == "FAILED"
    assert "not found" in res["error"]


def test_verify_transfer_missing_file_on_disk(tmp_path: Path):
    """Verifying a record where file on disk was deleted must return FAILED."""
    db_path = tmp_path / "transfers.db"
    storage = TransferStorage(db_path=db_path)
    tid = "deleted-file-uuid"
    missing_path = tmp_path / "missing.dat"

    storage.record_transfer(
        transfer_id=tid,
        original_filename="missing.dat",
        file_size=100,
        expected_hash="a" * 64,
        stored_path=str(missing_path),
        status="VERIFIED"
    )

    res = verify_transfer(tid, storage=storage)
    assert res["status"] == "FAILED"
    assert "does not exist on disk" in res["error"]

    rec = storage.get_transfer(tid)
    assert rec["status"] == "FAILED"
