"""
Tests for MongoDB Atlas storage backend.
"""

import uuid
import pytest
from storage import MongoTransferStorage, get_storage
import config


def test_mongo_storage_lifecycle():
    """Verify record, get, update, and list operations against MongoDB Atlas."""
    try:
        storage = MongoTransferStorage()
    except Exception as e:
        pytest.skip(f"MongoDB Atlas cluster unreachable: {e}")

    transfer_id = f"test-mongo-uuid-{uuid.uuid4()}"
    filename = "test_cloud_file.pdf"
    file_size = 2048
    expected_hash = "1" * 64
    stored_path = f"received/{transfer_id}/{filename}"

    # Record transfer
    storage.record_transfer(
        transfer_id=transfer_id,
        original_filename=filename,
        file_size=file_size,
        expected_hash=expected_hash,
        stored_path=stored_path,
        status="INCOMPLETE"
    )

    # Fetch transfer
    rec = storage.get_transfer(transfer_id)
    assert rec is not None
    assert rec["transfer_id"] == transfer_id
    assert rec["original_filename"] == filename
    assert rec["file_size"] == file_size
    assert rec["status"] == "INCOMPLETE"

    # Update verification
    received_hash = expected_hash
    storage.update_verification(
        transfer_id=transfer_id,
        received_hash=received_hash,
        status="VERIFIED"
    )

    updated = storage.get_transfer(transfer_id)
    assert updated["status"] == "VERIFIED"
    assert updated["received_hash"] == received_hash
    assert updated["verified_at"] is not None

    # List transfers
    transfers = storage.list_transfers(limit=10)
    assert any(t["transfer_id"] == transfer_id for t in transfers)

    # Query by filename
    by_fn = storage.get_by_filename(filename)
    assert len(by_fn) >= 1

    # Cleanup test record
    storage.collection.delete_one({"_id": transfer_id})
