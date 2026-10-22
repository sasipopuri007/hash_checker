"""
Tests for TLS encrypted transfer.
Verifies end-to-end transfer using self-signed TLS certificates.
"""

from pathlib import Path
import threading
import time

from generate_certs import generate_self_signed_cert
from receiver import ReceiverServer
from sender import send_file
from storage import TransferStorage


def test_tls_transfer(tmp_path: Path):
    """End-to-end file transfer over TLS socket."""
    cert_path, key_path = generate_self_signed_cert(
        cert_path=tmp_path / "server.crt",
        key_path=tmp_path / "server.key",
        host="127.0.0.1"
    )

    save_dir = tmp_path / "received"
    db_path = tmp_path / "data" / "transfers.db"
    storage = TransferStorage(db_path=db_path)

    server = ReceiverServer(
        host="127.0.0.1",
        port=0,
        save_dir=save_dir,
        storage=storage,
        auth_token="tls-token-123",
        cert_path=cert_path,
        key_path=key_path
    )

    server_thread = threading.Thread(target=lambda: server.start(once=True), daemon=True)
    server_thread.start()
    time.sleep(0.1)

    source_file = tmp_path / "encrypted_doc.pdf"
    content = b"%PDF-1.4 Secret Encrypted Document Payload"
    source_file.write_bytes(content)

    try:
        res = send_file(
            filepath=source_file,
            host="127.0.0.1",
            port=server.port,
            auth_token="tls-token-123",
            quiet=True,
            use_tls=True,
            ca_cert=cert_path
        )

        assert res["status"] == "VERIFIED"
        assert res["sender_hash"] == res["received_hash"]

        record = storage.get_transfer(res["transfer_id"])
        assert record is not None
        assert record["status"] == "VERIFIED"

    finally:
        server.stop()
        server_thread.join(timeout=2.0)
