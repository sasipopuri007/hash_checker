"""
Tests for Flask web application endpoints.
"""

import io
from pathlib import Path
import pytest
from web_app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_route(client):
    """GET / must render the dashboard page with HTTP 200."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"Integrity Verification" in response.data or b"Secure Network File Transfer" in response.data


def test_api_stats(client):
    """GET /api/stats must return JSON with metric fields."""
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.get_json()
    assert "total" in data
    assert "verified" in data
    assert "mismatch" in data
    assert "failed" in data


def test_api_transfers_list(client):
    """GET /api/transfers must return a list of transfers."""
    response = client.get("/api/transfers")
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)


def test_api_transfer_upload(client):
    """POST /api/transfer must accept file, save under UUID folder, and verify SHA-256."""
    file_bytes = b"Sample upload content for web API test"
    data = {
        "file": (io.BytesIO(file_bytes), "web_sample.txt")
    }
    response = client.post("/api/transfer", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    res = response.get_json()
    assert res["status"] == "VERIFIED"
    assert res["filename"] == "web_sample.txt"
    assert res["file_size"] == len(file_bytes)
    assert "transfer_id" in res
    assert res["sender_hash"] == res["received_hash"]

    # Verify endpoint works on new transfer
    transfer_id = res["transfer_id"]
    verify_resp = client.post(f"/api/verify/{transfer_id}")
    assert verify_resp.status_code == 200
    assert verify_resp.get_json()["status"] == "VERIFIED"


def test_tamper_and_reverify_web_api(client):
    """Tampering through web API must result in MISMATCH upon subsequent verification."""
    # First upload a file
    file_bytes = b"Original uncorrupted bytes"
    data = {
        "file": (io.BytesIO(file_bytes), "contract_web.pdf")
    }
    resp = client.post("/api/transfer", data=data, content_type="multipart/form-data")
    transfer_id = resp.get_json()["transfer_id"]

    # Tamper file
    tamper_resp = client.post(f"/api/tamper/{transfer_id}")
    assert tamper_resp.status_code == 200
    assert tamper_resp.get_json()["success"] is True

    # Re-verify
    reverify_resp = client.post(f"/api/verify/{transfer_id}")
    assert reverify_resp.status_code == 200
    assert reverify_resp.get_json()["status"] == "MISMATCH"


def test_duplicate_demo_api(client):
    """POST /api/demo/duplicate must create two distinct transfers for report.pdf."""
    resp = client.post("/api/demo/duplicate")
    assert resp.status_code == 200
    data = resp.get_json()
    t1 = data["transfer1"]
    t2 = data["transfer2"]

    assert t1["filename"] == "report.pdf"
    assert t2["filename"] == "report.pdf"
    assert t1["transfer_id"] != t2["transfer_id"]
    assert t1["path"] != t2["path"]


def test_check_file_api(client):
    """POST /api/check-file computes SHA-256 and compares with expected hash."""
    content = b"Standalone hash calculation test"
    import hashlib
    correct_hash = hashlib.sha256(content).hexdigest()

    # Matching hash
    data_match = {
        "file": (io.BytesIO(content), "doc.txt"),
        "expected_hash": correct_hash
    }
    resp_match = client.post("/api/check-file", data=data_match, content_type="multipart/form-data")
    assert resp_match.status_code == 200
    assert resp_match.get_json()["status"] == "VERIFIED"

    # Mismatch hash
    data_mismatch = {
        "file": (io.BytesIO(content), "doc.txt"),
        "expected_hash": "f" * 64
    }
    resp_mismatch = client.post("/api/check-file", data=data_mismatch, content_type="multipart/form-data")
    assert resp_mismatch.status_code == 200
    assert resp_mismatch.get_json()["status"] == "MISMATCH"


def test_localize_endpoint(client):
    """POST /api/localize/<id> returns block power index localization."""
    file_bytes = b"X" * 4096
    data = {"file": (io.BytesIO(file_bytes), "block_test.bin")}
    resp = client.post("/api/transfer", data=data, content_type="multipart/form-data")
    transfer_id = resp.get_json()["transfer_id"]

    loc_resp = client.post(f"/api/localize/{transfer_id}")
    assert loc_resp.status_code == 200
    res = loc_resp.get_json()
    assert res["status"] == "VERIFIED"
    assert res["is_intact"] is True
    assert res["total_blocks"] > 0


def test_avalanche_endpoint(client):
    """POST /api/avalanche measures bit diffusion under 1-bit input flip."""
    data = {
        "text": "Gilbert & Gilbert 2025 Cryptographic Research Benchmark",
        "algorithm": "sha256",
        "bit_to_flip": 2
    }
    resp = client.post("/api/avalanche", data=data)
    assert resp.status_code == 200
    res = resp.get_json()
    assert "avalanche_percentage" in res
    assert 30.0 <= res["avalanche_percentage"] <= 70.0
    assert res["flipped_bits"] > 50


def test_benchmark_endpoint(client):
    """GET /api/benchmark returns comparative cryptographic metrics."""
    resp = client.get("/api/benchmark?size_mb=0.1")
    assert resp.status_code == 200
    res = resp.get_json()
    assert "results" in res
    assert len(res["results"]) >= 5
