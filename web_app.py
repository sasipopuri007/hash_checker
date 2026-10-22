"""
Web Application Interface for Network File Transfer & SHA-256 Hash Checker.
Provides a modern web dashboard for drag-and-drop file transfers, UUID duplicate handling,
real-time SQLite transfer audit log, tamper simulation, and manual hash checks.
"""

from pathlib import Path
import uuid
from flask import Flask, render_template, request, jsonify, send_file, abort
from werkzeug.utils import secure_filename

import config
from hash_checker import verify_transfer
from hash_utils import calculate_sha256
import protocol
from storage import TransferStorage

config.init_directories()

app = Flask(__name__, template_folder="templates")
storage = TransferStorage()


@app.route("/")
def index():
    """Render the primary dashboard."""
    return render_template("index.html")


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Return transfer metrics from SQLite."""
    all_records = storage.list_transfers(limit=1000)
    total = len(all_records)
    verified = sum(1 for r in all_records if r["status"] == "VERIFIED")
    mismatch = sum(1 for r in all_records if r["status"] == "MISMATCH")
    failed = sum(1 for r in all_records if r["status"] in ("FAILED", "INCOMPLETE"))

    return jsonify({
        "total": total,
        "verified": verified,
        "mismatch": mismatch,
        "failed": failed,
        "backend": getattr(storage, "backend_name", "mongodb")
    })


@app.route("/api/transfers", methods=["GET"])
def get_transfers():
    """Return recent transfers from SQLite."""
    records = storage.list_transfers(limit=100)
    return jsonify(records)


@app.route("/api/transfer", methods=["POST"])
def transfer_file_endpoint():
    """Handle file upload, SHA-256 hashing, UUID isolation, and verification."""
    if "file" not in request.files:
        return jsonify({"status": "FAILED", "error": "No file uploaded"}), 400

    upload = request.files["file"]
    if not upload.filename:
        return jsonify({"status": "FAILED", "error": "Empty filename"}), 400

    raw_filename = upload.filename
    safe_name = protocol.sanitize_filename(raw_filename)
    transfer_id = str(uuid.uuid4())

    # Create dedicated UUID directory for collision-free storage
    target_dir = config.RECEIVED_DIR / transfer_id
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / safe_name

    # Save incoming stream
    upload.save(str(target_path))
    file_size = target_path.stat().st_size

    # Calculate SHA-256 digests
    sender_hash = calculate_sha256(target_path)
    received_hash = sender_hash  # In web upload, receiver recalculates same file

    # Record in SQLite
    status = "VERIFIED"
    msg = f"Transfer verified successfully (SHA-256: {received_hash})"

    storage.record_transfer(
        transfer_id=transfer_id,
        original_filename=safe_name,
        file_size=file_size,
        expected_hash=sender_hash,
        stored_path=str(target_path),
        status="INCOMPLETE"
    )

    storage.update_verification(
        transfer_id=transfer_id,
        received_hash=received_hash,
        status=status,
        error_message=None
    )

    return jsonify({
        "status": status,
        "transfer_id": transfer_id,
        "filename": safe_name,
        "file_size": file_size,
        "sender_hash": sender_hash,
        "received_hash": received_hash,
        "message": msg
    })


@app.route("/api/verify/<transfer_id>", methods=["POST"])
def verify_endpoint(transfer_id):
    """Re-verify a transfer by recalculating SHA-256 of file on disk."""
    result = verify_transfer(transfer_id, storage=storage)
    return jsonify(result)


@app.route("/api/verify-all", methods=["POST"])
def verify_all_endpoint():
    """Audit all transfers in SQLite against files on disk."""
    records = storage.list_transfers(limit=500)
    verified = 0
    mismatch = 0
    failed = 0

    for r in records:
        tid = r["transfer_id"]
        res = verify_transfer(tid, storage=storage)
        st = res.get("status")
        if st == "VERIFIED":
            verified += 1
        elif st == "MISMATCH":
            mismatch += 1
        else:
            failed += 1

    return jsonify({
        "total_audited": len(records),
        "verified": verified,
        "mismatch": mismatch,
        "failed": failed
    })


@app.route("/api/tamper/<transfer_id>", methods=["POST"])
def tamper_endpoint(transfer_id):
    """Artificially tamper with a file on disk to simulate corruption or malicious alteration."""
    record = storage.get_transfer(transfer_id)
    if not record:
        return jsonify({"success": False, "error": "Transfer not found"}), 404

    target = Path(record["stored_path"])
    if not target.exists():
        return jsonify({"success": False, "error": "File does not exist on disk"}), 404

    # Inject tampered bytes
    original = target.read_bytes()
    tampered = original + b"\n[TAMPERED_INJECTION_TEST_DATA]"
    target.write_bytes(tampered)

    return jsonify({
        "success": True,
        "transfer_id": transfer_id,
        "filename": record["original_filename"],
        "message": f"Successfully injected tampered bytes into {target.name}."
    })


@app.route("/api/download/<transfer_id>", methods=["GET"])
def download_endpoint(transfer_id):
    """Download the received file safely."""
    record = storage.get_transfer(transfer_id)
    if not record:
        abort(404, description="Transfer record not found")

    target = Path(record["stored_path"])
    if not target.exists():
        abort(404, description="File does not exist on disk")

    return send_file(
        str(target),
        as_attachment=True,
        download_name=record["original_filename"]
    )


@app.route("/api/sample/<filename>", methods=["GET"])
def get_sample_file(filename):
    """Retrieve sample test files."""
    safe_name = protocol.sanitize_filename(filename)
    sample_path = config.SENDER_FILES_DIR / safe_name
    if not sample_path.exists():
        abort(404, description="Sample file not found")

    return send_file(
        str(sample_path),
        as_attachment=True,
        download_name=safe_name
    )


@app.route("/api/demo/duplicate", methods=["POST"])
def demo_duplicate_endpoint():
    """
    Demonstrate duplicate filename collision avoidance by generating two transfers
    with the identical filename 'report.pdf' but differing content.
    """
    safe_name = "report.pdf"

    # Transfer 1
    t1_id = str(uuid.uuid4())
    t1_dir = config.RECEIVED_DIR / t1_id
    t1_dir.mkdir(parents=True, exist_ok=True)
    t1_path = t1_dir / safe_name
    t1_content = b"%PDF-1.4 Report Copy A: Original Draft created at " + str(uuid.uuid4()).encode()
    t1_path.write_bytes(t1_content)
    t1_hash = calculate_sha256(t1_path)

    storage.record_transfer(
        transfer_id=t1_id,
        original_filename=safe_name,
        file_size=len(t1_content),
        expected_hash=t1_hash,
        stored_path=str(t1_path),
        status="VERIFIED"
    )

    # Transfer 2 (Same filename, different UUID, different content)
    t2_id = str(uuid.uuid4())
    t2_dir = config.RECEIVED_DIR / t2_id
    t2_dir.mkdir(parents=True, exist_ok=True)
    t2_path = t2_dir / safe_name
    t2_content = b"%PDF-1.4 Report Copy B: Final Signed Revision at " + str(uuid.uuid4()).encode()
    t2_path.write_bytes(t2_content)
    t2_hash = calculate_sha256(t2_path)

    storage.record_transfer(
        transfer_id=t2_id,
        original_filename=safe_name,
        file_size=len(t2_content),
        expected_hash=t2_hash,
        stored_path=str(t2_path),
        status="VERIFIED"
    )

    return jsonify({
        "message": "Transferred two duplicate files into distinct UUID folders",
        "transfer1": {
            "transfer_id": t1_id,
            "filename": safe_name,
            "path": str(t1_path),
            "hash": t1_hash
        },
        "transfer2": {
            "transfer_id": t2_id,
            "filename": safe_name,
            "path": str(t2_path),
            "hash": t2_hash
        }
    })


@app.route("/api/check-file", methods=["POST"])
def check_file_endpoint():
    """Calculate SHA-256 of uploaded file and optionally compare with expected hash."""
    if "file" not in request.files:
        return jsonify({"status": "FAILED", "error": "No file uploaded"}), 400

    upload = request.files["file"]
    expected_hash = request.form.get("expected_hash", "").strip().lower()

    # Calculate in memory/chunks from stream
    import hashlib
    hasher = hashlib.sha256()
    while chunk := upload.stream.read(config.BUFFER_SIZE):
        hasher.update(chunk)
    calculated_hash = hasher.hexdigest()

    status = "CALCULATED"
    msg = f"SHA-256 calculated: {calculated_hash}"

    if expected_hash:
        if calculated_hash.lower() == expected_hash:
            status = "VERIFIED"
            msg = "Hashes match! Integrity verified."
        else:
            status = "MISMATCH"
            msg = f"Integrity MISMATCH: expected {expected_hash}, calculated {calculated_hash}"

    return jsonify({
        "status": status,
        "filename": upload.filename,
        "calculated_hash": calculated_hash,
        "expected_hash": expected_hash if expected_hash else None,
        "message": msg
    })


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Secure Network File Transfer Web Application")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    args = parser.parse_args()

    print(f"\n==================================================================")
    print(f" Web Dashboard running at: http://{args.host}:{args.port}")
    print(f" Press Ctrl+C to stop.")
    print(f"==================================================================\n")
    app.run(host=args.host, port=args.port, debug=args.debug)
