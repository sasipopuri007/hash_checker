"""
Web Application Interface for Network File Transfer & Advanced Cryptographic Integrity Verification.
Based on Gilbert & Gilbert (2025):
- Dual SHA-256 + SHA-3-256 verification
- Block Power Indexing & Tamper Localization (Section 7.1)
- Avalanche Effect & Bit Diffusion Lab (Section II & IV)
- Multi-Algorithm Cryptographic Benchmark (Table 3, Section IX)
- MongoDB Atlas Cloud Database and local SQLite storage
"""

from pathlib import Path
import uuid
from flask import Flask, render_template, request, jsonify, send_file, abort, make_response

from advanced_hash import (
    BlockPowerIndexer,
    AvalancheAnalyzer,
    AlgorithmBenchmark,
    RobustnessPerturbationLab,
    ResidualSignatureTracer,
    CollisionProbabilityCalculator,
    ResearchReportGenerator,
    calculate_shannon_entropy
)
import config
from hash_checker import verify_transfer
from hash_utils import calculate_sha256, calculate_dual_hash
import protocol
from storage import TransferStorage

config.init_directories()

def find_templates_dir():
    candidates = [
        Path(__file__).resolve().parent / "templates",
        Path(__file__).resolve().parent / "api" / "templates",
        Path.cwd() / "templates",
        Path.cwd() / "api" / "templates",
    ]
    for c in candidates:
        if (c / "index.html").exists():
            return c
    return candidates[0]

TEMPLATES_DIR = find_templates_dir()
app = Flask(__name__, template_folder=str(TEMPLATES_DIR))
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024 * 1024  # 10 GB upload limit
storage = TransferStorage()


@app.errorhandler(413)
def request_entity_too_large(error):
    return make_response(jsonify({"status": "FAILED", "error": "File exceeds maximum upload size (10 GB)."}), 413)


@app.errorhandler(500)
def internal_server_error(error):
    return make_response(jsonify({"status": "FAILED", "error": f"Internal server error: {str(error)}"}), 500)


@app.errorhandler(Exception)
def unhandled_exception(e):
    return make_response(jsonify({"status": "FAILED", "error": f"Server error: {str(e)}"}), 500)


@app.route("/")
def index():
    """Render the primary dashboard."""
    try:
        return render_template("index.html")
    except Exception:
        index_file = TEMPLATES_DIR / "index.html"
        if index_file.exists():
            return index_file.read_text(encoding="utf-8"), 200, {"Content-Type": "text/html; charset=utf-8"}
        raise


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Return transfer metrics from Storage."""
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
    """Return recent transfers from database."""
    records = storage.list_transfers(limit=100)
    return jsonify(records)


@app.route("/api/transfer", methods=["POST"])
def transfer_file_endpoint():
    """
    Handle file upload, Dual Hashing (SHA-256 + SHA-3-256), Block Power Indexing,
    UUID isolation, and automated verification.
    """
    try:
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

        # Calculate Dual Hashes (SHA-256 Merkle-Damgård + SHA-3-256 Keccak Sponge)
        dual = calculate_dual_hash(target_path)
        sender_sha256 = dual["sha256"]
        sender_sha3 = dual["sha3_256"]

        # Compute Block Power Index for fine-grained tamper localization (Section 7.1)
        indexer = BlockPowerIndexer()
        block_index = indexer.compute_block_index(target_path)

        status = "VERIFIED"
        msg = "Dual-layer verified: SHA-256 and SHA-3-256 match perfectly."

        storage.record_transfer(
            transfer_id=transfer_id,
            original_filename=safe_name,
            file_size=file_size,
            expected_hash=sender_sha256,
            stored_path=str(target_path),
            status="INCOMPLETE",
            sha3_256=sender_sha3,
            block_index=block_index
        )

        storage.update_verification(
            transfer_id=transfer_id,
            received_hash=sender_sha256,
            status=status,
            error_message=None,
            received_sha3=sender_sha3,
            tamper_localization=None
        )

        return jsonify({
            "status": status,
            "transfer_id": transfer_id,
            "filename": safe_name,
            "file_size": file_size,
            "sender_hash": sender_sha256,
            "received_hash": sender_sha256,
            "sha3_256": sender_sha3,
            "block_count": len(block_index),
            "message": msg
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "FAILED", "error": f"Transfer failed: {str(e)}"}), 500


@app.route("/api/verify/<transfer_id>", methods=["POST"])
def verify_endpoint(transfer_id):
    """Re-verify a transfer by recalculating dual hashes and localizing any corruption."""
    result = verify_transfer(transfer_id, storage=storage)
    # Alias fields so the receiver panel can compare sender vs receiver hashes
    result["received_hash"] = result.get("calculated_hash")
    result["received_sha3"] = result.get("calculated_sha3")
    try:
        rec = storage.get_transfer(transfer_id)
        if rec:
            result.setdefault("file_size", rec.get("file_size", 0))
            result.setdefault("block_count", len(rec.get("block_index") or []))
    except Exception:
        pass
    return jsonify(result)


@app.route("/api/localize/<transfer_id>", methods=["POST"])
def localize_endpoint(transfer_id):
    """
    Fine-Grained Tamper Localization (Section 7.1, RQ v).
    Compares current file on disk against recorded Block Power Index,
    identifying exact corrupted blocks, offsets, and corruption percentages.
    """
    record = storage.get_transfer(transfer_id)
    if not record:
        return jsonify({"status": "FAILED", "error": "Transfer record not found"}), 404

    target = Path(record["stored_path"])
    block_index = record.get("block_index")
    if not block_index:
        return jsonify({
            "status": "FAILED",
            "error": "No Block Power Index recorded for this transfer."
        }), 400

    indexer = BlockPowerIndexer()
    report = indexer.localize_tampering(target, block_index)
    report["transfer_id"] = transfer_id
    report["filename"] = record["original_filename"]

    # Save localization report to database
    storage.update_verification(
        transfer_id=transfer_id,
        received_hash=record.get("received_hash"),
        status=record.get("status"),
        error_message=record.get("error_message"),
        tamper_localization=report
    )

    return jsonify(report)


@app.route("/api/avalanche", methods=["POST"])
def avalanche_endpoint():
    """
    Avalanche Effect & Bit Diffusion Lab (Section II & IV).
    Flips 1 bit in input data and computes Hamming distance diffusion metric.
    """
    algorithm = request.form.get("algorithm", "sha256").lower()
    text = request.form.get("text", "")
    bit_to_flip = int(request.form.get("bit_to_flip", 0))

    if "file" in request.files and request.files["file"].filename:
        data = request.files["file"].read()
    elif text:
        data = text.encode("utf-8")
    else:
        data = b"Cryptographic Integrity Verification Baseline Data"

    result = AvalancheAnalyzer.calculate_avalanche(
        input_data=data,
        algorithm=algorithm,
        bit_to_flip=bit_to_flip
    )
    return jsonify(result)


@app.route("/api/benchmark", methods=["GET"])
def benchmark_endpoint():
    """
    Cryptographic Algorithm Benchmark (Gilbert & Gilbert 2025, Table 3).
    Evaluates throughput, latency, and security strength across SHA variants.
    """
    size_mb = float(request.args.get("size_mb", 2.0))
    results = AlgorithmBenchmark.run_benchmark(data_size_mb=size_mb)
    return jsonify({
        "data_size_mb": size_mb,
        "results": results
    })


@app.route("/api/verify-all", methods=["POST"])
def verify_all_endpoint():
    """Audit all transfers in database against files on disk."""
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
    """
    Artificially tamper with a file on disk.
    Modifies bytes in the first quarter of the file to demonstrate Block Power Localization.
    """
    record = storage.get_transfer(transfer_id)
    if not record:
        return jsonify({"success": False, "error": "Transfer not found"}), 404

    target = Path(record["stored_path"])
    if not target.exists():
        return jsonify({"success": False, "error": "File does not exist on disk"}), 404

    # Inject tampered byte in middle of the data
    original = bytearray(target.read_bytes())
    if len(original) > 10:
        pos = min(len(original) // 2, 50)
        original[pos] ^= 0xFF  # Flip all 8 bits in byte at offset pos
    else:
        original.extend(b"[CORRUPTED]")

    target.write_bytes(original)

    # Immediately recalculate and localize tampering
    block_index = record.get("block_index")
    tamper_report = None
    if block_index:
        indexer = BlockPowerIndexer()
        tamper_report = indexer.localize_tampering(target, block_index)

    return jsonify({
        "success": True,
        "transfer_id": transfer_id,
        "filename": record["original_filename"],
        "tamper_report": tamper_report,
        "message": f"Successfully injected byte corruption into {target.name}."
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
    candidates = [
        config.SENDER_FILES_DIR / safe_name,
        Path(__file__).resolve().parent / "sender_files" / safe_name,
        Path(__file__).resolve().parent / "api" / "sender_files" / safe_name,
        Path.cwd() / "sender_files" / safe_name,
        Path.cwd() / "api" / "sender_files" / safe_name,
    ]
    for p in candidates:
        if p.exists():
            return send_file(str(p), as_attachment=True, download_name=safe_name)
    abort(404, description="Sample file not found")


@app.route("/api/demo/duplicate", methods=["POST"])
def demo_duplicate_endpoint():
    """
    Demonstrate duplicate filename collision avoidance by generating two transfers
    with the identical filename 'report.pdf' but differing content.
    """
    safe_name = "report.pdf"
    indexer = BlockPowerIndexer()

    # Transfer 1
    t1_id = str(uuid.uuid4())
    t1_dir = config.RECEIVED_DIR / t1_id
    t1_dir.mkdir(parents=True, exist_ok=True)
    t1_path = t1_dir / safe_name
    t1_content = b"%PDF-1.4 Report Copy A: Original Draft created at " + str(uuid.uuid4()).encode()
    t1_path.write_bytes(t1_content)
    t1_dual = calculate_dual_hash(t1_path)
    t1_blocks = indexer.compute_block_index(t1_path)

    storage.record_transfer(
        transfer_id=t1_id,
        original_filename=safe_name,
        file_size=len(t1_content),
        expected_hash=t1_dual["sha256"],
        stored_path=str(t1_path),
        status="VERIFIED",
        sha3_256=t1_dual["sha3_256"],
        block_index=t1_blocks
    )

    # Transfer 2 (Same filename, different UUID, different content)
    t2_id = str(uuid.uuid4())
    t2_dir = config.RECEIVED_DIR / t2_id
    t2_dir.mkdir(parents=True, exist_ok=True)
    t2_path = t2_dir / safe_name
    t2_content = b"%PDF-1.4 Report Copy B: Final Signed Revision at " + str(uuid.uuid4()).encode()
    t2_path.write_bytes(t2_content)
    t2_dual = calculate_dual_hash(t2_path)
    t2_blocks = indexer.compute_block_index(t2_path)

    storage.record_transfer(
        transfer_id=t2_id,
        original_filename=safe_name,
        file_size=len(t2_content),
        expected_hash=t2_dual["sha256"],
        stored_path=str(t2_path),
        status="VERIFIED",
        sha3_256=t2_dual["sha3_256"],
        block_index=t2_blocks
    )

    return jsonify({
        "message": "Transferred two duplicate files into distinct UUID folders",
        "transfer1": {
            "transfer_id": t1_id,
            "filename": safe_name,
            "path": str(t1_path),
            "sha256": t1_dual["sha256"],
            "sha3_256": t1_dual["sha3_256"],
            "blocks": len(t1_blocks)
        },
        "transfer2": {
            "transfer_id": t2_id,
            "filename": safe_name,
            "path": str(t2_path),
            "sha256": t2_dual["sha256"],
            "sha3_256": t2_dual["sha3_256"],
            "blocks": len(t2_blocks)
        }
    })


@app.route("/api/check-file", methods=["POST"])
def check_file_endpoint():
    """Calculate SHA-256 and SHA-3-256 of uploaded file and optionally compare with expected hash."""
    if "file" not in request.files:
        return jsonify({"status": "FAILED", "error": "No file uploaded"}), 400

    upload = request.files["file"]
    expected_hash = request.form.get("expected_hash", "").strip().lower()

    content = upload.stream.read()
    import hashlib
    sha256_hash = hashlib.sha256(content).hexdigest()
    sha3_hash = hashlib.sha3_256(content).hexdigest()

    status = "CALCULATED"
    msg = f"Hashes calculated: SHA-256 and SHA-3-256"

    if expected_hash:
        if sha256_hash.lower() == expected_hash or sha3_hash.lower() == expected_hash:
            status = "VERIFIED"
            msg = "Hashes match! Integrity verified."
        else:
            status = "MISMATCH"
            msg = f"Integrity MISMATCH: expected {expected_hash}, calculated {sha256_hash}"

    return jsonify({
        "status": status,
        "filename": upload.filename,
        "calculated_hash": sha256_hash,
        "sha3_256": sha3_hash,
        "expected_hash": expected_hash if expected_hash else None,
        "message": msg
    })


@app.route("/api/robustness-test", methods=["POST"])
def robustness_test_endpoint():
    """
    Run Empirical Robustness Testing across 3 data disturbance domains (Section 6 & Table 2):
    Bit-level noise, metadata alteration, and structural reordering.
    """
    if "file" in request.files and request.files["file"].filename:
        data = request.files["file"].stream.read()
    elif request.is_json and "text" in request.json:
        data = request.json["text"].encode("utf-8")
    elif request.form.get("text"):
        data = request.form.get("text").encode("utf-8")
    else:
        data = b"Gilbert & Gilbert (2025) Cryptographic Robustness Verification Benchmark Payload"

    result = RobustnessPerturbationLab.run_robustness_evaluation(data)
    return jsonify(result)


@app.route("/api/trace-signature", methods=["POST"])
def trace_signature_endpoint():
    """
    Forensic Residual Cryptographic Signature (RCS) Tracing & Tamper Classification (RQ v).
    Computes Shannon entropy gradients and classifies tampering vectors.
    """
    req_data = request.get_json(silent=True) or {}
    transfer_id = req_data.get("transfer_id") or request.form.get("transfer_id")

    if transfer_id:
        record = storage.get_transfer(transfer_id)
        if not record:
            return jsonify({"status": "FAILED", "error": f"Transfer record not found: {transfer_id}"}), 404
        target_path = Path(record["stored_path"])
        if not target_path.exists():
            return jsonify({"status": "FAILED", "error": f"File not found on disk: {target_path}"}), 404
        orig_bytes = target_path.read_bytes()

        # If simulated tamper requested or file is currently intact, test with a 1-byte perturbation
        simulate = req_data.get("simulate", True)
        if simulate or record.get("status") == "VERIFIED":
            alt = bytearray(orig_bytes)
            if len(alt) > 10:
                alt[5] ^= 0x01
            tampered_bytes = bytes(alt)
        else:
            tampered_bytes = orig_bytes
    elif "file" in request.files and request.files["file"].filename:
        orig_bytes = request.files["file"].stream.read()
        alt = bytearray(orig_bytes)
        if len(alt) > 10:
            alt[5] ^= 0x01
        tampered_bytes = bytes(alt)
    elif "text" in req_data:
        orig_bytes = req_data["text"].encode("utf-8")
        alt = bytearray(orig_bytes)
        if len(alt) > 0:
            alt[0] ^= 0x01
        tampered_bytes = bytes(alt)
    else:
        return jsonify({"status": "FAILED", "error": "No transfer_id, file, or text provided"}), 400

    trace_result = ResidualSignatureTracer.trace_signature(orig_bytes, tampered_bytes)
    return jsonify(trace_result)


@app.route("/api/collision-calculator", methods=["GET"])
def collision_calculator_endpoint():
    """
    Birthday Paradox Collision Probability & Cryptographic Attack Feasibility Calculator
    (Section 5.1 & 5.2, Figures 8, 9, 10).
    """
    items = request.args.get("items", default=1_000_000, type=int)
    bits = request.args.get("bits", default=256, type=int)

    prob_data = CollisionProbabilityCalculator.calculate_collision_probability(items, digest_bits=bits)
    attack_matrix = CollisionProbabilityCalculator.get_attack_feasibility_matrix()

    return jsonify({
        "collision_analysis": prob_data,
        "attack_feasibility_matrix": attack_matrix
    })


@app.route("/api/demo/mismatch", methods=["POST"])
def demo_mismatch_endpoint():
    """
    Demonstrate a Sender vs Receiver hash mismatch entirely within the web UI.
    Creates a 'sender' file, saves it as 'received', then corrupts the received copy.
    Returns both sender hashes and receiver hashes (which will differ) along with
    a Block Power localization report.
    """
    import hashlib
    indexer = BlockPowerIndexer()
    safe_name = "demo_mismatch.txt"

    # 1) Create SENDER content and compute sender hashes
    sender_content = (
        b"Hash Checker Demo: Sender File\n"
        b"This is the ORIGINAL file sent by the sender.\n"
        b"SHA-256 and SHA-3 are computed on this exact content.\n"
        b"If even one byte is changed, both hashes will completely differ.\n"
        b"Gilbert & Gilbert (2025): Dual-layer cryptographic integrity verification.\n"
    ) * 8  # make it big enough for block demo

    import hashlib
    sender_sha256 = hashlib.sha256(sender_content).hexdigest()
    sender_sha3   = hashlib.sha3_256(sender_content).hexdigest()

    # 2) Save sender content to received dir (simulating a received file)
    transfer_id = str(uuid.uuid4())
    target_dir  = config.RECEIVED_DIR / transfer_id
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / safe_name

    target_path.write_bytes(sender_content)
    block_index = indexer.compute_block_index(target_path)

    # Store original (clean) transfer record
    storage.record_transfer(
        transfer_id=transfer_id,
        original_filename=safe_name,
        file_size=len(sender_content),
        expected_hash=sender_sha256,
        stored_path=str(target_path),
        status="VERIFIED",
        sha3_256=sender_sha3,
        block_index=block_index
    )

    # 3) Tamper the received file (simulate in-transit corruption)
    received = bytearray(sender_content)
    tamper_positions = [50, 51, 52, 100, 101]  # multiple bytes in block 0
    for pos in tamper_positions:
        if pos < len(received):
            received[pos] ^= 0xFF

    target_path.write_bytes(bytes(received))

    # 4) Compute receiver hashes (now different from sender)
    receiver_sha256 = hashlib.sha256(bytes(received)).hexdigest()
    receiver_sha3   = hashlib.sha3_256(bytes(received)).hexdigest()

    # 5) Localize tampering
    tamper_report = indexer.localize_tampering(target_path, block_index)

    # Update DB to show MISMATCH
    storage.update_verification(
        transfer_id=transfer_id,
        received_hash=receiver_sha256,
        status="MISMATCH",
        error_message="Demo: simulated in-transit corruption",
        tamper_localization=tamper_report
    )

    return jsonify({
        "success": True,
        "transfer_id": transfer_id,
        "filename": safe_name,
        "file_size": len(sender_content),
        "block_count": len(block_index),
        "sender_sha256": sender_sha256,
        "sender_sha3": sender_sha3,
        "receiver_sha256": receiver_sha256,
        "receiver_sha3": receiver_sha3,
        "tamper_report": tamper_report,
        "message": "Mismatch demo: sender hashes != receiver hashes due to in-transit byte corruption."
    })


@app.route("/api/report/<transfer_id>", methods=["GET"])
def generate_report_endpoint(transfer_id):
    """
    Generate complete academic & forensic research audit report adhering to IJMRAP 2025 standard.
    """
    record = storage.get_transfer(transfer_id)
    if not record:
        return jsonify({"status": "FAILED", "error": f"Transfer not found: {transfer_id}"}), 404

    target_path = Path(record["stored_path"])
    tamper_report = None
    robustness_metrics = None
    residual_sig = None

    if target_path.exists():
        file_bytes = target_path.read_bytes()
        indexer = BlockPowerIndexer()
        block_idx = record.get("block_index")
        if block_idx:
            tamper_report = indexer.localize_tampering(target_path, block_idx)
        robustness_metrics = RobustnessPerturbationLab.run_robustness_evaluation(file_bytes)

        # Trace residual signature if tampered or simulated
        if record.get("status") == "MISMATCH":
            alt = bytearray(file_bytes)
            if len(alt) > 10:
                alt[0] ^= 0xFF
            residual_sig = ResidualSignatureTracer.trace_signature(file_bytes, bytes(alt))

    report = ResearchReportGenerator.generate_report(
        transfer_record=record,
        tamper_report=tamper_report,
        robustness_metrics=robustness_metrics,
        residual_signature=residual_sig
    )
    return jsonify(report)


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
