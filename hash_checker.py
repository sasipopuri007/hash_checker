"""
Hash Checker module and CLI utility.
Extended with capabilities from:
'Exploring Secure Hashing Algorithms for Data Integrity Verification' (Gilbert & Gilbert, 2025).

Features:
- Dual SHA-256 + SHA-3-256 integrity verification
- Fine-Grained Tamper Localization via Block Power Indexing (Section 7.1, RQ v)
- Avalanche Effect Bit Diffusion Analyzer (Section II & IV)
- Multi-Algorithm Cryptographic Performance Benchmark (Table 3, Section IX)
- Full-disk database audit utility
"""

import argparse
from pathlib import Path
import sys
from typing import Dict, Any, Optional

from advanced_hash import BlockPowerIndexer, AvalancheAnalyzer, AlgorithmBenchmark
import config
from hash_utils import calculate_sha256, calculate_dual_hash
from storage import TransferStorage

config.init_directories()


def verify_transfer(transfer_id: str, storage: Optional[TransferStorage] = None) -> Dict[str, Any]:
    """
    Re-verify a transfer by recalculating SHA-256 and SHA-3-256 digests.
    If corruption is detected, automatically runs Block Power Indexing to pinpoint
    the exact corrupted byte offsets and blocks.
    """
    storage = storage or TransferStorage()
    record = storage.get_transfer(transfer_id)
    if not record:
        return {
            "status": "FAILED",
            "transfer_id": transfer_id,
            "error": f"Transfer record not found in database for ID: {transfer_id}"
        }

    stored_path = Path(record["stored_path"])
    expected_hash = record["expected_hash"]
    expected_sha3 = record.get("sha3_256")
    block_index = record.get("block_index")

    if not stored_path.exists():
        err_msg = f"Stored file does not exist on disk: {stored_path}"
        storage.update_verification(transfer_id, None, "FAILED", error_message=err_msg)
        return {
            "status": "FAILED",
            "transfer_id": transfer_id,
            "filename": record["original_filename"],
            "error": err_msg
        }

    # Recalculate dual hashes (SHA-256 + SHA-3-256)
    dual = calculate_dual_hash(stored_path)
    calc_sha256 = dual["sha256"].lower()
    calc_sha3 = dual["sha3_256"].lower()

    sha256_matches = (calc_sha256 == expected_hash.lower())
    sha3_matches = (not expected_sha3 or calc_sha3 == expected_sha3.lower())

    tamper_report = None

    if sha256_matches and sha3_matches:
        status = "VERIFIED"
        msg = "Dual-layer hash verified: contents match expected SHA-256 and SHA-3-256 digests."
        storage.update_verification(
            transfer_id=transfer_id,
            received_hash=calc_sha256,
            status=status,
            error_message=None,
            received_sha3=calc_sha3,
            tamper_localization=None
        )
    else:
        status = "MISMATCH"
        msg = f"Hash MISMATCH: expected {expected_hash}, calculated {calc_sha256}"
        # Block Power Indexing Tamper Localization
        if block_index:
            indexer = BlockPowerIndexer()
            tamper_report = indexer.localize_tampering(stored_path, block_index)
            msg += f" | {tamper_report.get('summary', '')}"

        storage.update_verification(
            transfer_id=transfer_id,
            received_hash=calc_sha256,
            status=status,
            error_message=msg,
            received_sha3=calc_sha3,
            tamper_localization=tamper_report
        )

    return {
        "status": status,
        "transfer_id": transfer_id,
        "filename": record["original_filename"],
        "stored_path": str(stored_path),
        "expected_hash": expected_hash,
        "calculated_hash": calc_sha256,
        "expected_sha3": expected_sha3,
        "calculated_sha3": calc_sha3,
        "tamper_localization": tamper_report,
        "message": msg
    }


def localize_tampering_cli(transfer_id: str, storage: Optional[TransferStorage] = None) -> Dict[str, Any]:
    """Isolate and pinpoint exact corrupted blocks using Block Power Indexing."""
    storage = storage or TransferStorage()
    record = storage.get_transfer(transfer_id)
    if not record:
        return {"status": "FAILED", "error": f"Record not found: {transfer_id}"}

    stored_path = Path(record["stored_path"])
    block_index = record.get("block_index")
    if not block_index:
        return {
            "status": "FAILED",
            "error": "No Block Power Index recorded for this transfer. Cannot localize at block granularity."
        }

    indexer = BlockPowerIndexer()
    return indexer.localize_tampering(stored_path, block_index)


def check_file(file_path: Path, expected_hash: str) -> Dict[str, Any]:
    """Manually calculate SHA-256 and compare against an expected hash."""
    path = Path(file_path).resolve()
    if not path.is_file():
        return {"status": "FAILED", "error": f"File does not exist: {path}"}

    calculated = calculate_sha256(path)
    clean_expected = expected_hash.strip().lower()

    if calculated.lower() == clean_expected:
        status = "VERIFIED"
        msg = "Calculated SHA-256 matches expected digest."
    else:
        status = "MISMATCH"
        msg = f"Mismatch: expected {clean_expected}, got {calculated}"

    return {
        "status": status,
        "file_path": str(path),
        "expected_hash": clean_expected,
        "calculated_hash": calculated,
        "message": msg
    }


def print_card(title: str, fields: Dict[str, Any]) -> None:
    """Print formatted key-value summary card."""
    print(f"\n{'='*75}")
    print(f" {title}")
    print(f"{'='*75}")
    for k, v in fields.items():
        if k == "tamper_localization" and isinstance(v, dict):
            print(f" {'Tamper Report':<18}: {v.get('summary')}")
        else:
            print(f" {k:<18}: {v}")
    print(f"{'='*75}\n")


def cmd_verify(args):
    result = verify_transfer(args.transfer_id)
    print_card(f"VERIFICATION RESULT: {result.get('status')}", result)
    if result.get("status") != "VERIFIED":
        sys.exit(1)


def cmd_localize(args):
    res = localize_tampering_cli(args.transfer_id)
    print(f"\n{'='*85}")
    print(f" BLOCK POWER INDEXING: TAMPER LOCALIZATION (Section 7.1, RQ v)")
    print(f"{'='*85}")
    print(f" Status:              {res.get('status')}")
    print(f" Total Blocks:        {res.get('total_blocks')}")
    print(f" Intact Blocks:       {res.get('intact_count')}")
    print(f" Corrupted Blocks:    {res.get('corrupted_count')}")
    print(f" Corruption Ratio:    {res.get('corruption_percentage')}% of file")
    print(f" Summary:             {res.get('summary')}")
    print(f"{'-'*85}")

    corrupted = res.get("corrupted_blocks", [])
    if corrupted:
        print(f"{'Block ID':<10} {'Byte Offset Range':<25} {'Reason':<25}")
        print(f"{'-'*85}")
        for c in corrupted:
            start = f"{c.get('offset_start', 0):,}"
            end = f"{c.get('offset_end', 0):,}"
            range_str = f"[{start} - {end}]"
            print(f"#{c.get('block_id'):<9} {range_str:<25} {c.get('reason'):<25}")
        print(f"{'='*85}\n")
    else:
        print(" All blocks intact. Zero tamper anomalies detected.\n")


def cmd_avalanche(args):
    path = Path(args.path)
    if path.is_file():
        data = path.read_bytes()
    else:
        data = args.path.encode("utf-8")

    res = AvalancheAnalyzer.calculate_avalanche(data, algorithm=args.algorithm.lower())
    print(f"\n{'='*75}")
    print(f" AVALANCHE EFFECT & BIT DIFFUSION ANALYSIS (Section II & IV)")
    print(f"{'='*75}")
    print(f" Algorithm:           {res['algorithm']}")
    print(f" Total Output Bits:   {res['total_digest_bits']} bits")
    print(f" Bits Flipped (1-bit):{res['flipped_bits']} bits")
    print(f" Avalanche Metric:    {res['avalanche_percentage']}% (Target: 50.0%)")
    print(f" Diffusion Score:     {res['diffusion_score']}/100")
    print(f" Evaluation:          {res['verdict']}")
    print(f"{'-'*75}")
    print(f" Original Digest:     {res['original_hex']}")
    print(f" Perturbed Digest:    {res['perturbed_hex']}")
    print(f"{'='*75}\n")


def cmd_benchmark(args):
    print(f"\nRunning Cryptographic Algorithm Benchmark (Gilbert & Gilbert Table 3)...")
    results = AlgorithmBenchmark.run_benchmark(data_size_mb=args.size_mb)
    print(f"\n{'='*95}")
    print(f"{'Algorithm':<12} {'Family':<10} {'Construction':<20} {'Speed (MB/s)':<15} {'Latency (ms)':<15} {'Status'}")
    print(f"{'-'*95}")
    for r in results:
        algo = r["algorithm"]
        fam = r["family"]
        const = r["construction"]
        speed = str(r["throughput_mb_s"])
        lat = str(r["latency_ms"])
        sec = r["security_status"]
        print(f"{algo:<12} {fam:<10} {const:<20} {speed:<15} {lat:<15} {sec}")
    print(f"{'='*95}\n")


def cmd_check_file(args):
    result = check_file(args.path, args.expected_hash)
    print_card(f"FILE CHECK RESULT: {result.get('status')}", result)
    if result.get("status") != "VERIFIED":
        sys.exit(1)


def cmd_list(args):
    storage = TransferStorage()
    records = storage.list_transfers(status=args.status, limit=args.limit)

    if not records:
        print(f"\nNo transfer records found (filter status: {args.status or 'ALL'}).\n")
        return

    print(f"\n{'='*115}")
    print(f"{'Transfer ID':<38} {'Filename':<22} {'Size (B)':<10} {'Status':<12} {'Created At'}")
    print(f"{'-'*115}")
    for r in records:
        tid = r["transfer_id"]
        fname = (r["original_filename"][:19] + "...") if len(r["original_filename"]) > 22 else r["original_filename"]
        size = str(r["file_size"])
        st = r["status"]
        created = r["created_at"][:19].replace("T", " ")
        print(f"{tid:<38} {fname:<22} {size:<10} {st:<12} {created}")
    print(f"{'='*115}\n")


def cmd_verify_all(args):
    storage = TransferStorage()
    records = storage.list_transfers(limit=args.limit)
    if not records:
        print("\nNo transfers to verify.\n")
        return

    print(f"\nAuditing {len(records)} transfers against files on disk...")
    verified_count = 0
    mismatch_count = 0
    failed_count = 0

    print(f"{'='*115}")
    print(f"{'Transfer ID':<38} {'Filename':<22} {'Expected Status':<15} {'Audit Status'}")
    print(f"{'-'*115}")

    for r in records:
        tid = r["transfer_id"]
        fname = (r["original_filename"][:19] + "...") if len(r["original_filename"]) > 22 else r["original_filename"]
        old_st = r["status"]
        res = verify_transfer(tid, storage=storage)
        new_st = res["status"]

        if new_st == "VERIFIED":
            verified_count += 1
        elif new_st == "MISMATCH":
            mismatch_count += 1
        else:
            failed_count += 1

        print(f"{tid:<38} {fname:<22} {old_st:<15} {new_st}")

    print(f"{'='*115}")
    print(f"Audit Summary: {verified_count} VERIFIED, {mismatch_count} MISMATCH, {failed_count} FAILED\n")

    if mismatch_count > 0 or failed_count > 0:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Advanced Cryptographic Integrity Verification CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # verify <transfer_id>
    p_verify = subparsers.add_parser("verify", help="Re-verify a received transfer using its UUID")
    p_verify.add_argument("transfer_id", help="Transfer UUID")
    p_verify.set_defaults(func=cmd_verify)

    # localize <transfer_id>
    p_loc = subparsers.add_parser("localize", help="Pinpoint corrupted blocks via Block Power Indexing")
    p_loc.add_argument("transfer_id", help="Transfer UUID")
    p_loc.set_defaults(func=cmd_localize)

    # avalanche <path_or_text>
    p_ava = subparsers.add_parser("avalanche", help="Analyze Avalanche Effect bit diffusion on 1-bit perturbation")
    p_ava.add_argument("path", help="File path or text string to analyze")
    p_ava.add_argument("--algorithm", default="sha256", choices=["sha256", "sha3_256", "sha512", "md5"], help="Algorithm to test")
    p_ava.set_defaults(func=cmd_avalanche)

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Benchmark SHA family throughput and security metrics")
    p_bench.add_argument("--size-mb", type=float, default=2.0, help="Test payload size in MB (default: 2.0)")
    p_bench.set_defaults(func=cmd_benchmark)

    # check-file <path> <expected_hash>
    p_check = subparsers.add_parser("check-file", help="Calculate SHA-256 of any file and compare with expected hash")
    p_check.add_argument("path", type=Path, help="Path to local file")
    p_check.add_argument("expected_hash", help="Expected 64-char hex SHA-256 hash")
    p_check.set_defaults(func=cmd_check_file)

    # list [--status]
    p_list = subparsers.add_parser("list", help="List transfer history from database")
    p_list.add_argument("--status", choices=["VERIFIED", "MISMATCH", "FAILED", "INCOMPLETE"], help="Filter by status")
    p_list.add_argument("--limit", type=int, default=50, help="Maximum number of records to display")
    p_list.set_defaults(func=cmd_list)

    # verify-all
    p_audit = subparsers.add_parser("verify-all", help="Audit and re-verify all stored files on disk")
    p_audit.add_argument("--limit", type=int, default=100, help="Max records to audit")
    p_audit.set_defaults(func=cmd_verify_all)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
