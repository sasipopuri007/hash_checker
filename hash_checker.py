"""
Hash Checker module and CLI utility.
Supports automatic verification checks after transfer and manual re-checking later.
Provides verification by transfer ID, standalone file checking against expected hash,
transfer history querying, and audit verification of all stored files.
"""

import argparse
from pathlib import Path
import sys
from typing import Dict, Any, Optional

import config
from hash_utils import calculate_sha256
from storage import TransferStorage

config.init_directories()


def verify_transfer(transfer_id: str, storage: Optional[TransferStorage] = None) -> Dict[str, Any]:
    """
    Manually re-verify a transfer by recalculating the SHA-256 digest of the stored file
    and comparing it against the expected sender hash recorded in SQLite.
    
    Returns:
        Dictionary with status ('VERIFIED', 'MISMATCH', 'FAILED') and details.
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

    if not stored_path.exists():
        err_msg = f"Stored file does not exist on disk: {stored_path}"
        storage.update_verification(transfer_id, None, "FAILED", error_message=err_msg)
        return {
            "status": "FAILED",
            "transfer_id": transfer_id,
            "filename": record["original_filename"],
            "error": err_msg
        }

    # Recalculate SHA-256 of stored file in chunks
    calculated_hash = calculate_sha256(stored_path)

    if calculated_hash.lower() == expected_hash.lower():
        status = "VERIFIED"
        msg = "Hash verified: contents match expected sender digest."
        storage.update_verification(transfer_id, calculated_hash, status, error_message=None)
    else:
        status = "MISMATCH"
        msg = f"Hash MISMATCH: expected {expected_hash}, calculated {calculated_hash}"
        storage.update_verification(transfer_id, calculated_hash, status, error_message=msg)

    return {
        "status": status,
        "transfer_id": transfer_id,
        "filename": record["original_filename"],
        "stored_path": str(stored_path),
        "expected_hash": expected_hash,
        "calculated_hash": calculated_hash,
        "message": msg
    }


def check_file(file_path: Path, expected_hash: str) -> Dict[str, Any]:
    """
    Manually calculate the SHA-256 hash of any file and compare against an expected hash.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        return {
            "status": "FAILED",
            "error": f"File does not exist: {path}"
        }

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
        print(f" {k:<18}: {v}")
    print(f"{'='*75}\n")


def cmd_verify(args):
    result = verify_transfer(args.transfer_id)
    print_card(f"VERIFICATION RESULT: {result.get('status')}", result)
    if result.get("status") != "VERIFIED":
        sys.exit(1)


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
    parser = argparse.ArgumentParser(description="SHA-256 Hash Checker and Transfer Audit Utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # verify <transfer_id>
    p_verify = subparsers.add_parser("verify", help="Re-verify a received transfer using its UUID")
    p_verify.add_argument("transfer_id", help="Transfer UUID")
    p_verify.set_defaults(func=cmd_verify)

    # check-file <path> <expected_hash>
    p_check = subparsers.add_parser("check-file", help="Calculate SHA-256 of any file and compare with expected hash")
    p_check.add_argument("path", type=Path, help="Path to local file")
    p_check.add_argument("expected_hash", help="Expected 64-char hex SHA-256 hash")
    p_check.set_defaults(func=cmd_check_file)

    # list [--status]
    p_list = subparsers.add_parser("list", help="List transfer history from SQLite database")
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
