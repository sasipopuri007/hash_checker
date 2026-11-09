"""
Simple, easy-to-understand status checker for received files.
Works on all Windows consoles without encoding errors.
Usage:
    python check_status.py
"""

import os
from pathlib import Path
import config
from storage import TransferStorage
from hash_utils import calculate_dual_hash

def main():
    storage = TransferStorage(backend="sqlite")
    transfers = storage.list_transfers(limit=5)

    if not transfers:
        print("\n[!] No transfers found yet. Run sender.py or run_demo.py first.")
        return

    print("\n" + "=" * 65)
    print("         EASY FILE INTEGRITY STATUS CHECKER")
    print("=" * 65)

    for idx, t in enumerate(transfers, start=1):
        filename = t.get("original_filename", "unknown")
        stored_path = Path(t.get("stored_path", ""))
        expected_hash = t.get("expected_hash")
        
        print(f"\n[{idx}] File: {filename}")
        print(f"    Transfer ID: {t['transfer_id']}")
        
        if not stored_path.exists():
            print("    STATUS : [?] MISSING FILE")
            print("    MEANING: The file was deleted or moved from disk.")
            continue

        dual = calculate_dual_hash(stored_path)
        current_hash = dual["sha256"]

        if current_hash == expected_hash:
            print("    RESULT : [ PASS - 100% CORRECT ]")
            print("    MEANING: Safe! The receiver got the EXACT file.")
            print("             Not even 1 letter, number, or bit was changed.")
        else:
            print("    RESULT : [ FAIL - MISMATCH DETECTED! ]")
            print("    MEANING: DANGER! The file DOES NOT match the original!")
            print("             The file was altered, damaged, or hacked.")

    print("\n" + "=" * 65)
    print(" QUICK GUIDE:")
    print("  [ PASS ] = 100% Genuine. The receiver got the exact file.")
    print("  [ FAIL ] = MISMATCH. The file was changed or broken.")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
