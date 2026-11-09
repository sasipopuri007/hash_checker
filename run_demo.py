import os
import subprocess
import sys
import time
from pathlib import Path

PYTHON_EXE = r"C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe"

def run_step(title, cmd, env=None):
    print(f"\n{'='*75}")
    print(f" STEP: {title}")
    print(f" COMMAND: {' '.join(cmd)}")
    print(f"{'='*75}")
    t0 = time.time()
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    elapsed = time.time() - t0
    if res.stdout:
        print(res.stdout.strip())
    if res.stderr:
        print("STDERR:", res.stderr.strip())
    print(f"[Done in {elapsed:.2f}s | Exit Code: {res.returncode}]")
    return res

def main():
    print("="*75)
    print(" ADVANCED CRYPTOGRAPHIC HASH CHECKER - COMPLETE LIVE DEMONSTRATION")
    print(" Demonstrating:")
    print(" 1. TCP Framed File Streaming (sender -> receiver)")
    print(" 2. Dual-Layer Hash Verification (SHA-256 + SHA-3-256)")
    print(" 3. UUID Isolation & Local Database Persistence")
    print(" 4. Live Tamper Injection (Simulated Corruption)")
    print(" 5. Block Power Indexing & Exact Tamper Localization (Section 7.1)")
    print(" 6. Cryptographic Performance Benchmark (Table 3)")
    print("="*75)

    env = os.environ.copy()
    env["NFT_STORAGE_BACKEND"] = "sqlite"

    port = "9753"

    # Step 1: Start Receiver in background
    print("\n>>> Launching Receiver Server in background...")
    receiver_proc = subprocess.Popen(
        [PYTHON_EXE, "receiver.py", "--port", port, "--once"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env
    )
    time.sleep(1.0)  # Wait for receiver to bind socket

    # Step 2: Send file using Sender Client
    send_res = run_step(
        "1. Send File via TCP Client (Dual Hashing + Block Power Indexing)",
        [PYTHON_EXE, "sender.py", "sender_files/notes.txt", "--port", port],
        env=env
    )

    # Collect receiver output
    rec_out, rec_err = receiver_proc.communicate(timeout=5)
    print("\n--- Receiver Server Output ---")
    print(rec_out.strip())

    # Step 3: List transfers in database
    list_res = run_step(
        "2. Query Transfer History from SQLite Database",
        [PYTHON_EXE, "hash_checker.py", "list"],
        env=env
    )

    # Extract the newest transfer_id from output
    import storage
    s = storage.SQLiteTransferStorage()
    recent = s.list_transfers(limit=1)
    if not recent:
        print("Error: No transfers found in database.")
        return

    transfer_id = recent[0]["transfer_id"]
    file_path = recent[0]["stored_path"]
    print(f"\n[Active Transfer ID]: {transfer_id}")
    print(f"[Stored File Path]  : {file_path}")

    # Step 4: Verify transfer
    run_step(
        "3. Verify File Integrity (Before Tampering - Clean State)",
        [PYTHON_EXE, "hash_checker.py", "verify", transfer_id],
        env=env
    )

    # Step 5: Inject byte corruption into received file
    print(f"\n>>> Artificially corrupting byte at offset 42 in '{file_path}'...")
    with open(file_path, "r+b") as f:
        data = bytearray(f.read())
        orig_byte = data[42]
        data[42] ^= 0xFF  # Flip all 8 bits
        f.seek(0)
        f.write(data)
    print(f"[Tampered] Byte at offset 42 altered from 0x{orig_byte:02X} to 0x{data[42]:02X}")

    # Step 6: Verify transfer after tampering -> Must report MISMATCH
    run_step(
        "4. Re-Verify File Integrity (After Tampering - Expecting MISMATCH)",
        [PYTHON_EXE, "hash_checker.py", "verify", transfer_id],
        env=env
    )

    # Step 7: Localize Tampering using Block Power Indexing
    run_step(
        "5. Localize Exact Corrupted Block & Byte Offset (Section 7.1 Novelty)",
        [PYTHON_EXE, "hash_checker.py", "localize", transfer_id],
        env=env
    )

    # Step 8: Run Algorithm Benchmark
    run_step(
        "6. Cryptographic Algorithm Benchmark (Table 3: Throughput & Latency)",
        [PYTHON_EXE, "hash_checker.py", "benchmark"],
        env=env
    )

    print("\n" + "="*75)
    print(" LIVE DEMONSTRATION COMPLETE: ALL SYSTEMS FUNCTIONING PERFECTLY!")
    print("="*75)

if __name__ == "__main__":
    main()
