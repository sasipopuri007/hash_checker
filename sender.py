"""
Sender client for Network File Transfer.
Calculates SHA-256 digests in chunks, generates unique transfer IDs (UUIDs),
sends length-prefixed metadata and binary payload over TCP,
and displays transfer progress and verification feedback.
Supports optional TLS encryption and sender authentication.
"""

import argparse
import logging
from pathlib import Path
import socket
import ssl
import sys
import time
import uuid
from typing import Dict, Any, Optional, Sequence

import config
from hash_utils import calculate_sha256
import protocol

config.init_directories()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.LOG_FILE, encoding="utf-8")
    ]
)
logger = logging.getLogger("Sender")


def render_progress_bar(transferred: int, total: int, width: int = 30) -> str:
    """Render a text progress bar."""
    if total <= 0:
        return "[==============================] 100% (0 B / 0 B)"
    percent = min(1.0, transferred / total)
    filled = int(width * percent)
    bar = "=" * filled + "-" * (width - filled)
    return f"[{bar}] {percent*100:5.1f}% ({transferred:,} / {total:,} bytes)"


def send_file(
    filepath: Path,
    host: str = config.DEFAULT_HOST,
    port: int = config.DEFAULT_PORT,
    auth_token: Optional[str] = config.AUTH_TOKEN,
    transfer_id: Optional[str] = None,
    chunk_size: int = config.BUFFER_SIZE,
    quiet: bool = False,
    use_tls: bool = False,
    ca_cert: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Send a single file over TCP with metadata and SHA-256 digest.
    
    Args:
        filepath: Local file path to send.
        host: Target receiver host.
        port: Target receiver port.
        auth_token: Optional authentication token.
        transfer_id: Optional UUID (generates a new UUID v4 if omitted).
        chunk_size: Chunk size in bytes for streaming.
        quiet: If True, suppress progress prints.
        use_tls: If True, wrap socket in TLS.
        ca_cert: Optional CA cert to verify server.
        
    Returns:
        Dictionary containing transfer summary and verification result.
    """
    path = Path(filepath).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"File to send does not exist: {path}")

    file_size = path.stat().st_size
    filename = path.name
    transfer_id = transfer_id or str(uuid.uuid4())

    if not quiet:
        mode = "TLS Encrypted" if use_tls else "Plaintext TCP"
        print(f"\n{'='*70}")
        print(f"Preparing to send: {filename} [{mode}]")
        print(f"Transfer ID:       {transfer_id}")
        print(f"File size:         {file_size:,} bytes")
        print(f"Target:            {host}:{port}")

    # Compute Dual SHA-256 and SHA-3-256 hashes & Block Power Index
    from hash_utils import calculate_dual_hash
    from advanced_hash import BlockPowerIndexer

    start_hash_time = time.time()
    dual = calculate_dual_hash(path, chunk_size=chunk_size)
    file_hash = dual["sha256"]
    sha3_hash = dual["sha3_256"]
    indexer = BlockPowerIndexer()
    block_index = indexer.compute_block_index(path)
    hash_duration = time.time() - start_hash_time

    if not quiet:
        print(f"Sender SHA-256:    {file_hash} (computed in {hash_duration:.3f}s)")
        print(f"Sender SHA-3-256:  {sha3_hash} [Keccak Permutation Sponge]")
        print(f"Block Power Index: {len(block_index)} blocks indexed for tamper localization")
        print(f"{'-'*70}")

    metadata = {
        "transfer_id": transfer_id,
        "original_filename": filename,
        "file_size": file_size,
        "sha256": file_hash,
        "sha3_256": sha3_hash,
        "block_index": block_index,
        "auth_token": auth_token
    }

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(60.0)

    try:
        raw_sock.connect((host, port))
        sock = raw_sock

        if use_tls:
            if ca_cert and Path(ca_cert).exists():
                ssl_context = ssl.create_default_context(cafile=str(ca_cert))
            else:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            sock = ssl_context.wrap_socket(raw_sock, server_hostname=host)

        logger.info(f"Connected to {host}:{port}. Sending metadata for {filename} [{transfer_id}]")

        # Send length-prefixed metadata
        protocol.send_metadata(sock, metadata)

        # Stream file bytes
        bytes_sent = 0
        start_send_time = time.time()

        with open(path, "rb") as f:
            while bytes_sent < file_size:
                to_read = min(file_size - bytes_sent, chunk_size)
                chunk = f.read(to_read)
                if not chunk:
                    break
                sock.sendall(chunk)
                bytes_sent += len(chunk)

                if not quiet and sys.stdout.isatty():
                    bar = render_progress_bar(bytes_sent, file_size)
                    sys.stdout.write(f"\rSending: {bar}")
                    sys.stdout.flush()

        if not quiet and sys.stdout.isatty():
            sys.stdout.write("\n")

        send_duration = max(time.time() - start_send_time, 0.0001)
        speed_kbps = (bytes_sent / 1024) / send_duration
        if not quiet:
            print(f"Stream complete: {bytes_sent:,} bytes transferred in {send_duration:.3f}s ({speed_kbps:.1f} KB/s)")
            print("Awaiting receiver integrity verification...")

        # Receive acknowledgment from receiver
        response = protocol.recv_response(sock)
        status = response.get("status", "UNKNOWN")
        received_hash = response.get("received_hash")
        msg = response.get("message") or response.get("error", "")

        result = {
            "transfer_id": transfer_id,
            "filename": filename,
            "file_size": file_size,
            "sender_hash": file_hash,
            "received_hash": received_hash,
            "status": status,
            "message": msg,
            "duration_sec": send_duration
        }

        if not quiet:
            print(f"{'-'*70}")
            print(f"Receiver Status:   {status}")
            print(f"Receiver SHA-256:  {received_hash}")
            print(f"Details:           {msg}")
            print(f"{'='*70}\n")

        logger.info(f"Transfer [{transfer_id}] result: {status} - {msg}")
        return result

    finally:
        raw_sock.close()


def send_files(
    file_paths: Sequence[Path],
    host: str = config.DEFAULT_HOST,
    port: int = config.DEFAULT_PORT,
    auth_token: Optional[str] = config.AUTH_TOKEN,
    chunk_size: int = config.BUFFER_SIZE,
    quiet: bool = False,
    use_tls: bool = False,
    ca_cert: Optional[Path] = None
) -> Sequence[Dict[str, Any]]:
    """Send multiple files sequentially, generating a distinct UUID for each."""
    results = []
    for fp in file_paths:
        res = send_file(
            filepath=fp,
            host=host,
            port=port,
            auth_token=auth_token,
            chunk_size=chunk_size,
            quiet=quiet,
            use_tls=use_tls,
            ca_cert=ca_cert
        )
        results.append(res)
    return results


def main():
    parser = argparse.ArgumentParser(description="Network File Transfer Sender Client")
    parser.add_argument("files", nargs="+", type=Path, help="One or more files to send")
    parser.add_argument("--host", default=config.DEFAULT_HOST, help=f"Target receiver host (default: {config.DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT, help=f"Target receiver port (default: {config.DEFAULT_PORT})")
    parser.add_argument("--token", default=config.AUTH_TOKEN, help="Authentication token")
    parser.add_argument("--tls", action="store_true", help="Enable TLS encrypted transfer")
    parser.add_argument("--ca-cert", type=Path, default=None, help="Optional CA certificate to verify server")
    parser.add_argument("--quiet", action="store_true", help="Quiet mode (no progress output)")
    args = parser.parse_args()

    results = send_files(
        file_paths=args.files,
        host=args.host,
        port=args.port,
        auth_token=args.token,
        quiet=args.quiet,
        use_tls=args.tls,
        ca_cert=args.ca_cert
    )

    all_verified = all(r.get("status") == "VERIFIED" for r in results)
    sys.exit(0 if all_verified else 1)


if __name__ == "__main__":
    main()
