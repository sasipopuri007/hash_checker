"""
Receiver server for Network File Transfer.
Listens on TCP, receives metadata, saves files into UUID-isolated directories,
computes SHA-256 digests, performs automatic integrity verification,
and stores transfer history in SQLite.
Supports optional TLS encryption and sender authentication.
"""

import argparse
import logging
from pathlib import Path
import re
import socket
import ssl
import sys
import threading
from typing import Optional, Tuple

import config
from hash_utils import IncrementalHasher
import protocol
from storage import TransferStorage

# Configure logging to both console and transfer.log
config.init_directories()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.LOG_FILE, encoding="utf-8")
    ]
)
logger = logging.getLogger("Receiver")

HEX_SHA256_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")


class ReceiverServer:
    """TCP server that handles incoming file transfers."""

    def __init__(
        self,
        host: str = config.DEFAULT_HOST,
        port: int = config.DEFAULT_PORT,
        save_dir: Path = config.RECEIVED_DIR,
        storage: Optional[TransferStorage] = None,
        auth_token: Optional[str] = config.AUTH_TOKEN,
        max_file_size: int = config.MAX_FILE_SIZE,
        cert_path: Optional[Path] = None,
        key_path: Optional[Path] = None,
    ):
        self.host = host
        self.port = port
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self.storage = storage or TransferStorage()
        self.auth_token = auth_token
        self.max_file_size = max_file_size
        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._lock = threading.Lock()

        # TLS Configuration
        self.ssl_context: Optional[ssl.SSLContext] = None
        if cert_path and key_path:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
            logger.info("TLS encryption enabled for receiver.")

    def start(self, once: bool = False, max_transfers: Optional[int] = None) -> None:
        """Start listening for incoming TCP transfers."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        # Obtain actual port if bound to 0
        self.port = self._server_sock.getsockname()[1]
        self._server_sock.listen(5)
        self._running = True
        tls_status = "TLS active" if self.ssl_context else "plaintext TCP"
        logger.info(f"Receiver listening on {self.host}:{self.port} [{tls_status}] (Saving to: {self.save_dir})")

        transfers_count = 0
        try:
            while self._running:
                try:
                    self._server_sock.settimeout(1.0)
                    raw_client_sock, client_addr = self._server_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                logger.info(f"Accepted connection from {client_addr[0]}:{client_addr[1]}")
                client_sock = raw_client_sock
                try:
                    if self.ssl_context:
                        client_sock = self.ssl_context.wrap_socket(raw_client_sock, server_side=True)

                    self.handle_connection(client_sock, client_addr)
                    transfers_count += 1
                except ssl.SSLError as e:
                    logger.error(f"TLS handshake failure with {client_addr}: {e}")
                finally:
                    try:
                        client_sock.close()
                    except OSError:
                        pass

                if once or (max_transfers and transfers_count >= max_transfers):
                    logger.info("Transfer limit reached; shutting down server loop.")
                    break
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop listening and close socket."""
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        logger.info("Receiver server stopped.")

    def handle_connection(self, sock: socket.socket, addr: Tuple[str, int]) -> None:
        """Handle a single client connection for file transfer."""
        sock.settimeout(60.0)
        transfer_id = "unknown"
        safe_filename = "unknown"
        target_path = None
        part_path = None

        try:
            # Step 1: Read and validate metadata
            meta = protocol.recv_metadata(sock)
            logger.info(f"Received metadata from {addr}: {meta}")

            transfer_id = str(meta.get("transfer_id", "")).strip()
            raw_filename = meta.get("original_filename", "")
            file_size = meta.get("file_size")
            expected_hash = str(meta.get("sha256", "")).strip().lower()
            client_token = meta.get("auth_token")

            # Validate authentication
            if self.auth_token and client_token != self.auth_token:
                err_msg = "Authentication failed: invalid or missing auth token."
                logger.warning(f"Rejecting transfer from {addr}: {err_msg}")
                protocol.send_response(sock, {
                    "status": "FAILED",
                    "transfer_id": transfer_id,
                    "error": err_msg
                })
                return

            # Validate metadata structure
            if not transfer_id:
                raise protocol.ProtocolError("Missing required 'transfer_id' in metadata.")
            if not HEX_SHA256_REGEX.match(expected_hash):
                raise protocol.ProtocolError(f"Invalid SHA-256 hash format: '{expected_hash}'")
            if not isinstance(file_size, int) or file_size < 0:
                raise protocol.ProtocolError(f"Invalid file size: {file_size}")
            if file_size > self.max_file_size:
                raise protocol.ProtocolError(
                    f"File size {file_size} exceeds allowed limit of {self.max_file_size} bytes."
                )

            # Sanitize filename (prevents directory traversal e.g. ../ or /etc/)
            safe_filename = protocol.sanitize_filename(raw_filename)

            # Step 2: Ensure UUID isolation directory
            # Each transfer is saved in received/<uuid>/<safe_filename>
            transfer_dir = self.save_dir / transfer_id
            transfer_dir.mkdir(parents=True, exist_ok=True)
            target_path = transfer_dir / safe_filename
            part_path = transfer_dir / f"{safe_filename}.part"

            # Step 3: Record initial state in SQLite as INCOMPLETE
            self.storage.record_transfer(
                transfer_id=transfer_id,
                original_filename=safe_filename,
                file_size=file_size,
                expected_hash=expected_hash,
                stored_path=str(target_path),
                status="INCOMPLETE"
            )

            # Step 4: Stream file bytes to disk and calculate incremental hash
            hasher = IncrementalHasher()
            bytes_received = 0

            with open(part_path, "wb") as f:
                while bytes_received < file_size:
                    to_read = min(file_size - bytes_received, config.BUFFER_SIZE)
                    chunk = sock.recv(to_read)
                    if not chunk:
                        raise protocol.IncompleteReadError(
                            expected=file_size, received=bytes_received
                        )
                    f.write(chunk)
                    hasher.update(chunk)
                    bytes_received += len(chunk)

            # Step 5: Finalize file and compute receiver hash
            if part_path.exists():
                if target_path.exists():
                    target_path.unlink()
                part_path.rename(target_path)

            received_hash = hasher.hexdigest().lower()

            # Step 6: Automatic verification
            if received_hash == expected_hash:
                status = "VERIFIED"
                msg = f"Transfer verified successfully (SHA-256 matches: {received_hash})"
                logger.info(f"Transfer [{transfer_id}] {safe_filename}: VERIFIED")
            else:
                status = "MISMATCH"
                msg = f"Integrity MISMATCH: expected {expected_hash}, received {received_hash}"
                logger.error(f"Transfer [{transfer_id}] {safe_filename}: {msg}")

            # Record in SQLite
            self.storage.update_verification(
                transfer_id=transfer_id,
                received_hash=received_hash,
                status=status,
                error_message=None if status == "VERIFIED" else msg
            )

            # Step 7: Send response ack to sender
            protocol.send_response(sock, {
                "status": status,
                "transfer_id": transfer_id,
                "received_hash": received_hash,
                "expected_hash": expected_hash,
                "message": msg
            })

        except protocol.IncompleteReadError as e:
            err_msg = f"Incomplete transfer: {e}"
            logger.error(f"Transfer [{transfer_id}] interrupted: {err_msg}")
            if part_path and part_path.exists():
                incomplete_path = part_path.with_suffix(".incomplete")
                if incomplete_path.exists():
                    incomplete_path.unlink()
                part_path.rename(incomplete_path)
            self.storage.update_verification(
                transfer_id=transfer_id,
                received_hash=None,
                status="FAILED",
                error_message=err_msg
            )
            try:
                protocol.send_response(sock, {
                    "status": "FAILED",
                    "transfer_id": transfer_id,
                    "error": err_msg
                })
            except Exception:
                pass

        except Exception as e:
            err_msg = f"Transfer error: {e}"
            logger.exception(f"Error handling transfer [{transfer_id}]: {err_msg}")
            if part_path and part_path.exists():
                try:
                    part_path.unlink()
                except OSError:
                    pass
            self.storage.update_verification(
                transfer_id=transfer_id,
                received_hash=None,
                status="FAILED",
                error_message=err_msg
            )
            try:
                protocol.send_response(sock, {
                    "status": "FAILED",
                    "transfer_id": transfer_id,
                    "error": str(e)
                })
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="Network File Transfer Receiver Server")
    parser.add_argument("--host", default=config.DEFAULT_HOST, help=f"Host interface to bind (default: {config.DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT, help=f"Port to listen on (default: {config.DEFAULT_PORT})")
    parser.add_argument("--save-dir", type=Path, default=config.RECEIVED_DIR, help=f"Destination directory for received files (default: {config.RECEIVED_DIR})")
    parser.add_argument("--token", default=config.AUTH_TOKEN, help="Shared authentication token")
    parser.add_argument("--once", action="store_true", help="Stop after receiving one transfer")
    parser.add_argument("--tls", action="store_true", help="Enable TLS encryption")
    parser.add_argument("--cert", type=Path, default=config.DATA_DIR / "server.crt", help="Path to TLS certificate file")
    parser.add_argument("--key", type=Path, default=config.DATA_DIR / "server.key", help="Path to TLS private key file")
    args = parser.parse_args()

    cert_path = args.cert if args.tls else None
    key_path = args.key if args.tls else None

    server = ReceiverServer(
        host=args.host,
        port=args.port,
        save_dir=args.save_dir,
        auth_token=args.token,
        cert_path=cert_path,
        key_path=key_path
    )

    try:
        server.start(once=args.once)
    except KeyboardInterrupt:
        logger.info("Receiver interrupted by user. Stopping...")
        server.stop()


if __name__ == "__main__":
    main()
