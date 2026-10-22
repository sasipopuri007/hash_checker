"""
Protocol definition and message framing for network file transfer.
Handles length-prefixed metadata serialization, safe exact TCP stream reads,
and acknowledgment responses.
"""

import json
import socket
import struct
from pathlib import Path
from typing import Dict, Any

import config

HEADER_STRUCT = struct.Struct("!I")  # 4-byte big-endian unsigned integer
HEADER_SIZE = HEADER_STRUCT.size


class ProtocolError(Exception):
    """Raised when incoming data violates protocol framing or specification."""
    pass


class IncompleteReadError(ProtocolError):
    """Raised when socket closes prematurely before expected bytes are read."""
    def __init__(self, expected: int, received: int):
        super().__init__(f"Premature EOF: expected {expected} bytes, but received only {received} bytes")
        self.expected = expected
        self.received = received


class AuthenticationError(ProtocolError):
    """Raised when client fails authentication."""
    pass


def sanitize_filename(filename: str) -> str:
    """
    Sanitize an incoming filename to prevent path traversal and unsafe characters.
    Extracts only the basename, rejecting paths like '../../secret.txt' or absolute paths.
    """
    if not filename or not isinstance(filename, str):
        raise ProtocolError("Filename must be a non-empty string.")

    # Remove null bytes
    clean = filename.replace("\x00", "").strip()
    
    # Extract only the file name portion using PurePath/Path
    base = Path(clean).name
    
    if not base or base in (".", ".."):
        raise ProtocolError(f"Invalid or unsafe filename: {filename!r}")

    return base


def recv_exact(sock: socket.socket, num_bytes: int, buffer_size: int = config.BUFFER_SIZE) -> bytes:
    """
    Read exactly num_bytes from a socket.
    
    TCP streams may fragment data across multiple reads. This helper loops until
    all requested bytes are received, or raises IncompleteReadError if the connection
    closes prematurely.
    """
    if num_bytes < 0:
        raise ValueError(f"Requested bytes must be non-negative, got {num_bytes}")
    if num_bytes == 0:
        return b""

    chunks = []
    received = 0
    while received < num_bytes:
        to_read = min(num_bytes - received, buffer_size)
        try:
            data = sock.recv(to_read)
        except OSError as e:
            raise ProtocolError(f"Socket error during read: {e}") from e

        if not data:
            raise IncompleteReadError(expected=num_bytes, received=received)

        chunks.append(data)
        received += len(data)

    return b"".join(chunks)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """Send length-prefixed binary frame (4-byte length + payload)."""
    header = HEADER_STRUCT.pack(len(payload))
    sock.sendall(header + payload)


def recv_frame(sock: socket.socket, max_size: int = config.MAX_METADATA_SIZE) -> bytes:
    """Receive length-prefixed binary frame."""
    header_bytes = recv_exact(sock, HEADER_SIZE)
    (length,) = HEADER_STRUCT.unpack(header_bytes)

    if length > max_size:
        raise ProtocolError(f"Frame length {length} exceeds maximum allowed size ({max_size} bytes)")
    if length < 0:
        raise ProtocolError(f"Invalid frame length: {length}")

    return recv_exact(sock, length)


def send_metadata(sock: socket.socket, metadata: Dict[str, Any]) -> None:
    """Serialize and send metadata JSON dictionary."""
    try:
        payload = json.dumps(metadata).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise ProtocolError(f"Failed to serialize metadata to JSON: {e}") from e

    send_frame(sock, payload)


def recv_metadata(sock: socket.socket, max_size: int = config.MAX_METADATA_SIZE) -> Dict[str, Any]:
    """Receive and deserialize length-prefixed metadata JSON dictionary."""
    payload = recv_frame(sock, max_size=max_size)
    try:
        metadata = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ProtocolError(f"Failed to parse metadata JSON: {e}") from e

    if not isinstance(metadata, dict):
        raise ProtocolError(f"Expected metadata dictionary, got {type(metadata).__name__}")

    return metadata


def send_response(sock: socket.socket, response: Dict[str, Any]) -> None:
    """Send acknowledgment/status response dictionary to peer."""
    send_metadata(sock, response)


def recv_response(sock: socket.socket, max_size: int = config.MAX_METADATA_SIZE) -> Dict[str, Any]:
    """Receive acknowledgment/status response dictionary from peer."""
    return recv_metadata(sock, max_size=max_size)
