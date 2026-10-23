"""
Hashing utilities for secure integrity verification.
Supports single-algorithm (SHA-256, SHA-3, SHA-512) and dual-layer hashing (SHA-256 + SHA-3-256)
in streaming chunks to prevent memory exhaustion on large files.
"""

import hashlib
from pathlib import Path
from typing import BinaryIO, Union, Dict
import config


def calculate_hash(
    source: Union[str, Path, BinaryIO],
    algorithm: str = "sha256",
    chunk_size: int = config.BUFFER_SIZE
) -> str:
    """
    Calculate the cryptographic hex digest of a file or binary stream in chunks.
    
    Args:
        source: Path to the file or an open binary stream.
        algorithm: Hashing algorithm ('sha256', 'sha3_256', 'sha512', etc.).
        chunk_size: Size of chunks to read into memory at a time.
        
    Returns:
        Hexadecimal hash digest string.
    """
    hasher = getattr(hashlib, algorithm.lower())()

    if isinstance(source, (str, Path)):
        file_path = Path(source)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
    else:
        while chunk := source.read(chunk_size):
            hasher.update(chunk)

    return hasher.hexdigest()


def calculate_sha256(
    source: Union[str, Path, BinaryIO],
    chunk_size: int = config.BUFFER_SIZE
) -> str:
    """Convenience wrapper for standard SHA-256 calculation."""
    return calculate_hash(source, algorithm="sha256", chunk_size=chunk_size)


def calculate_dual_hash(
    source: Union[str, Path, BinaryIO],
    chunk_size: int = config.BUFFER_SIZE
) -> Dict[str, str]:
    """
    Calculate both SHA-256 (Merkle-Damgård) and SHA-3-256 (Keccak Sponge) in a single pass.
    """
    h_sha256 = hashlib.sha256()
    h_sha3 = hashlib.sha3_256()

    if isinstance(source, (str, Path)):
        file_path = Path(source)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                h_sha256.update(chunk)
                h_sha3.update(chunk)
    else:
        while chunk := source.read(chunk_size):
            h_sha256.update(chunk)
            h_sha3.update(chunk)

    return {
        "sha256": h_sha256.hexdigest(),
        "sha3_256": h_sha3.hexdigest()
    }


class IncrementalHasher:
    """Incremental SHA-256 hasher for calculating digests while streaming data."""

    def __init__(self, algorithm: str = "sha256"):
        self.algorithm = algorithm.lower()
        self._hasher = getattr(hashlib, self.algorithm)()
        self._bytes_processed = 0

    def update(self, data: bytes) -> None:
        """Add bytes to the incremental hash computation."""
        self._hasher.update(data)
        self._bytes_processed += len(data)

    @property
    def bytes_processed(self) -> int:
        """Total number of bytes processed so far."""
        return self._bytes_processed

    def hexdigest(self) -> str:
        """Return the current hex digest."""
        return self._hasher.hexdigest()


class DualIncrementalHasher:
    """
    Incremental hasher for both SHA-256 and SHA-3-256 simultaneously during streaming.
    """

    def __init__(self):
        self._sha256 = hashlib.sha256()
        self._sha3 = hashlib.sha3_256()
        self._bytes_processed = 0

    def update(self, data: bytes) -> None:
        self._sha256.update(data)
        self._sha3.update(data)
        self._bytes_processed += len(data)

    @property
    def bytes_processed(self) -> int:
        return self._bytes_processed

    def digests(self) -> Dict[str, str]:
        return {
            "sha256": self._sha256.hexdigest(),
            "sha3_256": self._sha3.hexdigest(),
            "bytes_processed": self._bytes_processed
        }
