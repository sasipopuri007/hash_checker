"""
Hashing utilities for SHA-256 calculation.
Calculates SHA-256 digests in chunks so large files do not need to be loaded entirely into memory.
"""

import hashlib
from pathlib import Path
from typing import BinaryIO, Union
import config

def calculate_sha256(
    source: Union[str, Path, BinaryIO],
    chunk_size: int = config.BUFFER_SIZE
) -> str:
    """
    Calculate the SHA-256 hex digest of a file or binary stream in chunks.
    
    Args:
        source: Path to the file or an open binary stream.
        chunk_size: Size of chunks to read into memory at a time.
        
    Returns:
        64-character lowercase hexadecimal SHA-256 digest.
    """
    hasher = hashlib.sha256()

    if isinstance(source, (str, Path)):
        file_path = Path(source)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
    else:
        # Assuming binary stream
        while chunk := source.read(chunk_size):
            hasher.update(chunk)

    return hasher.hexdigest()


class IncrementalHasher:
    """
    Incremental SHA-256 hasher for calculating digests while streaming data.
    """

    def __init__(self):
        self._hasher = hashlib.sha256()
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
        """Return the current SHA-256 hex digest."""
        return self._hasher.hexdigest()
