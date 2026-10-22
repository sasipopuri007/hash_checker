"""
Tests for chunked SHA-256 calculation and incremental hasher.
Tests empty files, small files, and large files.
"""

import hashlib
from pathlib import Path
import pytest

from hash_utils import calculate_sha256, IncrementalHasher

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_empty_file_hash(tmp_path: Path):
    """Empty files must produce standard empty SHA-256 digest."""
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")

    digest = calculate_sha256(empty_file)
    assert digest == EMPTY_SHA256


def test_small_file_hash(tmp_path: Path):
    """Small files must match hashlib.sha256 digest exactly."""
    content = b"Hello, Network File Transfer with SHA-256 verification!"
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()
    digest = calculate_sha256(test_file)
    assert digest == expected


def test_large_file_chunked_hash(tmp_path: Path):
    """Large files (e.g. 2 MB) chunked read must match in-memory hash."""
    test_file = tmp_path / "large.dat"
    # Create 2 MB pseudo-random/repeating pattern
    pattern = b"0123456789ABCDEF" * 64  # 1 KB
    with open(test_file, "wb") as f:
        for _ in range(2048):  # 2048 * 1 KB = 2 MB
            f.write(pattern)

    hasher_std = hashlib.sha256()
    with open(test_file, "rb") as f:
        while chunk := f.read(64 * 1024):
            hasher_std.update(chunk)

    expected = hasher_std.hexdigest()
    # Calculate with custom small chunk size (16 KB) to test multi-chunk loop
    digest = calculate_sha256(test_file, chunk_size=16 * 1024)
    assert digest == expected


def test_incremental_hasher():
    """IncrementalHasher must incrementally compute correct digest and byte count."""
    hasher = IncrementalHasher()
    chunks = [b"Chunk 1 ", b"Chunk 2 ", b"Final chunk."]
    total_bytes = b"".join(chunks)

    for chunk in chunks:
        hasher.update(chunk)

    assert hasher.bytes_processed == len(total_bytes)
    assert hasher.hexdigest() == hashlib.sha256(total_bytes).hexdigest()


def test_file_not_found():
    """calculate_sha256 must raise FileNotFoundError for missing paths."""
    with pytest.raises(FileNotFoundError):
        calculate_sha256(Path("non_existent_file_path_123.bin"))
