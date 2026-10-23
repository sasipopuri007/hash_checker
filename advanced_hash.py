"""
Advanced Cryptographic Hashing and Verification Engine.
Based on research findings from:
'Exploring Secure Hashing Algorithms for Data Integrity Verification'
(Chris Gilbert & Mercy Abiola Gilbert, IJMRAP, 2025).

Features:
- Dual-Layer & Multi-Algorithm Hashing (SHA-256, SHA-3-256 Sponge, SHA-512, Blake2b)
- Block Power Indexing & Fine-Grained Tamper Localization (Section 7.1, RQ v)
- Substring Index Tables (Section 7.1)
- Avalanche Effect Analyzer & Hamming Distance Diffusion Metric (Section II & IV)
- Multi-Algorithm Cryptographic Benchmark (Table 3, Section IX)
"""

import hashlib
import io
import math
from pathlib import Path
import time
from typing import Dict, List, Any, Optional, Tuple, Union

import config

DEFAULT_BLOCK_SIZE = 64 * 1024  # 64 KB blocks (can scale down for small files)


class MultiHasher:
    """
    Computes multiple cryptographic hash digests in a single streaming pass.
    Combines Merkle-Damgård (SHA-256, SHA-512) and Keccak Sponge (SHA-3-256) constructions.
    """

    def __init__(self):
        self._sha256 = hashlib.sha256()
        self._sha3_256 = hashlib.sha3_256()
        self._sha512 = hashlib.sha512()
        self._blake2b = hashlib.blake2b()
        self._bytes_processed = 0

    def update(self, data: bytes) -> None:
        """Update all hashers simultaneously."""
        self._sha256.update(data)
        self._sha3_256.update(data)
        self._sha512.update(data)
        self._blake2b.update(data)
        self._bytes_processed += len(data)

    def digests(self) -> Dict[str, str]:
        """Return hexadecimal digests for all algorithms."""
        return {
            "sha256": self._sha256.hexdigest(),
            "sha3_256": self._sha3_256.hexdigest(),
            "sha512": self._sha512.hexdigest(),
            "blake2b": self._blake2b.hexdigest(),
            "bytes_processed": self._bytes_processed
        }


class BlockPowerIndexer:
    """
    Implements Block Power Indexing (Section 7.1) to partition files into indexed blocks.
    Enables fine-grained localization of unauthorized alterations, identifying the exact
    corrupted byte ranges without requiring unassisted manual inspection.
    """

    def __init__(self, block_size: int = DEFAULT_BLOCK_SIZE):
        self.block_size = block_size

    def compute_block_index(self, file_path: Union[str, Path, bytes]) -> List[Dict[str, Any]]:
        """
        Divide file or bytes into blocks and compute SHA-256 for each block.
        Returns a list of block metadata dicts.
        """
        blocks = []
        block_idx = 0

        if isinstance(file_path, bytes):
            stream = io.BytesIO(file_path)
            total_size = len(file_path)
        else:
            path = Path(file_path)
            if not path.is_file():
                raise FileNotFoundError(f"File not found: {path}")
            total_size = path.stat().st_size
            stream = open(path, "rb")

        # Determine effective block size: adapt for tiny files (< 16 KB)
        effective_block_size = self.block_size
        if total_size > 0 and total_size < self.block_size:
            effective_block_size = max(1024, total_size // 4 or 512)

        offset = 0
        try:
            while True:
                chunk = stream.read(effective_block_size)
                if not chunk and blocks:
                    break
                if not chunk and not blocks:
                    # Empty file (0 bytes) has 1 empty block
                    h = hashlib.sha256(b"").hexdigest()
                    blocks.append({
                        "block_id": 0,
                        "offset_start": 0,
                        "offset_end": 0,
                        "size": 0,
                        "sha256": h
                    })
                    break

                h = hashlib.sha256(chunk).hexdigest()
                chunk_len = len(chunk)
                blocks.append({
                    "block_id": block_idx,
                    "offset_start": offset,
                    "offset_end": offset + chunk_len,
                    "size": chunk_len,
                    "sha256": h
                })
                offset += chunk_len
                block_idx += 1
                if chunk_len < effective_block_size:
                    break
        finally:
            if not isinstance(file_path, bytes):
                stream.close()

        return blocks

    def localize_tampering(
        self,
        current_file_path: Union[str, Path, bytes],
        expected_block_index: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Compares expected block hashes against the current file on disk.
        Pinpoints the exact corrupted blocks, offsets, and corruption percentage.
        """
        if not expected_block_index:
            return {
                "status": "NO_INDEX",
                "message": "No block index available for localization",
                "corrupted_blocks": [],
                "tampered_bytes": 0,
                "total_blocks": 0
            }

        # Use the block size from the first block
        sample_block_size = expected_block_index[0].get("size", self.block_size) or self.block_size
        current_blocks = self.compute_block_index(current_file_path)

        corrupted_blocks = []
        tampered_bytes = 0
        total_expected_blocks = len(expected_block_index)
        total_current_blocks = len(current_blocks)

        max_blocks = max(total_expected_blocks, total_current_blocks)

        for i in range(max_blocks):
            exp = expected_block_index[i] if i < total_expected_blocks else None
            curr = current_blocks[i] if i < total_current_blocks else None

            if exp is None:
                # Extra block appended to current file
                corrupted_blocks.append({
                    "block_id": i,
                    "reason": "EXTRA_APPENDED_BLOCK",
                    "offset_start": curr["offset_start"],
                    "offset_end": curr["offset_end"],
                    "current_hash": curr["sha256"],
                    "expected_hash": None
                })
                tampered_bytes += curr["size"]
            elif curr is None:
                # Block truncated/missing
                corrupted_blocks.append({
                    "block_id": i,
                    "reason": "MISSING_TRUNCATED_BLOCK",
                    "offset_start": exp["offset_start"],
                    "offset_end": exp["offset_end"],
                    "current_hash": None,
                    "expected_hash": exp["sha256"]
                })
                tampered_bytes += exp["size"]
            elif exp["sha256"] != curr["sha256"]:
                # Content altered in this block
                corrupted_blocks.append({
                    "block_id": i,
                    "reason": "HASH_MISMATCH",
                    "offset_start": curr["offset_start"],
                    "offset_end": curr["offset_end"],
                    "current_hash": curr["sha256"],
                    "expected_hash": exp["sha256"],
                    "block_size": curr["size"]
                })
                tampered_bytes += curr["size"]

        total_file_size = sum(b.get("size", 0) for b in expected_block_index) or 1
        corruption_pct = round((tampered_bytes / total_file_size) * 100, 2)

        is_intact = len(corrupted_blocks) == 0

        return {
            "status": "VERIFIED" if is_intact else "CORRUPTED",
            "is_intact": is_intact,
            "total_blocks": total_expected_blocks,
            "corrupted_count": len(corrupted_blocks),
            "intact_count": total_expected_blocks - len(corrupted_blocks),
            "corrupted_blocks": corrupted_blocks,
            "tampered_bytes": tampered_bytes,
            "total_bytes": total_file_size,
            "corruption_percentage": min(100.0, corruption_pct),
            "summary": (
                "File integrity confirmed across all blocks."
                if is_intact
                else f"Corruption localized to {len(corrupted_blocks)} block(s) ({corruption_pct}% of file altered)."
            )
        }


class SubstringIndexTable:
    """
    Implements Substring Index Tables (Section 7.1) for isolating and evaluating
    critical structural regions (e.g. PDF header '%PDF-', text markers, EOF tags).
    """

    def __init__(self, max_substring_len: int = 128):
        self.max_len = max_substring_len

    def create_table(self, data: bytes, anchors: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Scan data for structural anchors and store their offsets and SHA-256 hashes."""
        anchors = anchors or ["%PDF", "%%EOF", "<!DOCTYPE", "PK\x03\x04", "{" , "\n"]
        table = []
        for anchor in anchors:
            anchor_bytes = anchor.encode("utf-8", errors="ignore")
            pos = 0
            while True:
                idx = data.find(anchor_bytes, pos)
                if idx == -1:
                    break
                sample_len = min(len(data) - idx, self.max_len)
                segment = data[idx : idx + sample_len]
                table.append({
                    "anchor": anchor,
                    "offset": idx,
                    "length": sample_len,
                    "sha256": hashlib.sha256(segment).hexdigest()
                })
                pos = idx + len(anchor_bytes)
                if len(table) >= 50:  # Bound table size
                    break
        return table


class AvalancheAnalyzer:
    """
    Evaluates the Avalanche Effect and bit diffusion metrics (Section II & IV).
    Measures the percentage of digest bits that flip when a single bit is changed in the input.
    Ideal cryptographic diffusion approaches 50%.
    """

    @staticmethod
    def calculate_avalanche(
        input_data: Union[str, bytes],
        algorithm: str = "sha256",
        bit_to_flip: int = 0
    ) -> Dict[str, Any]:
        """
        Flip 1 bit in input data and measure the Hamming distance between the two digests.
        """
        if isinstance(input_data, str):
            raw1 = input_data.encode("utf-8")
        else:
            raw1 = bytearray(input_data)

        if not raw1:
            raw1 = bytearray(b"0")

        # Create modified copy with exactly 1 flipped bit
        raw2 = bytearray(raw1)
        byte_index = (bit_to_flip // 8) % len(raw2)
        bit_index = bit_to_flip % 8
        raw2[byte_index] ^= (1 << bit_index)

        # Compute digests
        h1_func = getattr(hashlib, algorithm)()
        h2_func = getattr(hashlib, algorithm)()

        h1_func.update(raw1)
        h2_func.update(raw2)

        digest1_hex = h1_func.hexdigest()
        digest2_hex = h2_func.hexdigest()

        # Convert hex digests to binary strings
        digest1_bin = bin(int(digest1_hex, 16))[2:].zfill(len(digest1_hex) * 4)
        digest2_bin = bin(int(digest2_hex, 16))[2:].zfill(len(digest2_hex) * 4)

        total_bits = len(digest1_bin)
        flipped_bits = sum(b1 != b2 for b1, b2 in zip(digest1_bin, digest2_bin))
        avalanche_percentage = round((flipped_bits / total_bits) * 100, 2)

        return {
            "algorithm": algorithm.upper(),
            "total_digest_bits": total_bits,
            "flipped_bits": flipped_bits,
            "avalanche_percentage": avalanche_percentage,
            "ideal_percentage": 50.0,
            "diffusion_score": round(100.0 - abs(50.0 - avalanche_percentage) * 2, 2),
            "original_hex": digest1_hex,
            "perturbed_hex": digest2_hex,
            "flipped_byte_index": byte_index,
            "flipped_bit_position": bit_index,
            "verdict": (
                "Excellent Diffusion (~50% Avalanche Effect)"
                if 45.0 <= avalanche_percentage <= 55.0
                else "Acceptable Diffusion"
            )
        }


class AlgorithmBenchmark:
    """
    Benchmarks cryptographic hashing algorithms (Table 3, Section IX).
    Evaluates throughput (MB/s), latency, and security strength.
    """

    ALGORITHMS = [
        {"name": "md5", "family": "MD", "bits": 128, "status": "DEPRECATED (Collisions broken)", "safe": False, "type": "Merkle-Damgård"},
        {"name": "sha1", "family": "SHA-1", "bits": 160, "status": "DEPRECATED (Shattered attack)", "safe": False, "type": "Merkle-Damgård"},
        {"name": "sha256", "family": "SHA-2", "bits": 256, "status": "STANDARD (Optimal balance)", "safe": True, "type": "Merkle-Damgård"},
        {"name": "sha512", "family": "SHA-2", "bits": 512, "status": "HIGH SECURITY (64-bit systems)", "safe": True, "type": "Merkle-Damgård"},
        {"name": "sha3_256", "family": "SHA-3", "bits": 256, "status": "STANDARD (Keccak Sponge / Quantum-Resilient)", "safe": True, "type": "Permutation Sponge"},
        {"name": "blake2b", "family": "BLAKE", "bits": 512, "status": "MODERN (High Throughput)", "safe": True, "type": "HAIFA/Tree"}
    ]

    @classmethod
    def run_benchmark(cls, data_size_mb: float = 2.0) -> List[Dict[str, Any]]:
        """Run benchmark on pseudo-random binary data across all algorithms."""
        total_bytes = int(data_size_mb * 1024 * 1024)
        # Generate test payload
        chunk = b"CryptographicIntegrityVerificationBenchmarkDataGilbert2025" * 1000
        reps = (total_bytes // len(chunk)) + 1
        data = (chunk * reps)[:total_bytes]

        results = []
        for algo in cls.ALGORITHMS:
            name = algo["name"]
            func = getattr(hashlib, name, None)
            if not func:
                continue

            start_t = time.perf_counter()
            h = func()
            # Process in 64KB blocks
            pos = 0
            while pos < len(data):
                h.update(data[pos : pos + 64 * 1024])
                pos += 64 * 1024
            _ = h.hexdigest()
            duration = max(time.perf_counter() - start_t, 0.0001)

            throughput_mbps = round(data_size_mb / duration, 2)
            results.append({
                "algorithm": name.upper(),
                "family": algo["family"],
                "digest_bits": algo["bits"],
                "throughput_mb_s": throughput_mbps,
                "latency_ms": round(duration * 1000, 2),
                "construction": algo["type"],
                "security_status": algo["status"],
                "is_secure": algo["safe"]
            })

        return results
