"""
Tests for Advanced Cryptographic Hashing and Verification Engine
(Gilbert & Gilbert, 2025).
"""

from pathlib import Path
import pytest
from advanced_hash import (
    MultiHasher,
    BlockPowerIndexer,
    SubstringIndexTable,
    AvalancheAnalyzer,
    AlgorithmBenchmark,
    calculate_shannon_entropy,
    RobustnessPerturbationLab,
    ResidualSignatureTracer,
    CollisionProbabilityCalculator,
    ResearchReportGenerator
)
from hash_utils import calculate_dual_hash


def test_multi_hasher():
    """MultiHasher must compute valid SHA-256, SHA-3-256, SHA-512, and Blake2b digests."""
    hasher = MultiHasher()
    hasher.update(b"Test payload for multi-algorithm verification Gilbert 2025")
    digests = hasher.digests()

    assert len(digests["sha256"]) == 64
    assert len(digests["sha3_256"]) == 64
    assert len(digests["sha512"]) == 128
    assert len(digests["blake2b"]) == 128
    assert digests["bytes_processed"] > 0


def test_calculate_dual_hash(tmp_path: Path):
    """calculate_dual_hash must calculate matching SHA-256 and SHA-3-256 digests."""
    sample = tmp_path / "dual_sample.bin"
    sample.write_bytes(b"Dual layer integrity testing: Merkle-Damgard + Keccak Sponge")

    res = calculate_dual_hash(sample)
    assert "sha256" in res
    assert "sha3_256" in res
    assert len(res["sha256"]) == 64
    assert len(res["sha3_256"]) == 64


def test_block_power_indexing_tamper_localization(tmp_path: Path):
    """
    Block Power Indexing must isolate and pinpoint the exact corrupted block and byte offset
    when 1 byte is modified (Section 7.1, RQ v).
    """
    indexer = BlockPowerIndexer(block_size=1024)  # 1 KB blocks for test

    # Create a 4 KB test file (4 blocks)
    test_file = tmp_path / "document.dat"
    block_data = [
        b"A" * 1024,  # Block 0
        b"B" * 1024,  # Block 1
        b"C" * 1024,  # Block 2
        b"D" * 1024   # Block 3
    ]
    test_file.write_bytes(b"".join(block_data))

    # Compute baseline block power index
    baseline_index = indexer.compute_block_index(test_file)
    assert len(baseline_index) == 4
    assert baseline_index[0]["block_id"] == 0
    assert baseline_index[1]["block_id"] == 1

    # 1. Unaltered file verification
    report_clean = indexer.localize_tampering(test_file, baseline_index)
    assert report_clean["status"] == "VERIFIED"
    assert report_clean["is_intact"] is True
    assert len(report_clean["corrupted_blocks"]) == 0

    # 2. Tamper: corrupt 1 byte strictly inside Block #2 (offset 2048 to 3072)
    tampered_bytes = bytearray(test_file.read_bytes())
    tamper_offset = 2048 + 50  # inside block 2
    tampered_bytes[tamper_offset] ^= 0xFF
    test_file.write_bytes(tampered_bytes)

    # 3. Localize tampering
    report_tampered = indexer.localize_tampering(test_file, baseline_index)
    assert report_tampered["status"] == "CORRUPTED"
    assert report_tampered["is_intact"] is False
    assert report_tampered["corrupted_count"] == 1
    assert report_tampered["intact_count"] == 3

    corrupted = report_tampered["corrupted_blocks"][0]
    assert corrupted["block_id"] == 2
    assert corrupted["offset_start"] == 2048
    assert corrupted["offset_end"] == 3072
    assert corrupted["reason"] == "HASH_MISMATCH"


def test_substring_index_table():
    """SubstringIndexTable must index structural anchor positions and compute hashes."""
    indexer = SubstringIndexTable(max_substring_len=64)
    data = b"%PDF-1.4\n1 0 obj\n<< /Title (Research Paper) >>\nendobj\n%%EOF\n"
    table = indexer.create_table(data, anchors=["%PDF", "%%EOF"])

    assert len(table) >= 2
    assert any(entry["anchor"] == "%PDF" for entry in table)
    assert any(entry["anchor"] == "%%EOF" for entry in table)
    for entry in table:
        assert "sha256" in entry
        assert "offset" in entry


def test_avalanche_analyzer():
    """
    AvalancheAnalyzer must flip 1 bit and verify that the bit diffusion percentage
    is near the 50% theoretical ideal (Section II & IV).
    """
    sample_text = "The quick brown fox jumps over the lazy dog."
    result = AvalancheAnalyzer.calculate_avalanche(sample_text, algorithm="sha256", bit_to_flip=3)

    assert result["algorithm"] == "SHA256"
    assert result["total_digest_bits"] == 256
    # SHA-256 exhibits strong avalanche effect, typically between 40% and 60%
    assert 35.0 <= result["avalanche_percentage"] <= 65.0
    assert result["flipped_bits"] > 80
    assert result["original_hex"] != result["perturbed_hex"]


def test_algorithm_benchmark():
    """AlgorithmBenchmark must test SHA families and return performance metrics."""
    results = AlgorithmBenchmark.run_benchmark(data_size_mb=0.2)
    assert len(results) >= 5

    names = [r["algorithm"] for r in results]
    assert "SHA256" in names
    assert "SHA3_256" in names
    assert "SHA512" in names
    assert "MD5" in names

    for r in results:
        assert r["throughput_mb_s"] > 0
        assert r["latency_ms"] >= 0
        assert "construction" in r


def test_shannon_entropy():
    """Verify Shannon entropy computation bounds."""
    # Constant bytes have entropy 0.0
    assert calculate_shannon_entropy(b"AAAAAAA") == 0.0
    # Random/mixed bytes have higher entropy
    mixed = bytes(range(256))
    assert calculate_shannon_entropy(mixed) == 8.0


def test_robustness_perturbation_lab():
    """Verify the 3 disturbance scenarios and Table 2 criteria scores."""
    sample = b"Secure Network File Transfer Cryptographic Robustness Test (Gilbert & Gilbert 2025)" * 50
    eval_res = RobustnessPerturbationLab.run_robustness_evaluation(sample)

    assert "table2_criteria_scores" in eval_res
    scores = eval_res["table2_criteria_scores"]
    assert scores["structural_agnosticism"] >= 50.0
    assert scores["error_resilience"] == 100.0
    assert scores["operational_stability"] >= 75.0
    assert scores["overall_robustness_index"] >= 75.0

    scenarios = eval_res["scenarios"]
    assert len(scenarios) == 3
    # All 3 perturbations should be successfully detected by dual hashing
    assert all(s["detected"] for s in scenarios)


def test_residual_signature_tracer():
    """Verify residual signature tracing and forensic tamper classification (RQ v)."""
    orig = b"Original baseline data for cryptographic forensic tracing" * 20
    # Case 1: Intact
    res_intact = ResidualSignatureTracer.trace_signature(orig, orig)
    assert res_intact["tamper_classification"] == "INTACT_NO_TAMPERING"

    # Case 2: Bit flip
    tampered_flip = bytearray(orig)
    tampered_flip[10] ^= 0x01
    res_flip = ResidualSignatureTracer.trace_signature(orig, bytes(tampered_flip))
    assert res_flip["tamper_classification"] == "RANDOM_BIT_FLIP"
    assert len(res_flip["residual_signature_hash"]) == 64

    # Case 3: Truncated
    tampered_trunc = orig[:len(orig) // 2]
    res_trunc = ResidualSignatureTracer.trace_signature(orig, tampered_trunc)
    assert res_trunc["tamper_classification"] == "TRUNCATION_OR_APPEND"


def test_collision_probability_calculator():
    """Verify Birthday Paradox collision probability mathematics."""
    # 2 items in 256 bits has essentially 0% collision probability
    calc_small = CollisionProbabilityCalculator.calculate_collision_probability(2, digest_bits=256)
    assert calc_small["collision_probability"] == 0.0
    assert "CRYPTOGRAPHICALLY SECURE" in calc_small["security_verdict"]

    # Testing an item count exceeding birthday bound for a toy 16-bit space
    calc_toy = CollisionProbabilityCalculator.calculate_collision_probability(500, digest_bits=16)
    assert calc_toy["collision_probability"] > 0.5

    # Check attack feasibility matrix
    matrix = CollisionProbabilityCalculator.get_attack_feasibility_matrix()
    assert len(matrix) >= 5
    assert any(m["algorithm"] == "MD5" and m["is_cryptographically_broken"] for m in matrix)
    assert any(m["algorithm"] == "SHA-256" and not m["is_cryptographically_broken"] for m in matrix)


def test_research_report_generator():
    """Verify academic research audit report generation."""
    rec = {
        "transfer_id": "test-uuid-1234",
        "original_filename": "paper.pdf",
        "status": "VERIFIED",
        "file_size": 1024,
        "expected_hash": "a" * 64,
        "received_hash": "a" * 64
    }
    report = ResearchReportGenerator.generate_report(rec)
    assert report["report_metadata"]["transfer_id"] == "test-uuid-1234"
    assert report["cryptographic_verification"]["dual_layer_verified"] is True

