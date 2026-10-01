"""
verify_report_numbers.py
========================
Guards against the most embarrassing viva failure: a number in the report that
no longer matches the CSV it came from.

Every headline value quoted in report.tex / VIVA.md / the EXPLAINED docs is
listed here with its source (file, row, column). The script re-reads the CSVs
and reports drift. Run it after ANY re-run of the benchmarks.

Why this exists: re-running `benchmark_pqc.py --quick` or
`hybrid_handshake.py --reps 30` overwrites the canonical CSVs with
lower-fidelity data, silently invalidating the report's tables. This caught
exactly that during final verification.

Timings drift run-to-run on a laptop (turbo, thermals), so a tolerance band is
applied: values within TOLERANCE are fine, beyond it they need a look. Sizes
and byte counts are deterministic and must match EXACTLY.

Usage:  python verify_report_numbers.py
Exit code 0 = everything reconciles (within tolerance); 1 = drift found.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"
TOLERANCE = 0.20  # 20% band for timing values on a laptop


def load(name, key_cols, val_col):
    out = {}
    with (RESULTS / name).open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out[tuple(r[c] for c in key_cols)] = r[val_col]
    return out


# (label, expected, actual-getter) — expected values are those quoted in
# report.tex Tables I-III, the abstract, and VIVA.md section 3.
def main() -> int:
    timings = load("timings.csv", ["algorithm", "operation"], "median_ms")
    sizes_pk = load("sizes.csv", ["algorithm"], "public_key_bytes")
    sizes_ct = load("sizes.csv", ["algorithm"], "observed_bytes")
    hs_ms = load("handshake_results.csv", ["mode", "level"], "median_ms")
    hs_b = load("handshake_results.csv", ["mode", "level"], "bytes_total")

    timing_claims = [
        # Values as quoted in report.tex Tables I & III (run of 2026-07-27,
        # browser-open machine; ~1.6x slower than the idle-machine canonical
        # run — every conclusion is relative, so the story is unchanged).
        ("ECDH P-256 encaps", 0.143, ("ECDH P-256", "encapsulate")),
        ("X25519 encaps", 0.111, ("X25519", "encapsulate")),
        ("RSA-2048 decrypt", 0.891, ("RSA-2048 (OAEP)", "decapsulate")),
        ("ML-KEM-512 encaps", 0.154, ("ML-KEM-512 (Kyber512)", "encapsulate")),
        ("ML-KEM-512 decaps", 0.064, ("ML-KEM-512 (Kyber512)", "decapsulate")),
        ("ML-KEM-768 decaps", 0.090, ("ML-KEM-768 (Kyber768)", "decapsulate")),
        ("HQC-128 decaps", 8.07, ("HQC-128", "decapsulate")),
        ("ML-DSA-44 sign", 0.572, ("ML-DSA-44 (Dilithium2)", "sign")),
        ("ML-DSA-44 verify", 0.141, ("ML-DSA-44 (Dilithium2)", "verify")),
        ("Falcon-512 sign", 6.41, ("Falcon-512", "sign")),
        ("Falcon-512 verify", 0.066, ("Falcon-512", "verify")),
        ("SPHINCS+-128f sign", 60.5, ("SPHINCS+-SHA2-128f", "sign")),
        ("SPHINCS+-128s sign", 1189.0, ("SPHINCS+-SHA2-128s", "sign")),
        ("handshake classical", 1.056, None),
        ("handshake pq-768", 1.642, None),
        ("handshake hybrid-768", 2.256, None),
    ]
    hs_lookup = {
        "handshake classical": ("classical", "-"),
        "handshake pq-768": ("pq", "768"),
        "handshake hybrid-768": ("hybrid", "768"),
    }

    exact_claims = [
        # label, expected, actual
        ("ML-KEM-512 public key", 800, int(sizes_pk[("ML-KEM-512 (Kyber512)",)])),
        ("ML-KEM-512 ciphertext", 768, int(sizes_ct[("ML-KEM-512 (Kyber512)",)])),
        ("ML-KEM-768 public key", 1184, int(sizes_pk[("ML-KEM-768 (Kyber768)",)])),
        ("ML-DSA-44 public key", 1312, int(sizes_pk[("ML-DSA-44 (Dilithium2)",)])),
        ("ML-DSA-44 signature", 2420, int(sizes_ct[("ML-DSA-44 (Dilithium2)",)])),
        # NOTE: Falcon is deliberately absent from the exact list. Its
        # signature uses a variable-length COMPRESSED encoding, so its observed
        # size is a draw from a distribution, not a constant. It is range-checked
        # below instead. (Treating it as exact was itself a review finding.)
        ("SPHINCS+-128s signature", 7856, int(sizes_ct[("SPHINCS+-SHA2-128s",)])),
        ("SPHINCS+-128f signature", 17088, int(sizes_ct[("SPHINCS+-SHA2-128f",)])),
        ("X25519 public key", 32, int(sizes_pk[("X25519",)])),
        ("ECDH P-256 public key", 65, int(sizes_pk[("ECDH P-256",)])),
        ("handshake classical bytes", 202, int(hs_b[("classical", "-")])),
        ("handshake pq-768 bytes", 2410, int(hs_b[("pq", "768")])),
        ("handshake hybrid-768 bytes", 2474, int(hs_b[("hybrid", "768")])),
        ("hybrid overhead vs pure PQ",
         64, int(hs_b[("hybrid", "768")]) - int(hs_b[("pq", "768")])),
    ]

    # Variable-length signatures: check a plausible range, not equality.
    range_claims = [
        ("Falcon-512 signature (variable)", 620, 752,
         int(sizes_ct[("Falcon-512",)])),
        ("Falcon-1024 signature (variable)", 1200, 1462,
         int(sizes_ct[("Falcon-1024",)])),
    ]

    problems = 0

    print("EXACT values (sizes/bytes — must match)")
    for label, expected, actual in exact_claims:
        ok = expected == actual
        problems += 0 if ok else 1
        print(f"  [{'OK ' if ok else 'BAD'}] {label:34s} report {expected:>6}  csv {actual:>6}")

    print("\nVARIABLE-LENGTH signatures (range-checked, not exact)")
    for label, lo, hi, actual in range_claims:
        ok = lo <= actual <= hi
        problems += 0 if ok else 1
        print(f"  [{'OK ' if ok else 'BAD'}] {label:34s} expect {lo}-{hi:<6} csv {actual:>6}")

    print("\nTIMING values (laptop drift allowed within "
          f"{int(TOLERANCE*100)}%)")
    for label, expected, key in timing_claims:
        actual = float(hs_ms[hs_lookup[label]] if key is None else timings[key])
        drift = (actual - expected) / expected
        ok = abs(drift) <= TOLERANCE
        problems += 0 if ok else 1
        print(f"  [{'OK ' if ok else 'DRIFT'}] {label:32s} report {expected:8.3f}"
              f"  csv {actual:8.3f}  {drift:+6.1%}")

    print()
    if problems:
        print(f"{problems} value(s) need attention — update the report tables, "
              f"or re-run the canonical (non-quick) benchmarks:")
        print("  python benchmark_pqc.py           # NOT --quick")
        print("  python hybrid_handshake.py        # 100 reps default")
        return 1
    print("all report numbers reconcile with the CSVs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
