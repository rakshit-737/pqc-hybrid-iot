"""
benchmark_pqc.py
================
Real-machine benchmark of classical vs post-quantum public-key cryptography.

Fills Gap 2 (the base paper, PQShield-IoT, reports only *simulated* numbers)
and Gap 3 (the base paper fixes on Dilithium2 with no comparison against
Falcon or SPHINCS+) of the project's gap analysis.

What is measured
----------------
KEMs (key establishment):    keygen / encapsulate / decapsulate
Signatures (authentication): keygen / sign / verify
Calibration (overhead):      an empty Python call and one os.urandom(32) call,
                             so the fixed per-call cost baked into every
                             sub-millisecond row is quantified, not guessed.

Schemes
-------
Classical (quantum-BROKEN by Shor's algorithm -> baseline only):
    RSA-2048 (OAEP key transport + PSS signatures), ECDH P-256, ECDSA P-256,
    X25519, Ed25519
Post-quantum (via pqcrypto = PQClean portable-C implementations):
    ML-KEM-512/768/1024   FIPS 203 final. Same design lineage as the round-3
                          Kyber512/768/1024 the base paper uses, near-identical
                          cost, but NOT bit-compatible (FIPS 203 changed the
                          FO-transform/KDF details).
    HQC-128               code-based; NIST's 2025 backup-KEM selection
    ML-DSA-44/65          FIPS 204 final. Successor of round-3 Dilithium2/3
                          (the base paper's signature); near-identical cost,
                          not bit-compatible (sk grew 2528 -> 2560 B).
    Falcon-512/1024       compact lattice signatures; selected for
                          standardization as FN-DSA (FIPS 206 not yet published)
    SPHINCS+-SHA2-128f/s  hash-based, v3.1 submission code — the basis of
                          FIPS 205 SLH-DSA (same sizes/performance; encodings
                          not bit-compatible with final SLH-DSA)

Methodology (defend these choices in the viva)
----------------------------------------------
* time.perf_counter_ns(): monotonic, highest-resolution clock in Python.
  Never use time.time() for benchmarking (NTP can move it mid-run).
* TIME-BASED warm-up (>= WARMUP_S seconds, not a fixed call count): long
  enough to ramp CPU frequency and settle caches even for microsecond ops.
* Process pinned to one CPU and raised to high priority (best effort) so
  samples do not migrate between P- and E-cores on hybrid CPUs.
* Garbage collector disabled inside the timed region.
* BATCHED sampling for fast operations: any op estimated under 1 ms is timed
  in batches of k calls sized so each sample spans >= TARGET_SAMPLE_S. A
  sample is then the batch MEAN. This defeats timer granularity and
  scheduler-quantum effects; ops >= 1 ms use k=1 (per-call timing), which
  also preserves per-call variance where it is the story (Dilithium's
  rejection sampling, RSA's prime search).
* Adaptive sample count: run until BUDGET_S seconds or MAX_SAMPLES,
  never fewer than MIN_SAMPLES. Config lives in CONFIG and is read at call
  time (NOT via default arguments — Python binds those at definition time,
  which is exactly the bug an earlier version of this script had).
* MEDIAN is the headline statistic (right-skewed noise: the OS only ever
  ADDS time). min approximates the noise floor; mean/stdev/max show spread.
* Each keypair-generation is measured ONCE per key type and the same row is
  reported under both the KEM and Signature tables where applicable (RSA,
  P-256) — re-measuring it minutes apart on a laptop yields contradictory
  numbers as the machine warms up.
* 59-byte signing message: the SUPERCOP / pqm4 benchmarking convention. This
  makes our benchmark SETUP match pqm4's when the report cites its Cortex-M4
  numbers next to ours; it does NOT make x86 milliseconds directly comparable
  to M4 cycle counts — cross-platform comparisons stay qualitative.
* Correctness preflight: before timing, every KEM must round-trip a shared
  secret and every signature must verify, so we never benchmark a silently
  broken operation.

Fairness notes (state these up front, they bound every conclusion)
------------------------------------------------------------------
1. Classical numbers come from OpenSSL's hand-tuned assembly; PQC numbers
   from PQClean's portable "clean" C (no AVX2). Relative orderings are
   trustworthy WITHIN each family; classical-vs-PQC gaps are UPPER BOUNDS on
   PQC cost (AVX2 ML-KEM is roughly 5-10x faster than clean C and would move
   past several classical rows).
2. Sub-millisecond rows include fixed per-call overhead (Python dispatch,
   CFFI, and an OS-RNG syscall for the randomized ops: keygen/encapsulate/
   sign). The Calibration rows measure that overhead. This is why our
   ML-KEM decapsulate (deterministic, no RNG) can appear FASTER than
   encapsulate, whereas on raw cycle counts (PQClean/SUPERCOP/pqm4)
   decapsulation is slightly SLOWER — cite the published ordering, not ours,
   for that specific claim.
3. ECDH/X25519 are benchmarked as KEMs including the wire costs a real
   DH-KEM pays: encapsulate serializes the ephemeral public key and hashes
   the shared secret (minimal KDF); decapsulate parses/validates the received
   point before the exchange. RSA-OAEP is key TRANSPORT (encrypt a random
   32-byte secret) benchmarked under the KEM interface; the distinct RSA-KEM
   construction (ISO 18033-2) is not what is measured here.

Usage
-----
    python benchmark_pqc.py            # full run (~4-6 minutes)
    python benchmark_pqc.py --quick    # smoke test, fewer/shorter samples

Outputs (written to ../results/):
    timings.csv, sizes.csv, system_info.txt
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import gc
import importlib
import importlib.metadata
import math
import os
import platform
import secrets
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    padding,
    rsa,
    x25519,
)

# --------------------------------------------------------------------------
# Configuration — mutable at runtime (read inside bench() at CALL time)
# --------------------------------------------------------------------------

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

CONFIG = {
    "warmup_s": 0.25,        # time-based warm-up per operation
    "budget_s": 3.0,         # sampling budget per operation (soft)
    "min_samples": 15,       # floor, even for very slow ops
    "max_samples": 300,      # ceiling, even for very fast ops
    "target_sample_s": 0.01, # batch fast ops so one sample spans >= 10 ms
    "batch_threshold_s": 1e-3,  # ops slower than this are never batched (k=1)
}

CT_POOL = 32  # pre-generated ciphertexts / ephemeral keys / signatures
SIG_LEN_SAMPLES = 100  # signatures sampled to characterise variable-length sigs

# 59-byte message: SUPERCOP/pqm4 convention, padded IoT-style telemetry.
MESSAGE = b'{"dev":"n01","t":24.5,"h":61,"seq":1042}'.ljust(59, b" ")[:59]
assert len(MESSAGE) == 59


def pin_process() -> str:
    """Best-effort: pin to CPU 0 and raise priority so samples don't migrate
    between P-/E-cores or lose the CPU mid-measurement. Returns a status
    string recorded in system_info.txt."""
    if sys.platform != "win32":
        try:
            os.sched_setaffinity(0, {0})
            return "affinity CPU0 (sched_setaffinity)"
        except Exception as e:
            return f"not pinned ({e})"
    try:
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
        # GetCurrentProcess returns the pseudo-handle -1; without explicit
        # types ctypes truncates it to 32 bits and every call silently fails.
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        k32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k32.SetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.c_size_t]
        HIGH_PRIORITY_CLASS = 0x00000080
        proc = k32.GetCurrentProcess()
        ok1 = k32.SetPriorityClass(proc, HIGH_PRIORITY_CLASS)
        ok2 = k32.SetProcessAffinityMask(proc, 1)  # CPU 0: a P-core thread on hybrid Intel
        return f"priority=HIGH({bool(ok1)}), affinity=CPU0({bool(ok2)})"
    except Exception as e:
        return f"not pinned ({e})"


# --------------------------------------------------------------------------
# Timing engine
# --------------------------------------------------------------------------

def bench(fn) -> tuple[list[float], int]:
    """Time fn() under CONFIG; return (samples in ms, batch size k).

    Fast ops (< batch_threshold_s per call) are measured in batches of k
    calls per sample, sized so each sample spans >= target_sample_s; the
    sample value is the batch mean. Slow ops use k=1 (per-call samples).
    """
    c = CONFIG  # read at call time, so --quick actually takes effect

    # Time-based warm-up (>= warmup_s and >= 3 calls).
    t_end = time.perf_counter() + c["warmup_s"]
    calls = 0
    while calls < 3 or time.perf_counter() < t_end:
        fn()
        calls += 1

    # Estimate per-call cost (min of 3 to dodge a stray interrupt).
    est_s = math.inf
    for _ in range(3):
        t0 = time.perf_counter_ns()
        fn()
        est_s = min(est_s, (time.perf_counter_ns() - t0) / 1e9)

    if est_s < c["batch_threshold_s"]:
        k = max(1, min(10_000, math.ceil(c["target_sample_s"] / max(est_s, 1e-9))))
    else:
        k = 1

    samples: list[float] = []
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        deadline = time.perf_counter() + c["budget_s"]
        while len(samples) < c["max_samples"]:
            if len(samples) >= c["min_samples"] and time.perf_counter() >= deadline:
                break
            t0 = time.perf_counter_ns()
            for _ in range(k):
                fn()
            samples.append((time.perf_counter_ns() - t0) / k / 1e6)  # ns -> ms per call
    finally:
        if gc_was_enabled:
            gc.enable()
    return samples, k


@dataclass
class TimingRow:
    family: str          # Classical / Lattice / Code-based / Hash-based / Calibration
    kind: str            # KEM / Signature / Overhead
    algorithm: str
    nist_level: str      # "1".."5" for PQC, "-" otherwise
    quantum_resistant: str  # yes / no / n-a
    operation: str       # keygen / encapsulate / decapsulate / sign / verify / call
    samples: int
    batch: int           # calls per sample (1 = per-call timing)
    median_ms: float
    mean_ms: float
    stdev_ms: float
    min_ms: float
    max_ms: float


def summarize(family, kind, algorithm, nist_level, qr, operation,
              bench_result: tuple[list[float], int]) -> TimingRow:
    samples, k = bench_result
    return TimingRow(
        family=family, kind=kind, algorithm=algorithm, nist_level=nist_level,
        quantum_resistant=qr, operation=operation,
        samples=len(samples), batch=k,
        median_ms=round(statistics.median(samples), 6),
        mean_ms=round(statistics.fmean(samples), 6),
        stdev_ms=round(statistics.stdev(samples), 6) if len(samples) > 1 else 0.0,
        min_ms=round(min(samples), 6),
        max_ms=round(max(samples), 6),
    )


def cycler(fn, key, blobs):
    """Apply fn(key, blob) over a pool of blobs, one per call, so the input
    of decapsulate/verify is produced OUTSIDE the timed region and varies
    across iterations."""
    i = 0
    def run():
        nonlocal i
        fn(key, blobs[i])
        i = (i + 1) % len(blobs)
    return run


# --------------------------------------------------------------------------
# Calibration — quantify fixed per-call overhead
# --------------------------------------------------------------------------

def bench_calibration(timings):
    print("  calibration: python call / OS RNG")
    noop = (lambda: None)
    timings.append(summarize("Calibration", "Overhead", "empty Python call", "-",
                             "n-a", "call", bench(noop)))
    timings.append(summarize("Calibration", "Overhead", "os.urandom(32)", "-",
                             "n-a", "call", bench(lambda: os.urandom(32))))


# --------------------------------------------------------------------------
# Post-quantum adapters (pqcrypto / PQClean)
# --------------------------------------------------------------------------

# (module, display name, family, NIST security category)
PQ_KEMS = [
    ("ml_kem_512",  "ML-KEM-512 (Kyber512)",   "Lattice",    "1"),
    ("ml_kem_768",  "ML-KEM-768 (Kyber768)",   "Lattice",    "3"),
    ("ml_kem_1024", "ML-KEM-1024 (Kyber1024)", "Lattice",    "5"),
    ("hqc_128",     "HQC-128",                 "Code-based", "1"),
]

PQ_SIGS = [
    ("ml_dsa_44",               "ML-DSA-44 (Dilithium2)", "Lattice",    "2"),
    ("ml_dsa_65",               "ML-DSA-65 (Dilithium3)", "Lattice",    "3"),
    ("falcon_512",              "Falcon-512",             "Lattice",    "1"),
    ("falcon_1024",             "Falcon-1024",            "Lattice",    "5"),
    ("sphincs_sha2_128f_simple", "SPHINCS+-SHA2-128f",    "Hash-based", "1"),
    ("sphincs_sha2_128s_simple", "SPHINCS+-SHA2-128s",    "Hash-based", "1"),
]


def bench_pq_kem(mod_name, label, family, level, timings, sizes):
    m = importlib.import_module(f"pqcrypto.kem.{mod_name}")
    pk, sk = m.generate_keypair()
    pool = [m.encrypt(pk) for _ in range(CT_POOL)]  # (ct, ss) pairs
    # Correctness preflight: decapsulation must round-trip, or we would be
    # timing garbage (ML-KEM's implicit rejection returns wrong bytes
    # silently instead of raising).
    assert m.decrypt(sk, pool[0][0]) == pool[0][1], f"{label}: decaps round-trip failed"
    ct_pool = [ct for ct, _ in pool]

    print(f"  {label}")
    for op, fn in [
        ("keygen",      lambda: m.generate_keypair()),
        ("encapsulate", lambda: m.encrypt(pk)),
        ("decapsulate", cycler(m.decrypt, sk, ct_pool)),
    ]:
        timings.append(summarize(family, "KEM", label, level, "yes", op, bench(fn)))

    sizes.append(dict(
        family=family, kind="KEM", algorithm=label, nist_level=level,
        quantum_resistant="yes",
        public_key_bytes=m.PUBLIC_KEY_SIZE, secret_key_bytes=m.SECRET_KEY_SIZE,
        ciphertext_or_signature_bytes=m.CIPHERTEXT_SIZE,
        observed_bytes=len(ct_pool[0]), shared_secret_bytes=m.PLAINTEXT_SIZE,
    ))


def bench_pq_sig(mod_name, label, family, level, timings, sizes):
    m = importlib.import_module(f"pqcrypto.sign.{mod_name}")
    pk, sk = m.generate_keypair()
    sig = m.sign(sk, MESSAGE)
    assert m.verify(pk, MESSAGE, sig), f"{label}: verify preflight failed"
    sig_pool = [m.sign(sk, MESSAGE) for _ in range(8)]

    print(f"  {label}")
    for op, fn in [
        ("keygen", lambda: m.generate_keypair()),
        ("sign",   lambda: m.sign(sk, MESSAGE)),
        ("verify", cycler(lambda k, s: m.verify(k, MESSAGE, s), pk, sig_pool)),
    ]:
        timings.append(summarize(family, "Signature", label, level, "yes", op, bench(fn)))

    # Falcon signatures use a variable-length COMPRESSED encoding, so a single
    # len(sig) is one draw from a distribution and will not reproduce. Sample a
    # pool and record mean/min/max; for fixed-length schemes min==max==mean.
    lens = [len(m.sign(sk, MESSAGE)) for _ in range(SIG_LEN_SAMPLES)]
    sizes.append(dict(
        family=family, kind="Signature", algorithm=label, nist_level=level,
        quantum_resistant="yes",
        # SIGNATURE_SIZE is PQClean's buffer MAXIMUM for the variable-length
        # compressed encoding. For Falcon the spec's fixed "padded" format is
        # 666 B (Falcon-512) / 1280 B (Falcon-1024); observed_* record what was
        # actually produced over SIG_LEN_SAMPLES signatures.
        ciphertext_or_signature_bytes=m.SIGNATURE_SIZE,
        public_key_bytes=m.PUBLIC_KEY_SIZE, secret_key_bytes=m.SECRET_KEY_SIZE,
        observed_bytes=round(statistics.fmean(lens)),
        observed_min_bytes=min(lens), observed_max_bytes=max(lens),
        shared_secret_bytes="",
    ))


# --------------------------------------------------------------------------
# Classical adapters (cryptography / OpenSSL)
# --------------------------------------------------------------------------
# ECDH and X25519 are benchmarked *as KEMs* (ephemeral-static DH) INCLUDING
# the wire costs a real DH-KEM pays:
#   encapsulate = generate ephemeral keypair + SERIALIZE its public key
#                 (that serialization IS the "ciphertext") + derive the
#                 shared secret + hash it (minimal KDF, as every real
#                 DH-KEM construction, incl. TLS 1.3's X25519MLKEM768, does)
#   decapsulate = PARSE/VALIDATE the received ephemeral public key +
#                 exchange + the same KDF hash
# ML-KEM's timed C calls include their (de)serialization and hashing, so
# excluding these steps would quietly favor the classical schemes.

RSA_BITS = 2048
RSA_E = 65537
CURVE = ec.SECP256R1()
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                  salt_length=hashes.SHA256().digest_size)  # instance, not class
ECDSA_SHA256 = ec.ECDSA(hashes.SHA256())


def _kdf32(shared: bytes, wire: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(shared + wire)
    return h.finalize()


def bench_classical(timings, sizes):
    # ---- shared keygen measurements (measured ONCE, reported where used) --
    print("  P-256 keygen (shared row)")
    p256_keygen = bench(lambda: ec.generate_private_key(CURVE))
    print("  RSA-2048 keygen (shared row)")
    rsa_keygen = bench(lambda: rsa.generate_private_key(public_exponent=RSA_E,
                                                        key_size=RSA_BITS))

    # ---- ECDH P-256 as a KEM -------------------------------------------
    print("  ECDH P-256")
    static = ec.generate_private_key(CURVE)
    static_pub = static.public_key()
    X962 = serialization.Encoding.X962
    UNCOMP = serialization.PublicFormat.UncompressedPoint
    eph_wires = [ec.generate_private_key(CURVE).public_key()
                 .public_bytes(X962, UNCOMP) for _ in range(CT_POOL)]

    def ecdh_encaps():
        eph = ec.generate_private_key(CURVE)
        wire = eph.public_key().public_bytes(X962, UNCOMP)
        _kdf32(eph.exchange(ec.ECDH(), static_pub), wire)

    def ecdh_decaps(key, wire):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, wire)  # on-curve validation
        _kdf32(key.exchange(ec.ECDH(), peer), wire)

    timings.append(summarize("Classical", "KEM", "ECDH P-256", "-", "no",
                             "keygen", p256_keygen))
    for op, fn in [
        ("encapsulate", ecdh_encaps),
        ("decapsulate", cycler(ecdh_decaps, static, eph_wires)),
    ]:
        timings.append(summarize("Classical", "KEM", "ECDH P-256", "-", "no", op, bench(fn)))
    sizes.append(dict(family="Classical", kind="KEM", algorithm="ECDH P-256",
                      nist_level="-", quantum_resistant="no",
                      public_key_bytes=65, secret_key_bytes=32,   # X9.62 uncompressed / raw scalar
                      ciphertext_or_signature_bytes=65,           # ephemeral public key on the wire
                      observed_bytes=len(eph_wires[0]), shared_secret_bytes=32))

    # ---- X25519 as a KEM (the classical half of TLS 1.3 hybrid) ---------
    print("  X25519")
    xs = x25519.X25519PrivateKey.generate()
    xs_pub = xs.public_key()
    x_wires = [x25519.X25519PrivateKey.generate().public_key()
               .public_bytes_raw() for _ in range(CT_POOL)]

    def x_encaps():
        eph = x25519.X25519PrivateKey.generate()
        wire = eph.public_key().public_bytes_raw()
        _kdf32(eph.exchange(xs_pub), wire)

    def x_decaps(key, wire):
        _kdf32(key.exchange(x25519.X25519PublicKey.from_public_bytes(wire)), wire)

    for op, fn in [
        ("keygen",      lambda: x25519.X25519PrivateKey.generate()),
        ("encapsulate", x_encaps),
        ("decapsulate", cycler(x_decaps, xs, x_wires)),
    ]:
        timings.append(summarize("Classical", "KEM", "X25519", "-", "no", op, bench(fn)))
    sizes.append(dict(family="Classical", kind="KEM", algorithm="X25519",
                      nist_level="-", quantum_resistant="no",
                      public_key_bytes=32, secret_key_bytes=32,
                      ciphertext_or_signature_bytes=32, observed_bytes=32,
                      shared_secret_bytes=32))

    # ---- RSA-2048 key transport (OAEP), benchmarked under the KEM interface
    print("  RSA-2048 (OAEP)")
    rkey = rsa.generate_private_key(public_exponent=RSA_E, key_size=RSA_BITS)
    rpub = rkey.public_key()
    # Actual DER encodings, computed instead of hardcoded:
    rsa_spki = len(rpub.public_bytes(serialization.Encoding.DER,
                                     serialization.PublicFormat.SubjectPublicKeyInfo))
    rsa_pkcs8 = len(rkey.private_bytes(serialization.Encoding.DER,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    secret32 = secrets.token_bytes(32)
    ct_pool = [rpub.encrypt(secrets.token_bytes(32), OAEP) for _ in range(CT_POOL)]

    timings.append(summarize("Classical", "KEM", "RSA-2048 (OAEP)", "-", "no",
                             "keygen", rsa_keygen))
    for op, fn in [
        ("encapsulate", lambda: rpub.encrypt(secret32, OAEP)),
        ("decapsulate", cycler(lambda k, c: k.decrypt(c, OAEP), rkey, ct_pool)),
    ]:
        timings.append(summarize("Classical", "KEM", "RSA-2048 (OAEP)", "-", "no", op, bench(fn)))
    sizes.append(dict(family="Classical", kind="KEM", algorithm="RSA-2048 (OAEP)",
                      nist_level="-", quantum_resistant="no",
                      public_key_bytes=rsa_spki,      # DER SubjectPublicKeyInfo
                      secret_key_bytes=rsa_pkcs8,     # DER PKCS#8
                      ciphertext_or_signature_bytes=RSA_BITS // 8,
                      observed_bytes=len(ct_pool[0]), shared_secret_bytes=32))

    # ---- ECDSA P-256 -----------------------------------------------------
    print("  ECDSA P-256")
    ek = ec.generate_private_key(CURVE)
    epub = ek.public_key()
    sig_pool = [ek.sign(MESSAGE, ECDSA_SHA256) for _ in range(CT_POOL)]
    epub.verify(sig_pool[0], MESSAGE, ECDSA_SHA256)  # preflight (raises on failure)

    timings.append(summarize("Classical", "Signature", "ECDSA P-256", "-", "no",
                             "keygen", p256_keygen))
    for op, fn in [
        ("sign",   lambda: ek.sign(MESSAGE, ECDSA_SHA256)),
        ("verify", cycler(lambda k, s: k.verify(s, MESSAGE, ECDSA_SHA256), epub, sig_pool)),
    ]:
        timings.append(summarize("Classical", "Signature", "ECDSA P-256", "-", "no", op, bench(fn)))
    sizes.append(dict(family="Classical", kind="Signature", algorithm="ECDSA P-256",
                      nist_level="-", quantum_resistant="no",
                      public_key_bytes=65, secret_key_bytes=32,
                      ciphertext_or_signature_bytes=72,  # DER max; actual 70-72
                      observed_bytes=len(sig_pool[0]), shared_secret_bytes=""))

    # ---- Ed25519 ----------------------------------------------------------
    print("  Ed25519")
    edk = ed25519.Ed25519PrivateKey.generate()
    edpub = edk.public_key()
    edsig = edk.sign(MESSAGE)
    edpub.verify(edsig, MESSAGE)  # preflight

    for op, fn in [
        ("keygen", lambda: ed25519.Ed25519PrivateKey.generate()),
        ("sign",   lambda: edk.sign(MESSAGE)),
        ("verify", lambda: edpub.verify(edsig, MESSAGE)),
    ]:
        timings.append(summarize("Classical", "Signature", "Ed25519", "-", "no", op, bench(fn)))
    sizes.append(dict(family="Classical", kind="Signature", algorithm="Ed25519",
                      nist_level="-", quantum_resistant="no",
                      public_key_bytes=32, secret_key_bytes=32,
                      ciphertext_or_signature_bytes=64, observed_bytes=len(edsig),
                      shared_secret_bytes=""))

    # ---- RSA-2048 signatures (PSS) ----------------------------------------
    print("  RSA-2048 (PSS)")
    rsig = rkey.sign(MESSAGE, PSS, hashes.SHA256())
    rpub.verify(rsig, MESSAGE, PSS, hashes.SHA256())  # preflight

    # keygen: same single measurement as the OAEP row (one keypair type, one
    # number — re-measuring it later in the run gave contradictory values).
    timings.append(summarize("Classical", "Signature", "RSA-2048 (PSS)", "-", "no",
                             "keygen", rsa_keygen))
    for op, fn in [
        ("sign",   lambda: rkey.sign(MESSAGE, PSS, hashes.SHA256())),
        ("verify", lambda: rpub.verify(rsig, MESSAGE, PSS, hashes.SHA256())),
    ]:
        timings.append(summarize("Classical", "Signature", "RSA-2048 (PSS)", "-", "no", op, bench(fn)))
    sizes.append(dict(family="Classical", kind="Signature", algorithm="RSA-2048 (PSS)",
                      nist_level="-", quantum_resistant="no",
                      public_key_bytes=rsa_spki, secret_key_bytes=rsa_pkcs8,
                      ciphertext_or_signature_bytes=RSA_BITS // 8,
                      observed_bytes=len(rsig), shared_secret_bytes=""))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def _ps(cmd: str) -> str:
    """Best-effort PowerShell one-liner for environment metadata."""
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                             capture_output=True, text=True, timeout=15)
        return " ".join(out.stdout.split()) or "?"
    except Exception:
        return "?"


def write_system_info(path: Path, mode: str, pin_status: str):
    if sys.platform == "win32":
        cpu_name = _ps("(Get-CimInstance Win32_Processor).Name")
        power_plan = _ps("powercfg /getactivescheme")
        battery = _ps("(Get-CimInstance Win32_BatteryStatus -EA SilentlyContinue).PowerOnline; (Get-CimInstance Win32_Battery -EA SilentlyContinue).BatteryStatus")
    else:
        cpu_name, power_plan, battery = platform.processor(), "?", "?"
    lines = [
        f"timestamp_utc   : {datetime.now(timezone.utc).isoformat()}",
        f"platform        : {platform.platform()}",
        f"cpu             : {cpu_name}",
        f"cpu (raw id)    : {platform.processor()}",
        f"logical cores   : {os.cpu_count()}",
        f"power plan      : {power_plan}",
        f"battery status  : {battery}  (2 or empty typically = on AC)",
        f"process pinning : {pin_status}",
        f"python          : {platform.python_version()} ({platform.python_implementation()})",
        f"pqcrypto        : {importlib.metadata.version('pqcrypto')} (PQClean portable C, no AVX2)",
        f"cryptography    : {importlib.metadata.version('cryptography')} (OpenSSL-backed, optimized asm)",
        f"mode            : {mode}",
        f"config          : {CONFIG}",
        f"message length  : {len(MESSAGE)} bytes (SUPERCOP/pqm4 convention)",
        "note            : run on AC power, high-performance plan, idle machine;",
        "                  classical ops run before PQC ops (order not interleaved).",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(description="Classical-vs-PQC benchmark suite")
    ap.add_argument("--quick", action="store_true",
                    help="shorter budgets / fewer samples (~40 s smoke test)")
    args = ap.parse_args()
    if args.quick:
        CONFIG.update(warmup_s=0.1, budget_s=0.5, min_samples=5,
                      max_samples=60, target_sample_s=0.005)

    pin_status = pin_process()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    write_system_info(RESULTS_DIR / "system_info.txt",
                      "quick" if args.quick else "full", pin_status)

    timings: list[TimingRow] = []
    sizes: list[dict] = []

    t_start = time.perf_counter()
    print("\n[1/4] Calibration (fixed per-call overhead)")
    bench_calibration(timings)

    print("[2/4] Classical baselines (cryptography/OpenSSL)")
    bench_classical(timings, sizes)

    print("[3/4] Post-quantum KEMs (pqcrypto/PQClean)")
    for mod, label, family, level in PQ_KEMS:
        bench_pq_kem(mod, label, family, level, timings, sizes)

    print("[4/4] Post-quantum signatures (pqcrypto/PQClean)")
    for mod, label, family, level in PQ_SIGS:
        bench_pq_sig(mod, label, family, level, timings, sizes)

    tpath = RESULTS_DIR / "timings.csv"
    with tpath.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(TimingRow.__dataclass_fields__))
        w.writeheader()
        for row in timings:
            w.writerow(dataclasses.asdict(row))

    spath = RESULTS_DIR / "sizes.csv"
    with spath.open("w", newline="", encoding="utf-8") as f:
        # rows are heterogeneous: only variable-length signature schemes carry
        # observed_min/max_bytes, so the header is the ordered union of keys
        fieldnames = list(dict.fromkeys(k for row in sizes for k in row))
        w = csv.DictWriter(f, fieldnames=fieldnames, restval="")
        w.writeheader()
        w.writerows(sizes)

    print(f"\nDone in {time.perf_counter() - t_start:.1f}s "
          f"-> {tpath}\n{'':13}-> {spath}")


if __name__ == "__main__":
    main()
