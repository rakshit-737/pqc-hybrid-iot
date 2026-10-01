"""
timing_analysis.py
==================
Timing side-channel analysis (Gap 4: the base paper performs no side-channel
or timing analysis at all).

Two experiments, one lesson: *timing is a side channel whenever execution
time correlates with secret data*.

Experiment A — the classic leak, demonstrated end-to-end
--------------------------------------------------------
A server checking a MAC tag / auth token with an early-exit comparison
(`for x, y in zip(a, b): if x != y: return False`) rejects a wrong tag
FASTER the earlier the first mismatch occurs. An attacker who can measure
rejection time can therefore guess the tag byte-by-byte (256 tries per byte
instead of 2^256 overall). We measure rejection time as a function of the
matching-prefix length for three comparison functions:

  * naive Python loop      -> expected: time grows linearly with prefix
  * bytes `==` (C memcmp)  -> also early-exit, but ~ns-scale differences
  * hmac.compare_digest    -> constant-time by contract: flat

Experiment B — the security-critical PQC path
---------------------------------------------
ML-KEM decapsulation runs the Fujisaki-Okamoto implicit-rejection check: it
re-encrypts the decrypted message and compares with the received ciphertext;
on mismatch it silently returns H(z || ct) instead of failing. If the valid
and invalid paths take measurably different time, an attacker gains a
chosen-ciphertext oracle against an IND-CCA2 KEM — this is not hypothetical:
the 2024 "KyberSlash" attacks exploited secret-dependent division timing in
reference Kyber decapsulation, and PQClean patched it. We time ML-KEM-512
decapsulation over three input classes:

  * valid ciphertexts
  * one bit flipped (implicit-rejection path)
  * fully random bytes of ciphertext length (implicit-rejection path)

and test whether the distributions differ.

Framing that earns viva marks: signature VERIFICATION operates on public
inputs only, so variable verify time is NOT a vulnerability - the operations
that must be constant-time are the ones touching secrets: decapsulation,
signing, and MAC/tag comparison. That is why Experiment B targets decaps.

Statistics — and two traps this script deliberately avoids
----------------------------------------------------------
Samples are batch means (like benchmark_pqc.py). Between two classes we
report the median difference and a Welch z-statistic
    z = (mean1 - mean2) / sqrt(s1^2/n1 + s2^2/n2)
with n in the hundreds z is ~N(0,1) under "no difference".

Trap 1 - a z-test alone over-claims. With n=300, |z|>3 flags differences of
a few nanoseconds that are real but far below anything exploitable through
Python's own ~50-100 ns per-call overhead. So Experiment A's verdict is
driven by the MONOTONIC TREND across matching-prefix lengths (Pearson r of
median-time vs prefix) - that rising staircase IS the attack signal - not by
a single significant z. A leak needs both a strong positive trend (r>0.9)
AND significance.

Trap 2 - measuring classes back-to-back lets thermal/frequency drift over the
run masquerade as a between-class difference. Every experiment here
INTERLEAVES its classes (round-robin, one batch of each per round) so drift
is spread evenly across all classes instead of confounding one.

Trap 3 - reusing one input object per class makes within-class variance
artificially tiny, which inflates z. Each class draws from a POOL of fresh
inputs, cycled across calls.

Usage:  python timing_analysis.py          (~1-2 min)
Output: ../results/timing_analysis.csv, consumed by plot_timing.py
"""

from __future__ import annotations

import csv
import gc
import hmac
import math
import secrets
import statistics
import time
from pathlib import Path

from pqcrypto.kem import ml_kem_512

from benchmark_pqc import pin_process  # same pinning as the benchmark suite

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

SAMPLES = 300          # batch-mean samples per (function, class)
CMP_BATCH = 2000       # comparisons per sample (Experiment A)
DECAPS_BATCH = 20      # decapsulations per sample (Experiment B)
TAG_LEN = 32           # bytes, like an HMAC-SHA-256 tag
PREFIXES = [0, 4, 8, 16, 24, 31]  # matching-prefix lengths to probe


# --------------------------------------------------------------------------
# Comparison functions under test (Experiment A)
# --------------------------------------------------------------------------

def naive_compare(a: bytes, b: bytes) -> bool:
    """Early-exit comparison — the textbook timing-leaky implementation."""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True


COMPARERS = [
    ("naive Python loop", naive_compare),
    ("bytes == (memcmp)", lambda a, b: a == b),
    ("hmac.compare_digest", hmac.compare_digest),
]


def collect_interleaved(runners: dict, n_samples: int, batch: int) -> dict:
    """Time each runner round-robin, batch calls per sample, so drift across
    the run is spread evenly across classes instead of confounding one.
    Returns {name: [batch-mean ns/call, ...]}."""
    for r in runners.values():          # warm one full batch of each
        for _ in range(batch):
            r()
    out = {name: [] for name in runners}
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(n_samples):
            for name, r in runners.items():
                t0 = time.perf_counter_ns()
                for _ in range(batch):
                    r()
                out[name].append((time.perf_counter_ns() - t0) / batch)  # ns/call
    finally:
        if gc_was_enabled:
            gc.enable()
    return out


def collect_sequential(runners: dict, n_samples: int, batch: int) -> dict:
    """Time each runner to completion before starting the next (all samples of
    class 1, then class 2, ...). This is the FLAWED design kept ONLY as a
    control: any drift over the run (thermal/frequency) maps onto class order
    and can manufacture a spurious 'timing difference'. Compare its verdict
    against collect_interleaved()'s to see the confound."""
    out = {}
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for name, r in runners.items():
            for _ in range(batch):      # per-class warm-up
                r()
            samples = []
            for _ in range(n_samples):
                t0 = time.perf_counter_ns()
                for _ in range(batch):
                    r()
                samples.append((time.perf_counter_ns() - t0) / batch)
            out[name] = samples
    finally:
        if gc_was_enabled:
            gc.enable()
    return out


def cycle_runner(fn, pool):
    """A zero-argument runner that applies fn to successive pool members."""
    i = 0
    def run():
        nonlocal i
        fn(pool[i])
        i = (i + 1) % len(pool)
    return run


def welch_z(s1: list[float], s2: list[float]) -> float:
    m1, m2 = statistics.fmean(s1), statistics.fmean(s2)
    v1, v2 = statistics.variance(s1), statistics.variance(s2)
    return (m1 - m2) / math.sqrt(v1 / len(s1) + v2 / len(s2))


def pearson(xs: list[float], ys: list[float]) -> float:
    n = len(xs)
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    sx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    sy = math.sqrt(sum((y - my) ** 2 for y in ys))
    return cov / (sx * sy) if sx and sy else 0.0


# --------------------------------------------------------------------------
# Experiment A
# --------------------------------------------------------------------------

def experiment_a(rows: list[dict]):
    print("[A] MAC-tag comparison timing vs matching-prefix length")
    correct = secrets.token_bytes(TAG_LEN)
    POOL = 16

    for cmp_name, cmp_fn in COMPARERS:
        # One runner per prefix, each cycling a pool of fresh candidates that
        # match `correct` in the first p bytes and differ at byte p.
        runners = {}
        for p in PREFIXES:
            pool = []
            for _ in range(POOL):
                tail = secrets.token_bytes(TAG_LEN - p)
                cand = bytearray(correct[:p] + tail)
                cand[p] = correct[p] ^ 0xFF          # guarantee mismatch at p
                assert not cmp_fn(bytes(cand), correct)
                pool.append(bytes(cand))
            runners[p] = cycle_runner(lambda c: cmp_fn(c, correct), pool)

        per_prefix = collect_interleaved(runners, SAMPLES, CMP_BATCH)
        for p in PREFIXES:
            s = per_prefix[p]
            rows.append(dict(
                experiment="A:tag-compare", function=cmp_name,
                input_class=f"prefix={p}", samples=len(s),
                median_ns=round(statistics.median(s), 2),
                mean_ns=round(statistics.fmean(s), 2),
                stdev_ns=round(statistics.stdev(s), 2),
            ))

        # Attack signal = does time rise monotonically with prefix length?
        med = [statistics.median(per_prefix[p]) for p in PREFIXES]
        r = pearson([float(p) for p in PREFIXES], med)
        z = welch_z(per_prefix[31], per_prefix[0])
        d = med[-1] - med[0]
        leaks = r > 0.9 and abs(z) > 3
        verdict = ("LEAKS (time rises with prefix)" if leaks
                   else "no exploitable trend")
        rows.append(dict(
            experiment="A:verdict", function=cmp_name,
            input_class="trend over prefix", samples=SAMPLES,
            median_ns=round(d, 2), mean_ns="", stdev_ns="",
            welch_z=round(z, 1), pearson_r=round(r, 3), verdict=verdict,
        ))
        print(f"  {cmp_name:22s} d(31-0)={d:8.1f} ns  r={r:+.3f}  z={z:7.1f}"
              f"  -> {verdict}")


# --------------------------------------------------------------------------
# Experiment B
# --------------------------------------------------------------------------

def experiment_b(rows: list[dict], collect=collect_interleaved,
                 tag: str = "B"):
    mode = "interleaved" if collect is collect_interleaved else "SEQUENTIAL (control)"
    print(f"[{tag}] ML-KEM-512 decapsulation: valid vs corrupted ciphertexts "
          f"[{mode}]")
    pk, sk = ml_kem_512.generate_keypair()
    n_ct = 64
    valid = [ml_kem_512.encrypt(pk)[0] for _ in range(n_ct)]

    def flip_one_bit(ct: bytes) -> bytes:
        i = secrets.randbelow(len(ct))
        return ct[:i] + bytes([ct[i] ^ 1]) + ct[i + 1:]

    classes = {
        "valid ct": valid,
        "1 bit flipped": [flip_one_bit(ct) for ct in valid],
        "random bytes": [secrets.token_bytes(ml_kem_512.CIPHERTEXT_SIZE)
                         for _ in range(n_ct)],
    }

    runners = {name: cycle_runner(lambda ct: ml_kem_512.decrypt(sk, ct), pool)
               for name, pool in classes.items()}
    dists = collect(runners, SAMPLES, DECAPS_BATCH)
    for name in classes:
        s = dists[name]
        rows.append(dict(
            experiment=f"{tag}:mlkem-decaps", function="ML-KEM-512 decapsulate",
            input_class=name, samples=len(s),
            median_ns=round(statistics.median(s), 1),
            mean_ns=round(statistics.fmean(s), 1),
            stdev_ns=round(statistics.stdev(s), 1),
        ))

    for other in ("1 bit flipped", "random bytes"):
        z = welch_z(dists[other], dists["valid ct"])
        d = statistics.median(dists[other]) - statistics.median(dists["valid ct"])
        rel = d / statistics.median(dists["valid ct"]) * 100
        verdict = ("TIMING DIFFERENCE (oracle risk)" if abs(z) > 3
                   else "constant-time (no evidence of leak)")
        rows.append(dict(
            experiment=f"{tag}:verdict", function="ML-KEM-512 decapsulate",
            input_class=f"{other} vs valid", samples=SAMPLES,
            median_ns=round(d, 1), mean_ns="", stdev_ns="",
            welch_z=round(z, 1), verdict=verdict,
        ))
        print(f"  {other:15s} vs valid: d(median) {d:8.1f} ns ({rel:+.2f}%), "
              f"z={z:6.1f} -> {verdict}")


def write_csv(path, rows):
    fields = ["experiment", "function", "input_class", "samples",
              "median_ns", "mean_ns", "stdev_ns", "welch_z", "pearson_r",
              "verdict"]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})
    print(f"wrote {path}")


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Timing side-channel analysis")
    ap.add_argument("--sequential", action="store_true",
                    help="ALSO run Experiment B with the flawed non-interleaved "
                         "design (control that shows drift can fake a leak)")
    args = ap.parse_args()

    print(f"pinning: {pin_process()}")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    experiment_a(rows)
    experiment_b(rows)  # interleaved (canonical)
    write_csv(RESULTS_DIR / "timing_analysis.csv", rows)

    if args.sequential:
        # The control run: measure Experiment B non-interleaved. Any spurious
        # significance here versus the interleaved run above IS the evidence
        # that measurement design matters. Written to its own CSV so the
        # comparison is reproducible, not asserted.
        print()
        seq_rows: list[dict] = []
        experiment_b(seq_rows, collect=collect_sequential, tag="B-seq")
        write_csv(RESULTS_DIR / "timing_analysis_sequential.csv", seq_rows)


if __name__ == "__main__":
    main()
