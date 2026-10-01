"""
pqm4_extrapolation.py
=====================
Phase 5 (Gap 5): bridge our desktop measurements to real constrained-device
performance using the PUBLIC pqm4 Cortex-M4 benchmark dataset, and produce an
RFC 7228 device-class -> PQC-scheme recommendation matrix.

Why this is methodologically sound (the point to make in the viva)
------------------------------------------------------------------
pqm4's "clean" cycle counts are compiled from the SAME PQClean C source that
our `pqcrypto`-based desktop benchmark runs. So this is not a hand-wave
across libraries: it is one codebase measured on two CPUs (an Intel i5-13500H
vs an ARM Cortex-M4), which is the cleanest cross-platform comparison
available without owning the hardware. The base paper (PQShield-IoT) only
*simulated* Cortex-M4F devices; here we anchor to independently published,
real-silicon cycle counts.

Data provenance
---------------
pqm4 speed benchmarks, "clean" implementations, measured at 24 MHz (the pqm4
convention, chosen so flash wait-states do not distort cycle counts):
    https://github.com/mupq/pqm4  (benchmarks.md, retrieved 2026-07)
Falcon-512 does NOT ship a clean implementation that fits pqm4's RAM; its row
uses the optimized `m4-ct` constant-time implementation and is flagged as
such (this memory-fit fact is itself evidence for the device matrix below).

Cross-platform numbers are QUALITATIVE. Cycle counts are the honest primary
metric (clock-independent); milliseconds are shown at 24 MHz (as pqm4 reports)
with the caveat that a 168 MHz STM32F407 deployment is ~5-7x faster but incurs
flash wait-states, so it is NOT a clean 7x.

Outputs (../results/):
    pqm4_comparison.csv       desktop vs M4, per operation, + base-paper check
    device_class_matrix.csv   RFC 7228 class -> scheme suitability
"""

from __future__ import annotations

import csv
from pathlib import Path

import pandas as pd

RESULTS = Path(__file__).resolve().parent.parent / "results"
PQM4_CLOCK_MHZ = 24
PQM4_SOURCE = "pqm4 benchmarks.md, clean impl, 24 MHz (github.com/mupq/pqm4)"

# --------------------------------------------------------------------------
# Published pqm4 cycle counts (clean impl @ 24 MHz), retrieved 2026-07.
# (keygen, op2, op3) where op2/op3 = encaps/decaps for KEMs, sign/verify for
# signatures. Falcon-512 = optimized m4-ct (clean ref does not fit RAM).
# --------------------------------------------------------------------------
PQM4_CYCLES = {
    # KEMs
    "ML-KEM-512 (Kyber512)":  dict(kind="KEM", keygen=595_793,   op2=700_605,     op3=888_653,     impl="clean"),
    "ML-KEM-768 (Kyber768)":  dict(kind="KEM", keygen=988_722,   op2=1_138_225,   op3=1_387_984,   impl="clean"),
    # Signatures
    "ML-DSA-44 (Dilithium2)": dict(kind="Signature", keygen=1_874_405, op2=7_925_955,   op3=2_063_096,   impl="clean"),
    "ML-DSA-65 (Dilithium3)": dict(kind="Signature", keygen=3_205_533, op2=12_359_056,  op3=3_377_305,   impl="clean"),
    "Falcon-512":             dict(kind="Signature", keygen=72_000_000, op2=22_000_000,  op3=255_000,     impl="opt m4-ct*"),
    "SPHINCS+-SHA2-128f":     dict(kind="Signature", keygen=15_742_990, op2=368_575_228, op3=21_923_628,  impl="clean"),
    "SPHINCS+-SHA2-128s":     dict(kind="Signature", keygen=1_007_731_522, op2=7_657_558_168, op3=7_471_794, impl="clean"),
}

OP_NAMES = {"KEM": ("keygen", "encapsulate", "decapsulate"),
            "Signature": ("keygen", "sign", "verify")}

# Base paper's SIMULATED latencies (Narayanan et al. 2026, Table 6 + text), ms.
BASE_PAPER_SIM = {
    ("ML-KEM-512 (Kyber512)", "encapsulate"): 28,
    ("ML-KEM-512 (Kyber512)", "decapsulate"): 31,
    ("ML-DSA-44 (Dilithium2)", "sign"): 42,
    ("ML-DSA-44 (Dilithium2)", "verify"): 36,
}

# The paper's own declared device clock (its Table 3: "ARM Cortex-M4 (120 MHz)").
# Comparing its Table 6 against pqm4 milliseconds at pqm4's 24 MHz convention
# would be a CLOCK-MISMATCH ERROR, so we do two clock-fair things instead:
#   1. normalise pqm4 cycles to the paper's own 120 MHz, and
#   2. compute the IMPLIED CLOCK each Table 6 entry would need in order to be a
#      real cycle-accurate measurement (cycles / time).
# (2) is the decisive test because it is clock-INDEPENDENT: if the four entries
# imply four wildly different clocks, they cannot all be measurements of one
# device at one frequency, whatever that frequency is.
PAPER_CLOCK_MHZ = 120


def cycles_to_ms(cycles: int, mhz: int = PQM4_CLOCK_MHZ) -> float:
    return cycles / (mhz * 1000)


def build_comparison() -> pd.DataFrame:
    desktop = pd.read_csv(RESULTS / "timings.csv")
    # desktop median per (algorithm, operation)
    dmed = {(r.algorithm, r.operation): r.median_ms
            for r in desktop.itertuples()}

    rows = []
    for alg, d in PQM4_CYCLES.items():
        kind = d["kind"]
        op_labels = OP_NAMES[kind]
        for cyc_key, op in zip(("keygen", "op2", "op3"), op_labels):
            cycles = d[cyc_key]
            m4_ms = cycles_to_ms(cycles)
            desk_ms = dmed.get((alg, op))
            slowdown = round(m4_ms / desk_ms, 0) if desk_ms else ""
            paper = BASE_PAPER_SIM.get((alg, op), "")
            rows.append(dict(
                algorithm=alg, kind=kind, operation=op, impl=d["impl"],
                m4_cycles=cycles,
                m4_ms_at_24mhz=round(m4_ms, 2),
                m4_ms_at_paper_120mhz=round(cycles_to_ms(cycles, PAPER_CLOCK_MHZ), 2),
                desktop_ms=desk_ms if desk_ms is not None else "",
                m4_vs_desktop_x=slowdown,
                base_paper_sim_ms=paper,
                # How many times the paper's figure is of pqm4 AT THE PAPER'S
                # OWN 120 MHz. >1 = paper slower (pessimistic); <1 = optimistic.
                paper_over_pqm4_at_120mhz=(
                    round(paper / cycles_to_ms(cycles, PAPER_CLOCK_MHZ), 2)
                    if paper else ""),
                # Clock-independent test: the frequency this entry would need
                # in order to be a genuine cycle-accurate measurement.
                implied_clock_mhz=(round(cycles / (paper * 1000), 1)
                                   if paper else ""),
            ))
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------
# RFC 7228 device-class recommendation matrix
# --------------------------------------------------------------------------
# RFC 7228 constrained-device classes (data-size / code-size, approx):
#   Class 0: << 10 KiB RAM, << 100 KiB Flash  (motes; cannot run PQC alone)
#   Class 1: ~ 10 KiB RAM,  ~ 100 KiB Flash   (CoAP-class; PQC only with care)
#   Class 2: ~ 50 KiB RAM,  ~ 250 KiB Flash   (can run a PQC stack)
#   > Class 2: gateways / edge servers        (anything, incl. hybrids)
# The base paper's simulated node (64 KiB SRAM / 256 KiB Flash, Cortex-M4F)
# sits at the top of Class 2.
#
# Suitability blends pqm4 latency (@24 MHz), published peak-stack usage, and
# key/sig wire size (from our sizes.csv). Stack figures are approximate,
# from pqm4 memory benchmarks; verify against the live table for a thesis.

DEVICE_MATRIX = [
    # (scheme, role, class0, class1, class2, rationale)
    ("ML-KEM-512", "KEM",
     "no", "yes*", "yes",
     "~3 KB stack, sub-40 ms/op @24 MHz; the practical KEM floor. *Class 1 fits but 800 B key + 768 B ct fragment heavily over 802.15.4."),
    ("ML-KEM-768", "KEM",
     "no", "caution", "yes",
     "TLS-recommended level; ~5 KB stack, ~58 ms decaps. Larger wire cost (1.1 KB) strains Class 1 radios."),
    ("ML-DSA-44", "signature",
     "no", "caution", "yes",
     "~50+ KB peak stack for signing is the binding constraint on Class 1; sign ~330 ms @24 MHz. Fine on Class 2 (paper's node)."),
    ("Falcon-512", "signature",
     "no", "verify-only", "yes (verify-heavy)",
     "Verify is tiny (~11 ms, ~655 B sig - variable-length compressed encoding, 752 B max) -> great for firmware-update verification on constrained nodes; keygen (~3 s) and FP-heavy signing belong on a gateway."),
    ("SPHINCS+-128s", "signature",
     "no", "no", "verify-only",
     "Signing is minutes on M4; only verification (~0.3 s) is deployable. Conservative security when signing happens off-device."),
    ("SPHINCS+-128f", "signature",
     "no", "no", "caution",
     "Sign ~15 s @24 MHz and 17 KB signature; impractical on-device. Value is hash-only security for rarely-signing roots."),
    ("Hybrid X25519+ML-KEM-768", "KEM",
     "no", "no", "yes",
     "+64 B total on the wire (+32 B each way) and sub-ms over pure ML-KEM (Phase 3); the cheap insurance a Class 2 node should take. Below Class 2, offload to a gateway."),
    ("RSA-2048 / ECDH (classical)", "both",
     "ECDH only", "yes", "yes",
     "Quantum-BROKEN (baseline only). ECC is light on-device; RSA keygen (tens of ms + heavy tail) should never run on the device."),
]


def write_device_matrix():
    out = RESULTS / "device_class_matrix.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["scheme", "role", "RFC7228_class0", "RFC7228_class1",
                    "RFC7228_class2", "rationale"])
        w.writerows(DEVICE_MATRIX)
    print(f"wrote {out}")


def main():
    comp = build_comparison()
    comp_path = RESULTS / "pqm4_comparison.csv"
    comp.to_csv(comp_path, index=False)
    print(f"wrote {comp_path}\n")

    # Headline console summary
    print("Desktop (clean C) vs Cortex-M4 @24 MHz (clean C, same source):")
    for r in comp.itertuples():
        if r.desktop_ms != "" and r.impl == "clean":
            print(f"  {r.algorithm:24s} {r.operation:12s} "
                  f"desktop {float(r.desktop_ms):8.3f} ms  ->  "
                  f"M4 {r.m4_ms_at_24mhz:9.2f} ms  ({r.m4_vs_desktop_x:.0f}x)")

    print(f"\nBase-paper SIMULATED vs pqm4, at the paper's OWN declared clock "
          f"({PAPER_CLOCK_MHZ} MHz, its Table 3):")
    for r in comp.itertuples():
        if r.base_paper_sim_ms != "":
            direction = "pessimistic" if r.paper_over_pqm4_at_120mhz > 1 else "OPTIMISTIC"
            print(f"  {r.algorithm:24s} {r.operation:12s} "
                  f"paper {r.base_paper_sim_ms:>3} ms  vs  pqm4 "
                  f"{r.m4_ms_at_paper_120mhz:7.2f} ms  "
                  f"-> paper is {r.paper_over_pqm4_at_120mhz:5.2f}x pqm4 ({direction})")

    print("\nCLOCK-INDEPENDENT TEST — the clock each Table 6 entry would need")
    print("to be a genuine cycle-accurate measurement of one M4:")
    implied = []
    for r in comp.itertuples():
        if r.base_paper_sim_ms != "":
            implied.append(r.implied_clock_mhz)
            print(f"  {r.algorithm:24s} {r.operation:12s} "
                  f"{r.m4_cycles:>11,} cycles / {r.base_paper_sim_ms:>3} ms "
                  f"-> {r.implied_clock_mhz:7.1f} MHz")
    if implied:
        print(f"  => implied clocks span {min(implied):.1f}-{max(implied):.1f} MHz "
              f"({max(implied)/min(implied):.1f}x spread). No single processor at a"
              f"\n     single frequency produces that, so Table 6 cannot be "
              f"cycle-accurate\n     measurements of one device - whatever clock is assumed.")

    write_device_matrix()
    print(f"\nsource: {PQM4_SOURCE}")


if __name__ == "__main__":
    main()
