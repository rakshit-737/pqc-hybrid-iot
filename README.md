# Post-Quantum Cryptography for IoT — Gap Analysis of PQShield-IoT

College cryptography & network security project (internals). Builds on and
critically extends:

> Narayanan et al., "Quantum-Resilient IoT Communication Framework Using
> Post-Quantum Cryptography and Blockchain for Secure Edge Devices",
> *Iranian J. Sci. Technol. Trans. Electr. Eng.* 50:203–221 (2026).
> DOI: 10.1007/s40998-025-01002-1  → `base-paper/`

## Gaps in the base paper → this project's contributions

| # | Gap in PQShield-IoT | Contribution here | Status |
|---|---------------------|-------------------|--------|
| 1 | Pure PQC only — no hybrid classical+PQC (real migrations use hybrids, e.g. TLS 1.3 `X25519MLKEM768`) | Socket handshake: pure X25519 vs pure ML-KEM vs hybrid; latency + bytes-on-wire | ✅ done |
| 2 | Results **simulated** (NS-3/Contiki-NG); latencies reported with no measurement methodology (no host, timing method, repetition count or variance) | Real benchmark suite (PQClean via `pqcrypto`, OpenSSL via `cryptography`), 16 schemes | ✅ done |
| 3 | Fixed on Dilithium2; no Falcon / SPHINCS+ comparison | ML-DSA vs Falcon vs SPHINCS+ (time **and** size + trade-off figure) | ✅ done |
| 4 | No side-channel / timing analysis | Tag-comparison leak demo + ML-KEM decaps timing-oracle test (interleaved, pooled) | ✅ done |
| 5 | — (integrative) | pqm4 Cortex-M4 extrapolation + simulated-vs-measured reality check + RFC 7228 device matrix | ✅ done |

## Headline findings (defensible in viva)

1. **On CPU-class hardware, PQC's cost is bytes-on-wire, not compute.**
   ML-KEM-512 encaps (0.154 ms) sits within 8% of optimized-assembly ECDH P-256
   (0.143 ms), despite PQC running unoptimized portable C. The gap is size:
   768–2420 B vs 32–65 B, which fragments over 802.15.4's ~100 B frames.
2. **Hybrid is nearly-free insurance.** X25519+ML-KEM-768 (the TLS 1.3 group)
   adds only +64 B and ~0.6 ms over pure ML-KEM-768.
3. **A naive tag comparison leaks; ML-KEM decapsulation does not.** Pearson
   r=+1.000 for the early-exit loop; |z|≤1.5 for decaps valid-vs-corrupted.
4. **The base paper's four reported latencies imply four different processor
   clocks (25 / 29 / 189 / 57 MHz)** when divided into measured pqm4 cycle
   counts — a 7.5× spread on one declared 120 MHz device, so they cannot be
   cycle-accurate measurements whatever clock is assumed.
5. **The paper claims forward secrecy but uses static KEM keys**, which does not
   provide it; our ephemeral handshake demonstrates the difference.

## Start here

**Know nothing yet?** Read **[SIMPLE_EXPLANATION.md](SIMPLE_EXPLANATION.md)**
first — the whole project in plain language, no background assumed. Then
**[EXPLANATION.md](EXPLANATION.md)** — the complete technical story from the
problem statement through every phase. Then [VIVA.md](VIVA.md) for
quick-reference defence prep.

## Layout

```
CNS/
├── EXPLANATION.md              ← the complete walkthrough (start here)
├── VIVA.md                     quick-reference defence pack
├── PROJECT_REPORT.html         illustrated self-contained report (open in browser)
├── base-paper/                 the source PDF
├── literature-survey/
│   └── survey.md               6-thread survey → gap synthesis
├── code/
│   ├── benchmark_pqc.py            Gap 2+3: primitive benchmarks
│   ├── hybrid_handshake.py         Gap 1: classical/PQ/hybrid handshake
│   ├── timing_analysis.py          Gap 4: side-channel analysis
│   ├── pqm4_extrapolation.py       Gap 5: M4 extrapolation + device matrix
│   ├── plot_results.py             all figures (fig1–fig7)
│   ├── build_html_report.py        regenerates PROJECT_REPORT.html from CSVs
│   └── *_EXPLAINED.md              line-by-line viva notes per script
├── results/                    all CSVs + fig1–fig7 PNGs + system_info.txt
├── report/
│   ├── report.tex              IEEE (IEEEtran) — compile on Overleaf
│   ├── references.bib
│   ├── PROJECT_REPORT_template.html  HTML report template (numbers filled from CSVs)
│   └── README.md               compile instructions + figure manifest
└── SETUP.md                    environment + troubleshooting + reproduction
```

## Reproduce everything

```powershell
pip install pqcrypto cryptography matplotlib pandas
cd code
python benchmark_pqc.py         # Gap 2+3   (~2-4 min)
python hybrid_handshake.py      # Gap 1     (~30 s)
python timing_analysis.py       # Gap 4     (~1-2 min)
python pqm4_extrapolation.py    # Gap 5     (instant; uses cited pqm4 data)
python plot_results.py          # fig1–fig7
python test_handshake_security.py   # verifies fail-closed + hybrid properties
python verify_report_numbers.py     # checks report numbers vs the CSVs
python build_html_report.py         # regenerates PROJECT_REPORT.html from the CSVs
```

> ⚠️ **Before submitting, do one clean benchmark run.** Close your browser and
> other heavy apps first, then run `python benchmark_pqc.py` (**not**
> `--quick`) and `python verify_report_numbers.py`. Background CPU load makes
> every timing ~2.5× slower (see SETUP.md), and `--quick` overwrites the
> canonical CSVs with low-sample data. Sizes/bytes are unaffected either way.
> If the verifier still reports drift on an idle machine, update the timing
> columns of Tables I and III in `report/report.tex` to match the CSVs — the
> conclusions are all relative and do not change. Then run
> `python build_html_report.py` so `PROJECT_REPORT.html` picks up the fresh
> numbers automatically. (Current tables reflect the 2026-07-27 run, measured
> with browser open — ~1.6× slower than an idle machine, uniformly.)

Two-terminal handshake demo: `python hybrid_handshake.py --server` in one
terminal, `python hybrid_handshake.py --client --mode hybrid --level 768` in
another. Environment/troubleshooting: [SETUP.md](SETUP.md). Report build:
[report/README.md](report/README.md).

## Quality process

The benchmark suite and the Phase 3–5 artifacts each went through a multi-agent
**adversarial review** (independent reviewer lenses + majority-vote
verification); the first pass found and fixed 22 issues (a silent `--quick`
bug, a P-core-pinning ctypes bug, over-stated naming, a decaps-vs-encaps
measurement artifact). See the `*_EXPLAINED.md` docs for the stories.

## Critical-reading notes on the base paper (constructive)

* Results are **simulated**, not hardware-measured — the basis of Gap 2/5, not
  an accusation. Our reality-check quantifies where the simulation is accurate
  (Kyber) and where it is optimistic (Dilithium sign, ~8×).
* Platform described inconsistently: Hyperledger **Fabric** (Table 3),
  **Sawtooth** validator (§3.6), "DAG-based ledger" (same section); node count
  varies (15 in §3.6 vs 50–200 elsewhere). Raised as limitations to
  investigate. The blockchain layer is outside this project's crypto scope.
```
