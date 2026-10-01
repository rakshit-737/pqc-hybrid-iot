# Hybrid Post-Quantum Cryptography for IoT

Gap analysis and extension of the PQShield-IoT framework. The project measures 16 classical and post-quantum schemes on real hardware, prices classical, post-quantum and hybrid handshakes in bytes on the wire, tests for timing side channels, and cross-checks the paper's numbers against pqm4 Cortex-M4 data. It also proposes AHQR, a protocol that combines classical and post-quantum cryptography for constrained devices.

College Cryptography and Network Security project. Base paper:

> Narayanan et al., "Quantum-Resilient IoT Communication Framework Using Post-Quantum Cryptography and Blockchain for Secure Edge Devices", *Iranian J. Sci. Technol. Trans. Electr. Eng.* 50:203–221 (2026). [doi:10.1007/s40998-025-01002-1](https://doi.org/10.1007/s40998-025-01002-1)

## Gaps in the base paper and what this project adds

| # | Gap in PQShield-IoT | Contribution here | Evidence |
|---|---|---|---|
| 1 | Pure PQC only, no hybrid | Socket handshake: classical vs PQ vs hybrid | Hybrid costs +64 B and ~0.6 ms over pure ML-KEM-768 |
| 2 | Results simulated; no measurement method reported | Benchmark suite, 16 schemes, real libraries | ML-KEM-512 encaps 0.154 ms vs ECDH P-256 0.143 ms |
| 3 | Dilithium2 only | ML-DSA vs Falcon vs SPHINCS+, time and size | Falcon verify 0.066 ms; SPHINCS+-128s sign 1.19 s |
| 4 | No side-channel analysis | Tag-compare leak demo + ML-KEM decaps timing test | Leak r = +1.000; decaps \|z\| ≤ 1.5 |
| 5 | (integrative) | pqm4 Cortex-M4 extrapolation + RFC 7228 device matrix | Paper's latencies imply 25–189 MHz clocks |
| 6 | Claims forward secrecy with static KEM keys | Ephemeral handshake | A leaked `sk_kem` exposes every recorded session |
| 7 | Key rotation (Eq. 10) re-hashes the same shared secret, so a compromised device never recovers | AHQR dual-cadence hybrid ratchet | After a leak, AHQR (Q=256) exposes 13.8 % of a session against a quantum attacker; static design 100 % |
| 8 | Authentication rests on Dilithium2 alone | Composite Ed25519 AND ML-DSA-44 signature | Forgery needs both schemes broken |
| 9 | Adaptation driven by computation, energy, latency and throughput (Eqs. 12–13), not by a threat model | Mosca-driven policy | Deferring PQ signatures cuts a handshake from 91 to 31 frames |

## AHQR: Adaptive Hybrid Quantum-Resilient Ratchet

AHQR runs classical and post-quantum cryptography side by side, each at its own cadence, so that expensive PQ material is sent only as often as the threat model requires.

| Layer | Classical part | Post-quantum part |
|---|---|---|
| Handshake | X25519 key exchange, Ed25519 signature | ML-KEM key exchange, ML-DSA-44 signature; both signatures must verify |
| Ratchet | X25519 step every C messages (+84 B) | Hybrid X25519 + ML-KEM step every Q messages (+2.3 KB) |
| Policy | | Mosca's inequality picks KEM level, signature mode, C and Q per device class and data shelf-life |

Every message also gets its own key from a one-way chain, which gives forward secrecy at no byte cost.

Results over a 1,000-message session:

* At the same recovery speed as re-running a full hybrid handshake every 16 messages (Q = 16), AHQR sends 2.5× fewer bytes and 2.3× fewer radio frames.
* With Q = 256, AHQR needs 20 % more frames than the base paper's static-key design. It adds forward secrecy, hybrid protection, and recovery after a device compromise within 256 messages, even against a quantum attacker.
* Recovery assumes the attacker is passive at the next ratchet step, the same assumption Signal's double ratchet makes.

Design, security argument and limitations: [AHQR.md](AHQR.md).

## Results

Figures are generated from the CSVs in [`results/`](results/) by [`plot_results.py`](code/plot_results.py) (fig1–fig7) and [`ahqr_evaluation.py`](code/ahqr_evaluation.py) (fig8–fig11).

### AHQR

![Share of message keys each adversary recovers](results/fig8_ahqr_security.png)

<p align="center"><img src="results/fig9_ahqr_link_cost.png" width="85%" alt="AHQR link cost"></p>

| Design | Bytes | 802.15.4 frames | Forward secrecy | Recovery after a leak, quantum attacker |
|---|---:|---:|---|---|
| PQShield-style (static ML-KEM key) | 58,536 | 1,082 | no | never |
| Hybrid handshake, static key | 59,304 | 1,091 | no | never |
| Classical ratchet (Signal-like) | 57,400 | 1,128 | yes | never |
| Hybrid re-handshake every 16 | 512,152 | 6,733 | yes | within 16 messages |
| AHQR (C=16, Q=16) | 205,376 | 2,951 | yes | within 16 messages |
| AHQR (C=16, Q=256) | 71,328 | 1,299 | yes | within 256 messages |

<table><tr>
<td width="50%"><img src="results/fig10_ahqr_tradeoff.png" alt="Cadence trade-off"></td>
<td width="50%"><img src="results/fig11_ahqr_timings.png" alt="AHQR operation timings"></td>
</tr><tr>
<td align="center"><sub>Mean exposure after a leak is about Q/2 messages; overhead falls roughly as 1/Q</sub></td>
<td align="center"><sub>Hybrid ratchet step about 1.6 ms; each message about 0.04 ms</sub></td>
</tr></table>

### Primitive benchmarks

<table><tr>
<td width="50%"><img src="results/fig1_kem_timings.png" alt="KEM timings"></td>
<td width="50%"><img src="results/fig2_sig_timings.png" alt="Signature timings"></td>
</tr><tr>
<td align="center"><sub>KEM timings: ML-KEM-512 encapsulation is within 8 % of ECDH P-256</sub></td>
<td align="center"><sub>Signature timings: ML-DSA, Falcon and SPHINCS+ against ECDSA, Ed25519 and RSA</sub></td>
</tr><tr>
<td><img src="results/fig3_sizes.png" alt="Sizes"></td>
<td><img src="results/fig4_sign_tradeoff.png" alt="Signature trade-off"></td>
</tr><tr>
<td align="center"><sub>Key, ciphertext and signature sizes</sub></td>
<td align="center"><sub>Signature speed against size</sub></td>
</tr></table>

### Handshake, side channels and Cortex-M4 check

<table><tr>
<td width="50%"><img src="results/fig5_handshake.png" alt="Handshake"></td>
<td width="50%"><img src="results/fig6_timing.png" alt="Timing analysis"></td>
</tr><tr>
<td align="center"><sub>Classical (202 B), PQ (2,410 B) and hybrid (2,474 B) handshakes over TCP</sub></td>
<td align="center"><sub>Naive tag compare leaks (r = +1.000); ML-KEM decapsulation shows no leak (|z| ≤ 1.5)</sub></td>
</tr></table>

<p align="center"><img src="results/fig7_pqm4.png" width="80%" alt="pqm4 extrapolation"><br>
<sub>pqm4 Cortex-M4 extrapolation: the paper's four latencies imply four different clock speeds on one 120 MHz device</sub></p>

## Headline findings

1. **On CPU-class hardware, PQC's cost is bytes on the wire, not compute.** ML-KEM-512 encapsulation (0.154 ms) is within 8 % of assembly-optimised ECDH P-256 (0.143 ms), even though the PQC code is portable C. The gap is size: 768–2420 B against 32–65 B, which fragments over 802.15.4 frames that carry 81–102 B of payload depending on link-layer security.
2. **A hybrid is nearly free insurance.** X25519 + ML-KEM-768, the TLS 1.3 group, adds only 64 B and about 0.6 ms over pure ML-KEM-768.
3. **A naive tag comparison leaks; ML-KEM decapsulation does not.** Pearson r = +1.000 for the early-exit loop; |z| ≤ 1.5 for decapsulation of valid against corrupted ciphertexts.
4. **The base paper's four reported latencies imply four different processor clocks (25 / 29 / 189 / 57 MHz)** when divided into measured pqm4 cycle counts. That is a 7.5× spread on one declared 120 MHz device, so they cannot be cycle-accurate measurements whatever clock is assumed.
5. **The paper claims forward secrecy but uses static KEM keys**, which do not provide it. The ephemeral handshake here demonstrates the difference.
6. **Periodic PQ re-keying is where the bandwidth goes, and AHQR turns it into a parameter.** A hybrid step every 256 messages costs 19 B per message; re-handshaking every 16 messages costs 460 B per message.
7. **Confidentiality needs PQ now; authentication can wait.** Recorded traffic can be decrypted later, but a handshake can only be forged while it runs. Deferring PQ signatures until a quantum computer is near cuts a mutually authenticated handshake from 91 to 31 frames.

## Start here

New to the topic? Read [SIMPLE_EXPLANATION.md](SIMPLE_EXPLANATION.md) first: the whole project in plain language, no background assumed. Then [EXPLANATION.md](EXPLANATION.md), the complete technical story from the problem statement through every phase, and [AHQR.md](AHQR.md) for the protocol. [VIVA.md](VIVA.md) is the quick-reference defence pack.

## Layout

```
CNS/
├── EXPLANATION.md              complete walkthrough
├── SIMPLE_EXPLANATION.md       plain-language version
├── AHQR.md                     AHQR protocol: design, evaluation, limitations
├── VIVA.md                     quick-reference defence pack
├── PROJECT_REPORT.html         illustrated self-contained report (open in browser)
├── literature-survey/
│   └── survey.md               six-thread survey and gap synthesis
├── code/
│   ├── benchmark_pqc.py            Gaps 2+3: primitive benchmarks
│   ├── hybrid_handshake.py         Gap 1: classical / PQ / hybrid handshake
│   ├── timing_analysis.py          Gap 4: side-channel analysis
│   ├── pqm4_extrapolation.py       Gap 5: M4 extrapolation + device matrix
│   ├── ahqr.py                     Gaps 7–9: AHQR protocol, adversary simulator, policy
│   ├── ahqr_evaluation.py          AHQR experiments (fig8–fig11)
│   ├── test_ahqr.py                AHQR security-property tests
│   ├── test_handshake_security.py  handshake fail-closed tests
│   ├── plot_results.py             fig1–fig7
│   ├── verify_report_numbers.py    checks report numbers against the CSVs
│   ├── build_html_report.py        regenerates PROJECT_REPORT.html from the CSVs
│   └── *_EXPLAINED.md              line-by-line notes per script
├── results/                    all CSVs, fig1–fig11, system_info.txt
├── report/
│   ├── report.tex              IEEE (IEEEtran); compile on Overleaf
│   ├── references.bib
│   └── README.md               compile instructions and figure manifest
├── review1/, review2/          review submissions and diagrams
└── SETUP.md                    environment, troubleshooting, reproduction
```

## Reproduce

```powershell
pip install -r requirements.txt
cd code
python benchmark_pqc.py             # Gaps 2+3 (~2-4 min)
python hybrid_handshake.py          # Gap 1 (~30 s)
python timing_analysis.py           # Gap 4 (~1-2 min)
python pqm4_extrapolation.py        # Gap 5 (instant; uses cited pqm4 data)
python plot_results.py              # fig1–fig7
python ahqr_evaluation.py           # Gaps 7–9: fig8–fig11
python test_handshake_security.py   # handshake fail-closed and hybrid properties
python test_ahqr.py                 # AHQR security properties (12 tests)
python verify_report_numbers.py     # checks report numbers against the CSVs
python build_html_report.py         # regenerates PROJECT_REPORT.html from the CSVs
```

Tested with Python 3.14.3, pqcrypto 0.4.0 (PQClean, portable C), cryptography 49.0.0 (OpenSSL), matplotlib 3.10.8 and pandas 3.0.1 on Windows 11 (Intel i5-13500H).

Two-terminal handshake demo: `python hybrid_handshake.py --server` in one terminal, `python hybrid_handshake.py --client --mode hybrid --level 768` in another.

> **Before submitting, do one clean benchmark run.** Close the browser and other heavy apps, then run `python benchmark_pqc.py` (**not** `--quick`) and `python verify_report_numbers.py`. Background CPU load makes every timing about 2.5× slower (see SETUP.md), and `--quick` overwrites the canonical CSVs with low-sample data. Sizes and bytes are unaffected either way. If the verifier still reports drift on an idle machine, update the timing columns of Tables I and III in `report/report.tex` to match the CSVs; the conclusions are all relative and do not change. Then run `python build_html_report.py` so `PROJECT_REPORT.html` picks up the fresh numbers. (Current tables reflect the 2026-07-27 run, measured with the browser open, about 1.6× slower than an idle machine, uniformly.) `ahqr_evaluation.py` re-measures `ahqr_timings.csv` and fig11 on every run; its byte, frame and security results are deterministic.

## Quality process

The benchmark suite and the Phase 3–5 artifacts each went through a multi-agent adversarial review (independent reviewer lenses plus majority-vote verification). The first pass found and fixed 22 issues: a silent `--quick` bug, a P-core-pinning ctypes bug, over-stated naming, and a decaps-vs-encaps measurement artifact. See the `*_EXPLAINED.md` docs for the stories.

## Critical-reading notes on the base paper

* Results are simulated, not hardware-measured. This is the basis of Gaps 2 and 5, not an accusation. The reality check quantifies where the simulation is accurate (Kyber) and where it is optimistic (Dilithium sign, about 8×).
* The platform is described inconsistently: Hyperledger Fabric (Table 3), a Sawtooth validator (§3.6) and a "DAG-based ledger" (same section). The node count varies (15 in §3.6, 50–200 elsewhere). These are raised as limitations to investigate. The blockchain layer is outside this project's cryptographic scope.

## Limitations

AHQR endpoints are simulated in-process: the bytes are real, but no radio is involved, and frame counts ignore 6LoWPAN/UDP headers. Its recovery after a compromise holds against an attacker who is passive at the next ratchet step. Its security argument is informal, not a machine-checked proof. Timings come from an x86 laptop; Cortex-M figures for the primitives are extrapolated from pqm4.

## License

Code and documentation: [MIT](LICENSE). The base paper is not redistributed here; cite it by DOI.
