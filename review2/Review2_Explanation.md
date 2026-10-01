# Review 2: Presenter's Guide

This guide goes with `CNS_Review2_Presentation.pptx`. It covers what to say on
every slide, which code to open and what to point at, what each result means,
and the questions faculty are likely to ask. Each slide also has short speaker
notes in the `.pptx` (View → Notes).

**Files in this folder**

| File | What it is |
|---|---|
| `CNS_Review2_Presentation.pptx` | The 24-slide deck (navy-and-grey report style; all charts are native and editable) |
| `methodology_diagram.png` / `.svg` | The detailed methodology diagram (slide 6). Use the PNG in documents; the SVG is vector and zooms without blur |
| `protocol_diagram.png` | Earlier image of the handshake message flow, used in the Review 2 docx. The deck redraws it natively on slide 12 |
| `CNS_Review2_Rakshit.docx` | The written Review 2 report (the source for every number in the deck) |
| `Review2_Explanation.md` | This file |

**Suggested timing:** about 15 minutes of talk plus a 2-minute live demo.
Spend the most time on slide 4 (the novel claim), slide 6 (methodology) and
the four code walkthroughs (slides 8, 13, 15, 18).

---

## Contents

1. [The 60-second opening](#1-the-60-second-opening)
2. [The novel claim, in plain words](#2-the-novel-claim-in-plain-words)
3. [The methodology diagram, stage by stage](#3-the-methodology-diagram-stage-by-stage)
4. [Slide-by-slide script](#4-slide-by-slide-script)
5. [Code walkthrough guide: what to open and what to point at](#5-code-walkthrough-guide)
6. [Results and outputs: what each one means](#6-results-and-outputs)
7. [Live demo](#7-live-demo)
8. [Questions faculty are likely to ask](#8-likely-questions-and-answers)
9. [Wording traps: say this, not that](#9-wording-traps)
10. [Before the review: checklist](#10-before-the-review-checklist)

---

## 1. The 60-second opening

> My base paper, PQShield-IoT by Narayanan et al., builds a quantum-resistant
> IoT framework from Kyber512, Dilithium2, AES-256-GCM and a permissioned
> blockchain. The design is sound, but the evaluation is weak: every
> performance number is simulated in NS-3 and Contiki-NG, and the paper never
> says how its latencies were measured. There is no host, timer, repetition
> count or variance. It also uses only one signature scheme, uses pure
> post-quantum instead of hybrid key exchange, and does no side-channel
> analysis.
>
> In Review 1 I proposed five phases to close those gaps. In this review I show
> that all five are implemented and producing results. The headline is that
> once you measure real code, post-quantum cryptography is not expensive to
> compute. Its real cost is the number of bytes it puts on a constrained radio.
> I also show that the paper's own reported latencies cannot all be
> measurements of one device.

---

## 2. The novel claim, in plain words

The claim on slide 4 has three parts. Know each one well enough to explain it
without the slide.

### Part 1: "PQC's cost for IoT is bytes on the wire, not computation"

- On the laptop, ML-KEM-512 encapsulation takes **0.154 ms** and classical ECDH
  P-256 takes **0.143 ms**, so they are within 8% of each other.
- That comparison actually *favours* classical: the ECDH code is hand-optimised
  OpenSSL assembly, while the ML-KEM code is portable C with no AVX2. So the
  real gap is even smaller than 8%.
- The size gap is enormous. One ML-KEM-512 exchange sends **1,568 bytes**
  (800 B public key + 768 B ciphertext). X25519 sends **64 bytes**.
- An IEEE 802.15.4 radio frame (the common low-power IoT radio) carries about
  **100 bytes** of payload. So ML-KEM-512 needs about 16 frames where X25519
  needs one. Every extra frame costs radio energy, adds loss risk and adds
  latency. **On a constrained network, fragmentation is the bottleneck, not CPU.**
- Caveat: on a microcontroller (Cortex-M4), compute *does* matter. That is why
  Phase 5 exists and why the device-class matrix treats MCU classes separately.

### Part 2: "Hybrid protection is nearly free"

- A hybrid key exchange runs X25519 *and* ML-KEM and combines both secrets, so
  an attacker must break both. This is what TLS 1.3 deploys today
  (`X25519MLKEM768`).
- Hybrid-768 sends **2,474 B**, pure ML-KEM-768 sends **2,410 B**. The
  difference is **+64 B** (32 B each direction, one X25519 public key each
  way), plus about **0.6 ms**.
- Going from classical to post-quantum at all costs about **2.2 KB**. Once you
  have paid that, the classical safety net costs almost nothing. So the base
  paper's pure-PQ choice is hard to justify: if ML-KEM were ever broken, a
  pure-PQ system has no fallback.

### Part 3: "The base paper's latencies are internally inconsistent"

- The paper reports four latencies (Kyber512 encaps 28 ms and decaps 31 ms,
  Dilithium2 sign 42 ms and verify 36 ms) and declares a 120 MHz Cortex-M4.
- pqm4, the standard public benchmark, gives the *measured cycle counts* for
  the same operations on a real Cortex-M4.
- **Cycles ÷ time = clock frequency.** So for each reported latency I compute
  the clock the device would need for that number to be a real measurement:
  25.0, 28.7, 188.7 and 57.3 MHz.
- One device has one clock. Four figures that imply four different clocks, a
  7.5× spread, cannot all be cycle-accurate measurements, *whatever clock the
  authors meant*. That is what makes the test strong: it assumes no clock at all.

### Plus: two dimensions the paper leaves out entirely

- **Timing side-channels.** A naive comparison leaks the secret byte by byte
  (Pearson r = +1.000). ML-KEM decapsulation is constant-time. A deliberately
  flawed measurement design invents a leak that isn't there.
- **Forward secrecy.** The paper claims it but uses static KEM keys, which
  cannot provide it. My handshake uses ephemeral keys and does provide it.

---

## 3. The methodology diagram, stage by stage

File: `methodology_diagram.png` (slide 6). Read it left to right: five
numbered stages, each in its own grey column.

**① Problem framing.** A critical reading of the base
paper plus a literature survey across six research threads
(`literature-survey/survey.md`) produced a *gap register*: G1 to G5.
G6, the forward-secrecy contradiction, has a dashed red tag because it was
found later, while reviewing the paper's security claims.

**② Instruments.** These are the inputs every experiment draws from:
- *PQClean via `pqcrypto` 0.4.0*: the same reference C code the base paper
  cites, so we measure what they say they used.
- *OpenSSL via `cryptography` 49.0.0*: the classical baseline.
- *pqm4*: published, measured Cortex-M4 cycle counts. We have no hardware, so
  this is how we get from laptop to microcontroller honestly.
- *RFC 7228 + IEEE 802.15.4*: the standard definitions of constrained device
  classes and the ~100 B radio frame.
- *Test host*: the laptop, pinned to one performance core at HIGH priority.

**③ Experiments and analysis.** There is one row per phase. The left box
(navy outline, with the gap tag it closes) is *what we run*; the grey box to
its right is *what we measure and which file it writes*. The shaded band under
all five rows is the **controlled measurement protocol**. Every phase uses it, and
it is the direct answer to G2 (the paper gives no methodology; ours is
explicit). Its nine elements:

| Element | Why it is there |
|---|---|
| `perf_counter_ns` clock | Monotonic, nanosecond resolution |
| Time-based warm-up | Fast and slow schemes both get properly warmed |
| Adaptive batching (≥ 10 ms / sample) | Fast ops are timed k at a time so we measure the op, not the timer |
| Garbage collector off while timing | A GC pause cannot land inside a sample |
| Pinned P-core, HIGH priority | The i5-13500H has fast and slow cores; pinning stops migration |
| Interleaved input classes | Drift is spread across classes instead of faking a difference |
| Input pools outside the timed region | We time the crypto, not the input generation |
| Medians + full distributions | Robust to outliers; nothing hidden |
| Environment logged every run | `system_info.txt` records exactly where numbers came from |

**④ Validation.** Six independent checks that the outputs are right:
- *Calibration rows*: an empty call (0.036 µs) and `os.urandom(32)` (0.196 µs)
  set a noise floor. Anything smaller is instrument noise.
- *Byte-accounting self-test*: bytes predicted from the protocol format equal
  the bytes measured on the socket, in all five modes.
- *Security assertions*: 8 checks on the key schedule.
- *Negative control*: the flawed sequential collector, kept on purpose to show
  that the interleaved design is doing real work.
- *Report ↔ CSV verifier*: every number in the written report is re-checked
  against its CSV.
- *Adversarial review*: independent review passes found and fixed 22 defects.

**⑤ Synthesis.** The findings feed the RFC 7228 device-class matrix,
which becomes the deployment guidance the project answers: *which post-quantum
scheme, in which role, on which class of IoT device.* The final deliverable is
the IEEE report plus reproducible code.

---

## 4. Slide-by-slide script

| # | Slide | What to say (key points) |
|---|---|---|
| 1 | Title | One sentence: I replaced a PQC-IoT paper's simulated numbers with real measurements and extended it in four directions. Review 2 = implementation + intermediate results. |
| 2 | Outline | One line: the talk follows the gap register; each phase is shown as method, then code, then result. |
| 3 | Base paper and gaps | What PQShield-IoT proposes (left table). The gaps and which phase closes each (right table). Stress: "sound design, unverifiable evaluation." It names PQClean and liboqs but reports no measurement method. |
| 4 | **Novel claim** | Read the shaded claim slowly. Then one line per column: measured not simulated; design spaces not single choices; security the paper omits. (See §2 above.) |
| 5 | Scope | All five phases plus verification are complete. 7 modules, ~1,890 lines, 16 schemes, 9 datasets, 7 figures. Figures are rendered from CSVs, never typed by hand. |
| 6 | **Methodology** | Walk the five stages left to right (see §3). Point at the shaded protocol band: "this is the answer to G2." |
| 7 | Implementation | Each script is standalone and writes its own CSV, so any phase can be audited alone. The environment table is logged automatically. Fairness caveat: OpenSSL is asm, PQ is portable C, so PQ gaps are upper bounds. |
| 8 | **Code 1: `bench()`** | Walk the 5 numbered comments (see §5.1). Punchline: the same function times a 64 µs op and a 1.2 s op correctly. |
| 9 | Compute result | ML-KEM ≈ ECDH (within 8%). HQC is >100× slower. Signing spans 4 orders of magnitude. Mention the honest anomaly if asked (see §8). |
| 10 | Bytes result | The reframing: ~16 radio frames vs 1. ML-DSA-44 signature is 38× Ed25519. Falcon is variable-length. |
| 11 | Signatures | Log-scale chart of signing time; exact values in the table. No family wins every axis. Falcon: verify-heavy roles such as firmware updates. ML-DSA: general. SPHINCS+: rarely-signing roots, signed off-device. |
| 12 | Protocol diagram | Walk msg1 → msg2 → key derivation → fin_C → fin_S. Byte counts at the arrow ends. Ephemeral keys, fail-closed on tamper. |
| 13 | **Code 2: key schedule** | Explain each hashed input (see §5.2). Four properties: combiner, downgrade detection, no reflection, forward secrecy. |
| 14 | Handshake result | +64 B and ~0.6 ms for hybrid vs +2.2 KB for PQ at all (highlighted row). Byte self-test matches in all 5 modes. |
| 15 | **Code 3: timing** | `naive_compare` exits early, so it leaks position. `collect_interleaved` goes round-robin. The verdict rule needs trend AND effect size. |
| 16 | Timing result | Chart: the naive loop rises linearly (r = +1.000, ~67 ns per correct byte); `bytes ==` and `hmac.compare_digest` stay flat. Table: ML-KEM decaps is constant-time (\|z\| ≤ 1.5). |
| 17 | Methodological control | Same code, only measurement order changes → a fake leak (z = 4.7, above the dashed threshold of 3). More samples would not help. This is why methodology matters. |
| 18 | **Code 4 + implied clock** | cycles ÷ ms = clock. Four figures → four clocks (bars) against the declared 120 MHz (dashed line) → cannot all be measurements. Do **not** compare pqm4 ms with the paper's ms (see §9). |
| 19 | Device matrix | Nothing PQ runs on Class 0 alone. Class 1: ML-KEM-512, Falcon verify. Class 2 (the paper's node): full stack including hybrid. |
| 20 | Forward secrecy | Read the comparison table row by row: static keys (§3.2) vs the FS claim (§4.9) → inconsistent. Our handshake is ephemeral. |
| 21 | Verification | 8 PASS lines; the 7th is "hybrid holds" as an executable test. The report verifier passes. 22 review fixes, 4 that changed results. |
| 22 | Findings | One sentence per row. These are intermediate: the run was taken with a browser open, which makes every timing ~1.6× slower uniformly. Conclusions are relative, so they don't change. |
| 23 | Limitations + plan | State limitations *before* being asked. Plan: clean re-run, comparison with existing work, energy estimate, confidence intervals, final report. |
| 24 | Demo + thanks | Run the demo if time allows (§7). |

---

## 5. Code walkthrough guide

If faculty ask to see the code, open these exact places. All paths are under
`code/`.

### 5.1 `benchmark_pqc.py`: the measurement harness (answers G2, G3)

| Where | What to point at |
|---|---|
| `bench()`, **line 185** | The core harness. Walk through it in this order: (1) time-based warm-up loop; (2) `est_s` = min of 3 single-call timings; (3) if the op is under 1 ms, batch `k = ceil(0.010 / est_s)` calls per sample, else `k = 1`; (4) `gc.disable()` around the timed loop; (5) stop at `max_samples`, or at `min_samples` once the time budget is spent. |
| `cycler()`, **line 263** | Feeds decapsulate/verify a *different* pre-made input each call, so input generation is outside the timer and nothing is cached. |
| `bench_calibration()`, **line 279** | Times an empty call and `os.urandom(32)`. This gives the noise floor. |
| `bench_pq_kem()`, **line 310** | The `assert m.decrypt(sk, ct) == ss` preflight. ML-KEM's implicit rejection returns *wrong bytes silently* instead of raising, so without this check you could be timing garbage. |
| `PQ_KEMS` / `PQ_SIGS`, **lines 293–307** | The scheme list: ML-KEM ×3, HQC, ML-DSA ×2, Falcon ×2, SPHINCS+ ×2. |

**How to explain batching in one line:** "Timing a 64-microsecond operation
once mostly measures the timer and the scheduler. So I time 210 of them
together and divide. For a 1-second signature, one call per sample is fine.
The code works out k by itself."

### 5.2 `hybrid_handshake.py`: the hybrid key exchange (answers G1, G6)

| Where | What to point at |
|---|---|
| `send_frame` / `recv_frame`, **lines 107–121** | Every message = 4-byte big-endian length + payload. The byte count on the wire is exact, not estimated. |
| `derive_key()`, **line 137** | `K = SHA3-256("CNS-hybrid-v1" ‖ mode ‖ level ‖ ss_classical ‖ ss_pq ‖ transcript)`. |
| `_fin()` / `_check_fin()`, **lines 159–171** | AES-256-GCM encrypts the transcript under K. The receiver decrypts and checks it equals its own transcript; any mismatch raises, so the handshake **fails closed**. |
| `handle_connection()`, **line 174** | Server side: generates a fresh X25519 key, does the exchange, runs ML-KEM `encrypt` (encapsulate) against the client's public key, replies. |
| `one_handshake()`, **line 230** | Client side: the clock starts *before* key generation, because generating ephemeral keys is real per-session work. |

What each hashed input in `derive_key` does:
- **Label** `"CNS-hybrid-v1"`: domain separation, so this hash can't be confused
  with any other use of SHA3.
- **mode, level**: if an attacker flips "hybrid" to "classical" in transit,
  the two sides derive different keys and the finished check fails. The
  downgrade is *detected*, not just discouraged.
- **ss_classical ‖ ss_pq**: both secrets go in, so both are needed.
- **transcript**: binds both ciphertexts into the key. Any tampered byte
  changes the key.
- The two finished messages use different AAD (`c-fin` / `s-fin`), so a
  server's finished message can't be reflected back as a client's.

### 5.3 `timing_analysis.py`: side-channel analysis (answers G4)

| Where | What to point at |
|---|---|
| `naive_compare()`, **line 101** | The leaky textbook loop: returns at the first mismatch, so time reveals how many leading bytes were right. |
| `COMPARERS`, **line 111** | The three functions compared: naive loop, `bytes ==`, `hmac.compare_digest`. |
| `collect_interleaved()`, **line 118** | Round-robin over classes, batch-averaged, GC off. **The correct design.** |
| `collect_sequential()`, **line 141** | All samples of one class, then the next. **The flawed design, kept only as a control.** |
| `welch_z()` / `pearson()`, **lines 177–190** | The two statistics, implemented by hand (no black-box library). |
| `experiment_a()`, **line 196** | Builds candidate tags matching the secret in exactly p leading bytes and differing at byte p. Verdict: `leaks = r > 0.9 and abs(z) > 3`. |
| `experiment_b()`, **line 248** | ML-KEM-512 decapsulation on valid, 1-bit-flipped and random ciphertexts (pools of 64). |

Run with `python timing_analysis.py --sequential` to also produce the control CSV.

**Why the verdict needs both r and z:** a strong trend with a tiny effect isn't
exploitable, and a large z with no trend is noise, not a byte-by-byte oracle.
The attacker exploits the *trend*: guess one byte, see which guess takes
longest, fix it, move to the next byte. That reduces a 2²⁵⁶ search to at most
256 × 32 trials.

### 5.4 `pqm4_extrapolation.py`: laptop → Cortex-M4 bridge (answers G5)

| Where | What to point at |
|---|---|
| `PQM4_CYCLES`, **line 53** | Published pqm4 cycle counts (clean-C implementations). |
| `BASE_PAPER_SIM`, **line 69** | The paper's four reported latencies. |
| The comment block above `PAPER_CLOCK_MHZ` | Explains *why* we must not compare milliseconds across clocks. |
| `build_comparison()`, **line 92** | `implied_clock_mhz = cycles / (paper_ms * 1000)`. This is the clock-independent test. |
| `DEVICE_MATRIX` (**line 144**) + `write_device_matrix()` (**line 173**) | The RFC 7228 recommendation table. |

### 5.5 Verification scripts

- `test_handshake_security.py` (96 lines): 8 assertions. The key one is
  *"knowing only the PQ secret is insufficient"*. It simulates an attacker
  who has broken ML-KEM and confirms they still can't rebuild K.
- `verify_report_numbers.py` (144 lines): re-reads the report's numbers and
  checks each against its CSV. Sizes must match exactly, Falcon is range-checked
  (variable-length), and timings may drift ±20%.

---

## 6. Results and outputs

All in `results/`. Every figure is generated by `plot_results.py` from the CSVs.

| Output | Shows | The number to quote |
|---|---|---|
| `timings.csv` | 51 rows: median, mean, std, min, max, samples, batch k | ML-KEM-512 encaps 0.154 ms vs ECDH P-256 0.143 ms |
| `sizes.csv` | Key, ciphertext and signature sizes read from real objects | ML-KEM-512 pk 800 B, ct 768 B; ML-DSA-44 sig 2,420 B |
| `system_info.txt` | The exact environment of the run | i5-13500H, pinned P-core, pqcrypto 0.4.0 |
| `fig1_kem_timings.png` | Key-establishment timings, log scale | classical vs PQ overlap |
| `fig2_sig_timings.png` | Signature timings by operation | Falcon verifies fastest, SPHINCS+ signs slowest |
| `fig3_sizes.png` | Sizes vs the 802.15.4 payload line | everything PQ is above the line |
| `fig4_sign_tradeoff.png` | Sign time vs signature size, log–log (the deck shows this data natively on slide 11) | no family is lower-left on everything |
| `handshake_results.csv`, `fig5_handshake.png` | Latency + bytes per mode | hybrid-768 = 2,474 B vs pure-768 = 2,410 B → +64 B |
| `timing_analysis.csv`, `fig6_timing.png` | Experiments A and B (the deck shows this data natively on slide 16) | naive r = +1.000, z = 70.5; decaps \|z\| ≤ 1.5 |
| `timing_analysis_sequential.csv` | The flawed control | z = +4.7 phantom leak |
| `pqm4_comparison.csv`, `fig7_pqm4.png` | Laptop vs M4; implied clocks | 25.0 / 28.7 / 188.7 / 57.3 MHz |
| `device_class_matrix.csv` | RFC 7228 guidance (slide 19) | Class 2 runs the full stack incl. hybrid |

**Reading the key results tables quickly**

Handshake (100 runs each, localhost):

| Mode | Median ms | Total bytes |
|---|---|---|
| Classical X25519 | 1.056 | 202 |
| Pure ML-KEM-512 | 1.394 | 1,706 |
| Pure ML-KEM-768 | 1.642 | 2,410 |
| Hybrid-512 | 2.076 | 1,770 |
| Hybrid-768 (TLS group) | 2.257 | 2,474 |

Timing, Experiment A (median ns per rejection):

| Function | prefix 0 | prefix 31 | Δ | Verdict |
|---|---|---|---|---|
| naive loop | 825 | 2,906 | +2,081 | LEAKS |
| `bytes ==` | 351 | 369 | +18 | no trend (word-wise compare, no byte-by-byte structure) |
| `hmac.compare_digest` | 433 | 433 | +0.9 | no trend |

---

## 7. Live demo

From `code/`, on the machine where `pqcrypto` is installed:

```
# terminal 1
python hybrid_handshake.py --server

# terminal 2
python hybrid_handshake.py --client --mode hybrid --level 768
```

The client prints the mode, median/min/max latency and bytes each way. If you
only have one terminal, `python hybrid_handshake.py` with no arguments runs
all five configurations against a built-in server and prints a table.

Other quick demos (a few seconds each):

```
python test_handshake_security.py   # 8 PASS lines
python verify_report_numbers.py     # "all report numbers reconcile with the CSVs"
```

---

## 8. Likely questions and answers

**Q: What exactly is novel here? You didn't invent a new algorithm.**
The novelty is evaluative, not algorithmic. (1) A measured, reproducible
re-evaluation of the paper's own primitives with a stated methodology. (2) A
clock-independent test showing the paper's figures are internally
inconsistent; I haven't seen this test applied to a simulated PQC-IoT paper.
(3) The hybrid design space and the forward-secrecy contradiction. (4) The
methodological control showing that measurement order alone can fabricate a
side-channel. (5) Device-class deployment guidance built from measured data.

**Q: Why measure on a laptop if the target is IoT?**
No hardware was available, and a laptop gives exact, reproducible
measurements of the same C code. For the device side I use pqm4's *measured*
Cortex-M4 cycle counts, not a simulation. Cycle counts are the exact metric;
laptop → M4 milliseconds are indicative only, and I say so.

**Q: Isn't comparing OpenSSL with PQClean unfair?**
Yes, and it's unfair *against* post-quantum: OpenSSL is optimised assembly,
PQClean is portable C with no AVX2. So every "PQ is only X% slower" result is
an upper bound on PQ's real cost. The conclusion only gets stronger.

**Q: Why is ML-KEM decapsulation faster than encapsulation in your data? It should be slower.**
Correct, it should be slower, and pqm4 confirms that (888,653 vs 700,605
cycles). In our data the inversion is a binding-level artefact: the randomised
operations draw randomness inside the C library. The calibration rows show
it's not explained by `os.urandom` cost. I report it rather than hide it, and
use pqm4 cycle counts for ordering questions below a millisecond.

**Q: Why is the hybrid secure? Isn't it just hashing two secrets together?**
Model SHA3-256 as a random oracle. The output is indistinguishable from random
as long as *either* input secret is unknown. So an attacker must break both
X25519 and ML-KEM. Including the transcript binds both ciphertexts, which is
the condition Giacon–Heuer–Poettering (2018) identify for a robust combiner.
The property that matters is **PRF / random-oracle indistinguishability plus
ciphertext binding, not preimage resistance.**

**Q: Your handshake has no authentication. Isn't that a MITM risk?**
Yes, it is an unauthenticated key exchange, stated as a limitation. It
demonstrates key establishment, hybrid combination and forward secrecy.
Authentication is the job of the signature layer (ML-DSA / Falcon) and the
paper's blockchain identities. Signing the transcript with ML-DSA to make it a
full AKE is a natural extension.

**Q: Why does interleaving matter so much?**
CPU frequency and temperature drift during a multi-minute run. If you time all
"valid" samples first and all "invalid" samples after, that drift lines up with
the class label and looks like a difference. The sequential control shows
exactly this: z = 4.7 (an earlier run gave −18.9) for a true effect of 5 ns.
More samples would *not* fix it; they'd just report the bias more
confidently.

**Q: Could your timing test detect KyberSlash?**
No, and I don't claim it can. Black-box wall-clock timing here resolves
effects of hundreds of nanoseconds. KyberSlash was a few-cycle leak, which needs
instruction-level tools. This is stated as a limitation.

**Q: Which operations need to be constant-time?**
Everything that touches secret material: key generation, encapsulation,
decapsulation, signing and secret-tag comparison. The exception is **signature
verification**, because all its inputs are public.

**Q: Isn't returning an explicit error on a bad ciphertext itself an oracle?**
No. Both Fujisaki–Okamoto variants (explicit and implicit rejection) are
provably IND-CCA2. ML-KEM chose *implicit* rejection because it gives tighter
proofs in the quantum random-oracle model and removes a secret-dependent
branch, not because explicit rejection is broken.

**Q: How do you know the paper's numbers are wrong?**
I don't claim they are wrong. I show they are **internally inconsistent**:
four figures from one declared device imply four different clocks, so they
cannot all be cycle-accurate measurements. The paper's other issue is that
they are **unverifiable**, since no measurement method is reported.

**Q: Why not just compare the paper's milliseconds with pqm4's milliseconds?**
Because pqm4 reports at 24 MHz and the paper declares 120 MHz. Comparing those
directly is a clock-mismatch error that invents a fake discrepancy. The
implied-clock test avoids assuming any clock.

**Q: Why HQC?**
NIST selected HQC in 2025 as a code-based backup to ML-KEM. A project arguing
that scheme diversity matters should measure the alternative. It costs over
100× ML-KEM-512 for decapsulation (8.07 ms), with a 4,433 B ciphertext.

**Q: Why is the Falcon signature size shown as ~655 B, not one number?**
Falcon uses a variable-length compressed encoding. We sign 100 times and
record the range (651–660 B). 752 B is the PQClean buffer maximum; 666 B is
the spec's padded format. Never quote one observed length as exact.

**Q: Are these final numbers?**
No, intermediate. The run was taken with a browser open, which slows every
timing by ~1.6× uniformly. A clean re-run on an idle machine is planned before
Review 3. All conclusions are ratios and deltas, so they aren't expected to
change. Sizes and byte counts don't depend on machine load at all.

---

## 9. Wording traps

| Say | Don't say |
|---|---|
| "The paper reports no measurement **methodology**" | "The paper used no real crypto library" (it names PQClean and liboqs) |
| "**unverifiable**", "**internally inconsistent**" | "wrong", "fabricated", "fake" |
| "implied clocks 25–189 MHz, a 7.5× spread" | "Dilithium is 7.9× optimistic" (that compared ms across different clocks; retired) |
| "ML-KEM-512 public key **800 B**, ciphertext **768 B**" | "768 B public key" |
| "hybrid costs **+64 B total** (+32 B each way)" | "+32 B" alone |
| "Falcon-512 signature **~655 B, variable**" | "Falcon signature is 666 B" |
| "combiner security = random-oracle/PRF indistinguishability + ciphertext binding" | "it's secure because SHA3 is preimage-resistant" |
| "constant-time: everything touching secrets; verify is the exception" | "only decapsulation and signing need to be constant-time" |

---

## 10. Before the review: checklist

- [ ] **Run the tests on your Windows machine.** `pqcrypto` is not installed on
      this Linux setup, so `test_handshake_security.py` could not be re-run
      while preparing these files. `verify_report_numbers.py` *was* run and
      passes: all report numbers reconcile with the CSVs.
- [ ] Rehearse the live demo once (§7) so you know the output format.
- [ ] Optional: do the clean benchmark re-run (close the browser, run
      `python benchmark_pqc.py` without `--quick`, then `plot_results.py` and
      `verify_report_numbers.py`). If numbers shift, the slides' timing values
      will be ~1.6× high; the conclusions stay the same.
- [ ] Carry the base paper hard copy. Know where §3.2 (static keys), §4.9
      (forward-secrecy claim), Table 3 (120 MHz) and Table 6 (the four
      latencies) are.
- [ ] Read §2 and §8 of this file aloud once.
