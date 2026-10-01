# `benchmark_pqc.py` — Block-by-Block Explanation (Viva Prep)

Read this next to the code. Each section explains *what* a block does, *why it
was written that way*, and the question an examiner is likely to ask about it.
The script went through an adversarial review (three independent reviewer
passes + majority-vote verification); the fixes that came out of it are marked
**[review fix]** — being able to narrate them is itself strong viva material.

---

## 0. The big picture

The script answers one question with real measurements: **what does
post-quantum cryptography cost, relative to the classical schemes it must
replace?** Two operation families are measured, because a secure channel needs
both:

* **KEM (Key Encapsulation Mechanism)** — how two parties agree on a shared
  secret key: `keygen` → `encapsulate` (sender derives secret + ciphertext
  from the receiver's public key) → `decapsulate` (receiver recovers the same
  secret with its private key). Replaces classical key exchange (ECDH) / key
  transport (RSA).
* **Digital signature** — how a device proves identity: `keygen` → `sign` →
  `verify`. This is the role the base paper uses Dilithium2 for (device
  identity, firmware attestation).

The base paper (PQShield-IoT) *simulated* its cryptography inside
NS-3/Contiki-NG. This script produces **measured** numbers from actual
implementations — the project's Gap-2 contribution — and measures Falcon and
SPHINCS+ alongside Dilithium — Gap 3.

---

## 1. Configuration — and the bug that lived here

```python
CONFIG = {"warmup_s": 0.25, "budget_s": 3.0, "min_samples": 15,
          "max_samples": 300, "target_sample_s": 0.01, "batch_threshold_s": 1e-3}
```

Config lives in a dict that `bench()` reads **at call time**. **[review fix]**
The first version used module constants as *default arguments*
(`def bench(fn, budget_s=TIME_BUDGET_S)`), and `main()` mutated the globals
for `--quick`. Python evaluates default arguments **once, at function
definition** — so `--quick` silently did nothing, while the environment record
claimed quick parameters. Three independent reviewers caught it. The fix (read
shared state at call time) is a classic Python lesson: *never* use a mutable
runtime setting as a default argument.

```python
MESSAGE = b'{"dev":"n01","t":24.5,"h":61,"seq":1042}'.ljust(59, b" ")[:59]
```

Every signature is over the same **59-byte message** — the message length used
by the SUPERCOP framework and by **pqm4** (the Cortex-M4 PQC benchmark
project). **[review fix]** Precision matters here: matching the convention
makes our benchmark *setup* consistent with pqm4's when the report cites its
numbers next to ours. It does **not** make x86 milliseconds "directly
comparable" to M4 cycle counts (different ISA, clocks, memory) — cross-platform
comparisons stay qualitative. Also note pqm4's headline numbers are
M4-*optimized* implementations, not the portable C we run.

**Viva question:** *"Why does message length barely matter?"* — All these
schemes hash/absorb the message once and then do fixed-size asymmetric math;
59 bytes vs 5 KB changes almost nothing. It would matter for megabytes.

---

## 2. The timing engine — `bench()`

The most probe-worthy part. In order:

**Process pinning (once, at startup).** `pin_process()` sets high priority and
pins the process to CPU 0. **[review fix]** This machine's i5-13500H is a
*hybrid* CPU (performance P-cores + efficiency E-cores); an unpinned benchmark
migrates between them mid-run and produces bimodal garbage — our first-run
Falcon-512 sign was 16 ms; pinned and warmed it is 4.0 ms. Implementation
war story: `GetCurrentProcess()` returns the pseudo-handle −1, and without
explicit ctypes `restype`/`argtypes` it gets truncated to 32 bits, so both
Win32 calls fail *silently* (they returned `False`, which the status string
exposed). Always check the return values of best-effort syscalls.

**Time-based warm-up.**
```python
while calls < 3 or time.perf_counter() < t_end:  # >= 0.25 s
    fn()
```
**[review fix]** A fixed 5-call warm-up is ~150 µs of work for a microsecond
operation — far too short to ramp CPU frequency or settle caches. Warming up
for a fixed *time* (0.25 s) works for fast and slow operations alike.

**Batched sampling for fast ops.**
```python
if est_s < 1 ms:  k = ceil(10 ms / est_s)   # one sample = mean of k calls
else:             k = 1                      # per-call samples
```
**[review fix]** 200 individual samples of a 30 µs operation complete in ~6 ms
of wall time — inside a single scheduler quantum, measuring "whatever state
the CPU happened to be in". Batching so each sample spans ≥ 10 ms means the
full 3 s budget is actually used and each sample is a steady-state mean. Ops
≥ 1 ms keep `k=1` deliberately: per-call timing is already well above timer
noise there, and per-call variance is sometimes *the finding* (RSA's prime
search, Falcon keygen's NTRU solving).

**Clock and GC.** `time.perf_counter_ns()` — monotonic, ~100 ns resolution on
Windows (QueryPerformanceCounter); never `time.time()`, which NTP can move
mid-run. The garbage collector is disabled inside the timed region
(`try/finally` guarantees re-enable) so a GC pause never lands inside a
sample.

**Adaptive sample count.** Sample until 3 s or 300 samples, never fewer
than 15. Fast ops get hundreds of steady-state samples; SPHINCS+-128s sign
(~0.7 s/call) still yields a valid minimum set.

---

## 3. Statistics — why the median leads

Benchmark noise on a desktop OS is **one-sided**: preemption, interrupts and
frequency drops only ever *add* time. So: **median** = headline (robust),
**min** ≈ noise floor, mean/stdev/max = honest spread. For batched rows the
spread is of *batch means* (steady-state variability); for `k=1` rows it is
raw per-call spread — the CSV's `batch` column says which you are looking at.

---

## 4. `cycler()` and the correctness preflight

Inputs for `decapsulate`/`verify` are pre-generated *outside* the timed region
(otherwise you time encaps+decaps together) and cycled from a pool of 32 so
the timed call never chews identical bytes. **[review fix]** Before any
timing, every KEM must round-trip a shared secret and every signature must
verify — ML-KEM's *implicit rejection* means a mismatched key/ciphertext bug
would silently return wrong bytes and be benchmarked happily; an assert makes
that impossible.

---

## 5. The scheme registry — precise naming (examiners check this)

| Category | Attack cost at least as hard as… |
|----------|----------------------------------|
| 1 | key search on AES-128 |
| 2 | collision search on SHA-256 |
| 3 | key search on AES-192 |
| 5 | key search on AES-256 |

**[review fix — say these precisely]:**

* **ML-KEM (FIPS 203 final) is the *successor* of round-3 Kyber, not the same
  bits.** FIPS 203 changed FO-transform/KDF details, so keys and ciphertexts
  are not interoperable with the Kyber512 the base paper cites. Same design,
  near-identical cost — the comparison is valid, the *identity* claim is not.
  Evidence our binaries are FIPS-final: ML-DSA-44 secret key = **2560 B**
  (round-3 Dilithium2 was 2528 B) — visible in our own `sizes.csv`.
* **SPHINCS+ here is the v3.1 submission**, the basis of FIPS 205 **SLH-DSA**
  but not bit-compatible with it (SLH-DSA added context-string message
  processing). Sizes and speed are the same; the label matters.
* **Falcon** was selected for standardization as **FN-DSA (FIPS 206, not yet
  published)** — don't call it a "draft standard" in the viva.
* **HQC-128**: NIST's March-2025 **backup KEM** selection — chosen because it
  is code-based, so a lattice breakthrough would not take it down with
  ML-KEM. That is the systemic-risk argument behind hybrids (Gap 1) made
  concrete.
* Classical rows: `quantum_resistant = no` — Shor's algorithm breaks RSA and
  all elliptic-curve schemes outright; their post-quantum security is nil.

---

## 6. Classical adapters — the modelling decisions to defend

**ECDH/X25519 as KEMs, including wire costs.** **[review fix]** The timed
closures now include what a real DH-KEM pays: `encapsulate` serializes the
ephemeral public key (that serialization *is* the ciphertext) and hashes the
shared secret (`SHA-256(ss || wire)`, a minimal KDF — raw DH output is not a
uniform key; every real construction, incl. TLS 1.3's `X25519MLKEM768`, runs
a KDF). `decapsulate` parses and validates the received point
(`from_encoded_point` does on-curve checking — a mandatory receiver-side step)
before the exchange. ML-KEM's timed C calls include their (de)serialization
and hashing, so excluding these steps would quietly favor classical.

**RSA-OAEP is key *transport*** (encrypt a random 32-byte secret), benchmarked
under the KEM interface for comparability. **[review fix]** Do not call it
"RSA-KEM" — that is a distinct ISO 18033-2 construction.

**Sizes are computed, not guessed.** **[review fix]** RSA sizes are measured
off the actual DER encodings at runtime: 294 B `SubjectPublicKeyInfo`, 1217 B
PKCS#8 — the first version hardcoded 270/1190 with wrong labels (those are
PKCS#1 encodings). EC sizes are raw wire encodings (65 B uncompressed point /
32 B scalar). Falcon's `SIGNATURE_SIZE` (752/1462 B) is PQClean's buffer
maximum for the variable-length compressed encoding; the spec's fixed
*padded* format is 666/1280 B, and `observed_bytes` (657/1268 B here) is what
was actually produced.

**Keygen measured once per key type.** **[review fix]** The first run measured
RSA keygen twice, minutes apart, and got 38 ms vs 280 ms — a laptop warming up,
not two truths. Now P-256 and RSA keygen are each measured once and the same
row is reported in both the KEM and Signature tables.

---

## 7. Calibration — measuring our own overhead

Every timed call crosses Python→C, and randomized operations draw OS
randomness. Two calibration rows quantify this: an empty Python call
(**26 ns**) and `os.urandom(32)` (**133 ns**) — both negligible.

But here is the subtle one, and it makes a great viva exhibit. In our data
ML-KEM **decapsulation appears ~2.5× faster than encapsulation**, while every
cycle-count dataset (PQClean, SUPERCOP, pqm4) has decaps *slightly slower*
(decaps = decrypt + full re-encryption for the implicit-rejection check). Look
at the encaps−decaps gap across parameter sets on this machine:

| | encaps ms | decaps ms | gap |
|---|---|---|---|
| ML-KEM-512 | 0.154 | 0.064 | **90 µs** |
| ML-KEM-768 | 0.201 | 0.090 | **111 µs** |
| ML-KEM-1024 | 0.204 | 0.130 | **75 µs** |

The gap stays **the same order of magnitude while the algorithm's cost
scales** — on the idle-machine run it was nearly constant at 49/46/43 µs;
background load adds jitter — the fingerprint of a *fixed additive overhead* on
the randomized operations (keygen/encaps/sign draw randomness inside the C
library's `randombytes`; decaps/verify are deterministic), not an algorithmic
property.

**Be precise about what is and isn't calibrated (an examiner will push here).**
The two calibration rows measure *Python's* `os.urandom(32)` at 0.20 µs — that
is **not** the ~90 µs overhead, and it would be wrong to claim the calibration
"quantifies" the gap. The overhead lives in PQClean's *internal* C `randombytes`
path, which these calibration rows do **not** touch. Its magnitude is therefore
**inferred** from the not-scaling-with-work pattern, not directly measured. So
the honest statement is: the desktop encaps/decaps inversion is a binding-level
artifact of the randomized operations; its exact size is not established by our
calibration; and for sub-millisecond decaps-vs-encaps *ordering* we defer to the
pqm4 cycle counts (where decaps is correctly slightly slower than encaps). Show
this table as evidence you understand your own measurement's error model — and
its limits.

---

## 8. What the current full run showed (i5-13500H, pinned P-core, medians, 2026-07-27)

| Observation | Numbers | Why |
|---|---|---|
| **ML-KEM-512 encaps ≈ ECDH P-256 encaps** | 0.154 vs 0.143 ms (within 8%) | the headline: portable-C lattice PQC matches optimized-assembly ECC once classical includes its real wire costs; ML-KEM decaps (0.064 ms) is ~1.7× *faster* than ECDH decaps |
| Full ML-KEM-512 exchange ≈ 0.36 ms of CPU | 0.138+0.154+0.064 | quantum resistance costs microseconds, not milliseconds |
| RSA private ops are the classical bottleneck | decrypt 0.89 ms; keygen 62 ms (max 235) | ~14× slower than ML-KEM-512 decaps; keygen = randomized prime search (heavy tail is intrinsic — never generate RSA keys on an IoT device) |
| HQC-128 ≈ 20–126× ML-KEM (20× keygen, 35× encaps, 126× decaps) | 2.82 / 5.40 / 8.07 ms | the backup KEM's price; textbook 1:2:3 keygen:encaps:decaps profile |
| ML-DSA-44 sign 0.572 ms with visible spread across batch means | | Fiat-Shamir **with aborts**: signing restarts until a candidate leaks nothing about the key — variance is intrinsic |
| Falcon-512: keygen 21.6 ms, sign 6.4 ms, verify 0.066 ms | | NTRU-equation keygen is expensive and variable; Gaussian sampling needs floating point (hard on FPU-less MCUs — desktop ordering does NOT transfer); verify is the fastest PQC verify measured |
| SPHINCS+-128s: sign 1.19 s, sig 7,856 B (128f: 60 ms, 17,088 B) | | thousands of hash calls; `s`mall vs `f`ast trades size against time; conservative security, impractical for per-message IoT signing |
| ECDSA verify ≈ 2.6× its sign | 0.102 vs 0.040 ms | sign = 1 scalar mult, verify = 2 — normal |

**For the report:** the base paper treats PQC compute as the scarce resource.
Our measurements say otherwise: on anything CPU-class, standardized lattice
PQC is sub-millisecond even unoptimized; the real cost is **bytes on the wire**
(Fig 3: 800–2,420 B keys/signatures vs 32–65 B classical) against 802.15.4's
~100 B frame payloads — fragmentation, not computation, is the bottleneck to
engineer around. (On Cortex-M-class devices compute does matter — that is what
the pqm4 extrapolation phase is for.)

---

## 9. Honesty box (limitations to state before the examiner does)

1. **Implementation asymmetry** **[review fix — the big one]**: classical =
   OpenSSL hand-tuned assembly; PQC = PQClean portable C, no AVX2. Relative
   orderings are trustworthy *within* each family; classical-vs-PQC gaps are
   **upper bounds on PQC cost** (AVX2 ML-KEM is ~5–10× faster than clean C).
   That our PQC still matches ECDH *despite* this handicap strengthens, not
   weakens, the conclusion.
2. **Fixed per-call overhead** on randomized sub-ms operations (~90 µs in the
   current run); discussed in §7, calibration rows in the CSV.
3. **Laptop, desktop OS**: pinning + priority + batching control the worst of
   it, but classical ops still run before PQC ops (order not interleaved) and
   turbo/thermal drift bounds precision to tens of percent. Environment is
   recorded (`system_info.txt`: CPU model, power plan, AC status, pinning).
4. **Batch means** damp per-call outliers for sub-ms ops (by design — steady
   state); the `batch` column discloses it.

---

## 10. Rapid-fire viva Q&A

* **Q: A KEM is just encryption, no?** No — a KEM never encrypts user data; it
  establishes a symmetric key (IND-CCA2-secure as a KEM); data then goes under
  AES-GCM (hybrid encryption).
* **Q: Why is Category 1 fine when the key is 800 bytes?** Size ≠ security:
  Category 1 = at-least-AES-128-hard. Lattice problems need bigger objects
  than elliptic curves to reach the same hardness.
* **Q: Your decapsulation is faster than encapsulation — the literature says
  opposite. Explain.** A binding-level overhead on the randomized ops
  (keygen/encaps draw randomness in the C library); the encaps−decaps gap
  stays the same order across parameter sets instead of scaling with the
  algorithm, the signature of *additive* overhead, not algorithm (§7). Its
  exact size isn't quantified by our `os.urandom` calibration (0.20 µs); for
  decaps-vs-encaps ordering I defer to pqm4 cycle counts, where decaps is
  correctly slightly slower.
* **Q: Why no real IoT board?** Laptop-only constraint, addressed by
  methodological compatibility with pqm4 (same PQClean codebase, same 59-byte
  convention) — its published Cortex-M4 numbers slot into our comparison
  qualitatively. The base paper itself is simulation-only, so
  measured-plus-cited is strictly stronger evidence on this axis.
* **Q: Grover halves AES security — why keep AES-256-GCM?** Grover is at most
  quadratic and parallelizes poorly; AES-256 keeps ≥128-bit effective
  security. Same reason the base paper keeps AES-256-GCM.
* **Q: Why median?** One-sided noise (the OS only adds time); the mean is
  dragged by outliers — see RSA keygen (median 41 ms, max 144 ms).
* **Q: What bugs did you find while building this?** Three good stories: the
  `--quick` default-argument bug (§1), the ctypes handle-truncation bug that
  made pinning fail silently (§2), and the first run's 16 ms Falcon sign that
  became 4 ms once pinned to a P-core — all three are why benchmark code needs
  the same scrutiny as the thing it measures.
* **Q: Would liboqs change your conclusions?** Same algorithms, faster
  absolute numbers (AVX2), same qualitative story; SETUP.md documents three
  reproduction routes.
