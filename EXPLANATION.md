# The Complete Explanation

*Everything in this project, from the problem statement to the current state of
the work, explained in order and from first principles.*

---

## How to use this document

This is the **narrative spine** of the project. It assumes no prior knowledge of
post-quantum cryptography and builds up to what was measured and why it matters.

There are four documentation layers; use the right one:

| Document | Purpose | Read when |
|---|---|---|
| **`EXPLANATION.md`** (this file) | The whole story, in order, explained | You want to *understand* the project |
| `VIVA.md` | Quick-reference defence pack | The night before / morning of the viva |
| `code/*_EXPLAINED.md` | Deep dive on one script each | You're asked about a specific script |
| `report/report.tex` | The formal IEEE deliverable | You're submitting |

**Table of contents**

1. [The problem: why any of this matters](#1-the-problem)
2. [The base paper: what PQShield-IoT proposes](#2-the-base-paper)
3. [Reading the paper critically: the gap analysis](#3-the-gap-analysis)
4. [Phase 1: building an environment that works](#4-phase-1--the-environment)
5. [Phase 2: real benchmarks (Gaps 2 and 3)](#5-phase-2--real-benchmarks)
6. [Phase 3: the hybrid handshake (Gap 1)](#6-phase-3--the-hybrid-handshake)
7. [Phase 4: timing side-channels (Gap 4)](#7-phase-4--timing-side-channels)
8. [Phase 5: from desktop to device (Gap 5)](#8-phase-5--from-desktop-to-device)
9. [How the work was quality-controlled](#9-how-the-work-was-quality-controlled)
10. [What the project concludes](#10-what-the-project-concludes)
11. [Current state and the one open item](#11-current-state)
12. [Limitations and honest weaknesses](#12-limitations)
13. [Appendices: **file-by-file reference**, commands, glossary](#13-appendices)
    — §13.1 explains *every file in the project*, one by one

---

## 1. The problem

### 1.1 Why quantum computers break today's cryptography

Almost every secure connection you make today rests on two mathematical problems
being hard:

* **Integer factorisation** — given a large number $N = p \times q$, find $p$ and
  $q$. This is what RSA rests on.
* **Discrete logarithm** — given points $P$ and $Q = kP$ on an elliptic curve,
  find $k$. This is what ECDH, ECDSA, X25519 and Ed25519 rest on.

Classically, both are believed to take time growing sub-exponentially or
exponentially in the key size, so a 2048-bit RSA key or a 256-bit elliptic curve
is comfortably out of reach.

**Shor's algorithm (1994)** solves *both* problems in polynomial time on a
sufficiently large quantum computer. Not "somewhat faster" — it moves them from
intractable to easy. The moment a cryptographically relevant quantum computer
exists, RSA, ECDH, ECDSA, X25519 and Ed25519 all fail completely. There is no
parameter increase that saves them; you cannot pick a bigger RSA key and be
safe, because the attack scales polynomially.

**Grover's algorithm** is the other quantum algorithm people cite, and it is
much less dramatic. It searches an unstructured space of size $N$ in
$\sqrt{N}$ steps — a *quadratic* speedup. Against a symmetric cipher, that
effectively halves the key length: AES-128 drops to ~64 bits of security
(too weak), but **AES-256 retains ~128 bits (still strong)**. Grover also
parallelises poorly, so real-world speedups are worse than the theory.

This asymmetry drives the entire design of post-quantum systems, including this
project and the base paper:

> **Replace the public-key parts. Keep the symmetric parts, just use big keys.**

That's why both the base paper and this project keep **AES-256-GCM** for bulk
encryption and **SHA3-256** for key derivation, and replace only the key exchange
and signatures.

### 1.2 Why "we'll upgrade later" doesn't work: harvest-now, decrypt-later

You might reasonably say: quantum computers capable of running Shor at scale
don't exist yet, so why act now?

Because an adversary can **record encrypted traffic today and decrypt it later**.
Anything you send now under RSA or ECDH — medical telemetry, industrial control
data, firmware — can be captured, stored cheaply, and opened the day the
capability arrives. For data with a long confidentiality lifetime, the deadline
already passed.

This is doubly true for IoT. A smart meter or industrial sensor deployed today
may run for **10–20 years** and may never receive a cryptographic upgrade. The
cryptography you ship in the firmware is the cryptography it dies with.

### 1.3 Why IoT is the hard case

Post-quantum cryptography is not free. Its keys, ciphertexts and signatures are
much larger than classical ones, and some schemes are much slower. IoT is exactly
where that hurts:

* **Tiny compute.** A typical constrained node is an ARM Cortex-M-class
  microcontroller running at tens of MHz — thousands of times slower than a
  laptop CPU.
* **Tiny memory.** Tens of kilobytes of RAM, hundreds of kilobytes of flash.
  Some post-quantum operations need more *stack* than the device has *RAM*.
* **Tiny radio frames.** IEEE 802.15.4 — the radio underneath Zigbee, Thread,
  and 6LoWPAN — carries a **127-byte physical frame**, leaving roughly 100 bytes
  of usable payload after headers. A 2,420-byte post-quantum signature does not
  fit in a frame; it fits in about **25 fragments**, every one of which can be
  lost, must be reassembled, and costs radio energy.
* **Battery.** Radio transmission usually costs far more energy than
  computation, so bytes-on-wire is often the real currency.

So the IoT question is not "is post-quantum cryptography secure?" (it is, as far
as we know) but **"does it fit, and what does it cost?"** That question is
answerable only by measurement — which is exactly where the base paper falls
short, and where this project contributes.

### 1.4 The standardisation response

NIST ran a multi-year competition and, in **August 2024**, published three
standards:

| Standard | Name | Was called | What it does | Based on |
|---|---|---|---|---|
| **FIPS 203** | ML-KEM | CRYSTALS-Kyber | key encapsulation | module lattices (Module-LWE) |
| **FIPS 204** | ML-DSA | CRYSTALS-Dilithium | signatures | module lattices |
| **FIPS 205** | SLH-DSA | SPHINCS+ | signatures | hash functions only |

Two more matter to this project:

* **Falcon**, selected for standardisation as **FN-DSA** (FIPS 206, *draft not
  yet published*). Compact lattice signatures via NTRU trapdoor sampling.
* **HQC**, selected in **March 2025** as a *backup* KEM to ML-KEM. It is
  **code-based**, not lattice-based — chosen deliberately so that a
  breakthrough against lattices would not compromise every standardised KEM at
  once.

That last point is worth pausing on, because it motivates this project's Gap 1.
NIST hedged at the standards level. Deployed systems hedge too (see §6). The base
paper does not hedge at all.

**A cautionary tale that proves the point:** **SIKE**, another NIST candidate
(isogeny-based, with beautifully small keys), was **completely broken in 2022**
by Castryck and Decru — not by a quantum computer, but by a *classical* attack
that recovered keys in about an hour on a single core. It had survived years of
public scrutiny before falling. Cryptographic confidence is not a guarantee, and
that is precisely why hybrids exist.

---

## 2. The base paper

**Narayanan, S., Archana, K. S., Rajesh, A., Parthiban, N., Srinivasan, V., and
Sheela, S. N. (2026).** "Quantum-Resilient IoT Communication Framework Using
Post-Quantum Cryptography and Blockchain for Secure Edge Devices."
*Iranian Journal of Science and Technology, Transactions of Electrical
Engineering*, 50:203–221. DOI: 10.1007/s40998-025-01002-1.

The framework is called **PQShield-IoT**. (Springer journal, SCIE + Scopus
indexed — a legitimate venue.)

### 2.1 What it proposes

PQShield-IoT is an *integrated* architecture — its contribution is putting
several pieces together end-to-end rather than inventing a new primitive:

**The cryptographic core**
* **Kyber512** for key encapsulation (NIST Category 1)
* **Dilithium2** for digital signatures
* **AES-256-GCM** for the encrypted session
* **SHA3-256** as the key-derivation function

The session key is derived as (their Eq. 5):

```
K_sess = KDF(ss ‖ ID ‖ ID′ ‖ T ‖ T′)
```

i.e. the Kyber shared secret bound together with both device identities and both
timestamps. Binding identity and time into the key is good practice — it gives
freshness and resists replay. (This project uses the same idea in §6.)

**The identity and access layer**
Rather than a certificate authority, each device registers on a **permissioned
blockchain**. At manufacture it holds a device ID, a firmware hash
$H_{fw} = \text{SHA3-256}(\text{firmware})$, and a signing key. Registration is a
signed transaction:

```
T_reg = ⟨ID_i, H_fw, pk_sig, σ_i, ts⟩
```

A smart contract verifies the signature and appends it to the ledger. Access
control is a smart-contract ACL check combined with a firmware-hash match, so a
device with tampered firmware fails authorisation. Firmware updates are
version-chained (each new record references its parent), giving an auditable
history rather than an overwrite.

**The optimisation layer**
Three ideas: *algorithmic pruning* (score each available primitive against the
device's CPU/memory/bandwidth profile and pick the best), *adaptive key rotation*
(rotate based on measured energy and throughput rather than a fixed schedule),
and *hardware acceleration* (offload to a crypto co-processor).

### 2.2 What it claims

Headline results, all from **simulation**:

* End-to-end latency **50 ms**, throughput **20 operations/second**
* Device registration under **250 ms** at scale (95 ms at 50 nodes → 215 ms at 200)
* Session establishment 110 ms → 265 ms (50 → 200 nodes)
* Verification success ≥ **98.7%**
* Per-operation crypto (their Table 6): **Kyber512 encapsulation 28 ms,
  decapsulation 31 ms; Dilithium2 sign 42 ms, verify 36 ms**
* Energy 1.1–4.8 mJ per session; CPU under 50%
* Claimed **28.5%** improvement in session integrity and **33.3%** throughput gain

That Table 6 row is the one this project later checks against real silicon (§8) —
remember the numbers **28 / 31 / 42 / 36**.

### 2.3 What is genuinely good about it

It is important to be fair, and a viva examiner will respect balance far more
than a hatchet job:

* The **integration is real.** Many papers do PQC *or* blockchain identity; this
  one wires identity → key establishment → encrypted session → audit into one
  coherent lifecycle.
* The **primitive choices are correct.** Kyber512 and Dilithium2 are the right
  NIST Category 1/2 picks for constrained devices, and keeping AES-256-GCM and
  SHA3 is exactly right given Grover (§1.1). (How those primitives are *used* is
  a separate matter — see Gap 6 in §3 on the static-key/forward-secrecy issue.)
* **Firmware attestation is well-designed.** Binding a firmware hash into
  registration and version-chaining updates is a genuinely good answer to
  rollback attacks.
* The **evaluation is broad** — latency, energy, CPU, memory, throughput, ACL
  behaviour, an ablation study of the optimiser, and a comparison table.

The problem is not *what* it measures. It is *how*.

---

## 3. The gap analysis

Everything below comes from reading the paper closely, not from a template.

### Gap 1 — Pure post-quantum, no hybrid

The framework uses Kyber alone for key establishment. That is a defensible
"clean" design, but it is **out of step with how real migrations are being
done**. TLS 1.3 deployments (Chrome, Firefox, Cloudflare) default to the
**hybrid** group `X25519MLKEM768`, which derives the session key from *both* an
X25519 exchange *and* an ML-KEM-768 encapsulation. An attacker must break **both**
elliptic-curve discrete log **and** module lattices.

Why hedge? Because lattice cryptanalysis is young compared to RSA/ECC
cryptanalysis, and because SIKE (§1.4) showed a well-studied candidate can fall
overnight. If Kyber is ever broken, every PQShield-IoT session key falls with it.

**Open question the paper never asks:** what does hybrid actually *cost*?
Nobody can weigh the trade-off without that number. → **Phase 3 measures it.**

### Gap 2 — The cryptographic timings are unattributable

This is the central gap, and it must be stated **precisely**, because the
tempting sloppy version is falsifiable from the paper itself.

**What the paper actually says.** §3.6 describes a **Contiki-NG** + **NS-3**
co-simulation with ARM Cortex-M4F device *profiles* (256 kB flash, 64 kB SRAM),
and — importantly — states: *"The cryptographic component was deployed by
utilizing the **PQClean and liboqs** libraries, with Kyber512 for key
encapsulation and Dilithium2 for digital signatures."*

So it would be **wrong** to claim "no real cryptographic library was used". It
was. An examiner can find that sentence in seconds, and a student who overstates
this loses the room. (An earlier draft of this project made exactly that
mistake; it was caught in review — see §9.)

**The defensible gap is narrower and still decisive.** The paper reports
per-operation latencies (Table 6: 28 / 31 / 42 / 36 ms) but never says **how
they were obtained**:

* On **what host** did the cryptographic code execute? Not stated.
* The device is an **emulated Cortex-M4F profile**, not silicon — so the
  milliseconds must come from some mapping between host execution and the
  modelled device. That mapping is never described.
* **No cycle counts**, no clock frequency for the timing model, no repetition
  count, no variance, no measurement methodology for any of the four numbers.

The numbers are therefore **unverifiable and unattributable**: you cannot tell
what was measured, on what, or how it was scaled. That is the gap — not the
absence of a library, but the absence of a method.

This matters because a model reproduces only what its author put into it. If it
omits a behaviour — say, that Dilithium signing *retries* an unpredictable number
of times (§5.5) — it will report a confident, wrong number.

**And there is a bonus.** Because the paper used **PQClean**, and pqm4 compiles
**the same PQClean source** for the Cortex-M4 (§8.1), Phase 5's comparison is a
**same-codebase** check. That makes the discrepancy it uncovers (§8.3) *harder*
to dismiss, not easier: nobody can attribute it to "different implementations".

→ **Phase 2 measures the primitives directly; Phase 5 tests whether the paper's
numbers are consistent with measured cycle counts of that same codebase.**

### Gap 3 — One signature scheme, no comparison

The paper fixes on Dilithium2 and never compares alternatives. But the three
signature families have *wildly* different shapes:

* **Falcon-512** — signature ~655 B (variable-length), verification extremely
  fast, but signing is floating-point heavy and key generation is expensive.
* **SPHINCS+** — signatures of 8–17 KB and signing measured in *seconds* on a
  microcontroller, but security resting only on hash functions.

For a constrained device, a signature that is 3.7× smaller (Falcon vs ML-DSA)
can decide whether a firmware update fits the radio budget. Choosing without
comparing is a design risk. → **Phase 2 benchmarks all three; Phase 5 maps them
to device classes.**

### Gap 4 — No side-channel or timing analysis

The paper has no timing analysis of any kind. Yet this is not a theoretical
concern for these exact algorithms: the **KyberSlash** attacks (2023–24)
recovered Kyber secret keys because reference decapsulation performed a division
whose *timing depended on secret data*. The reference code and PQClean were
patched.

ML-KEM's security specifically depends on a constant-time
**implicit-rejection** path (explained in §7.3). A framework that deploys ML-KEM
without checking this has an unexamined attack surface. → **Phase 4 tests it.**

### Gap 5 (integrative) — No bridge from claims to real constrained hardware

Even granting the simulation, nothing connects the paper's numbers to published
real-hardware measurements, and there is no guidance on *which* scheme suits
*which* class of device. → **Phase 5 builds both.**

### Gap 6 — The forward-secrecy claim does not hold

This one sits squarely inside the cryptography, and it is arguably the sharpest
critique in the whole analysis.

**What the paper claims.** §4.9 states that "Kyber512, Dilithium2 achieve
**forward secrecy** and long-term resistance to quantum attacks".

**What the protocol does.** §3.2 states: *"every device maintains a
**pre-computed** post-quantum key pair for both encryption and signing"*, and
Eq. 2 encapsulates against that **long-term** $pk_{kem}$. There is **no
ephemeral KEM keypair anywhere in the protocol.**

**Why that is a contradiction.** Forward secrecy means: *compromising long-term
keys today must not expose sessions recorded yesterday.* It is achieved by using
**ephemeral** keys that are generated per session and destroyed afterwards. With
a *static* KEM key, an attacker who later obtains $sk_{kem}$ can decapsulate
**every recorded session's** ciphertext and recover every session key. Eq. 5's
KDF does not rescue it either: it binds $ss$ with $ID$, $ID'$, $T$ and $T'$ —
and all four of those are **public**, so they add freshness but no secrecy.

So the framework has **no forward secrecy**, and this is exactly the
harvest-now-decrypt-later scenario that motivates the entire field (§1.2): an
adversary records traffic now and opens it when the device key eventually leaks.

**The contrast is a free win for this project.** The Phase 3 handshake (§6) uses
**ephemeral** keys on both legs — a fresh X25519 keypair and a fresh ML-KEM
keypair per handshake — so it *does* provide forward secrecy. You can
demonstrate the difference rather than merely assert it.

A related, softer observation: §3.2 also claims the design is *"eliminating
vulnerability to man-in-the-middle attackers"*. Signing the key-exchange
messages does give authentication, but "eliminating" MITM is a strong word for a
paper that provides no security model, no proof, and no analysis of the on-chain
public-key lookup as the actual trust anchor. Raise this as an overclaim in
wording, not as a break.

### Additional critical-reading observations

These are **secondary** — worth raising as limitations warranting scrutiny, not
as accusations, and they sit outside this project's cryptographic scope:

1. **The blockchain platform is described three different ways.** Table 3 says
   *Hyperledger Fabric*; §3.6 says smart contracts ran on a local *Hyperledger
   Sawtooth* validator; the same section describes an "adapted permissioned
   **DAG-based** ledger" with 500 ms block confirmation. Fabric, Sawtooth and a
   DAG ledger are three different systems with different performance
   characteristics, so it is unclear which produced the reported latencies.

2. **The node count is inconsistent.** §3.6 describes a **15-node** network;
   Table 3 and every result specify **50, 100, 200** nodes (and Table 12 goes to
   300). A reader cannot tell which configuration produced which figure.

3. **The device specification is inconsistent.** §3.6 says Cortex-M4F with
   **256 kB flash / 64 kB SRAM** under Contiki-NG; Table 3 says Cortex-M4
   120 MHz, **256 KB RAM / 512 KB flash**, under **RIOT OS**. Different OS,
   different memory, in the same paper.

4. **The comparison table includes a broken scheme without noting it.** Table 13
   compares PQShield-IoT against "SIKE (NIST) optimized" as a *quantum-resilient*
   framework. **SIKE was classically broken in 2022** (Castryck–Decru) and
   dropped by NIST. Comparing favourably against it — without flagging that it
   is no longer secure — weakens the comparison. This is a good example of why
   a comparison table needs currency checks, and it is a strong point to raise
   if asked "what else did you notice?"

None of these invalidate the framework's design. They do mean the *evaluation*
needs independent corroboration — which is what this project provides.

---

## 4. Phase 1 — the environment

### 4.1 The plan, and why it failed

The original plan was `liboqs-python` — the Python binding for **liboqs**, the
Open Quantum Safe project's C library. `pip install liboqs-python` succeeds, but
that package is only a thin wrapper: on the first `import oqs` it **downloads and
compiles the liboqs C library from source**, which needs CMake and a C compiler.

Checking this machine found: no `cl` (MSVC), no `gcc`, no Visual Studio Build
Tools, no CMake, no WSL, no conda. Installing Visual Studio Build Tools is a
multi-gigabyte download requiring administrator rights.

### 4.2 The fix, and why it is arguably better

The project uses **`pqcrypto` 0.4.0** instead, which ships **prebuilt Windows
wheels** (including for Python 3.14) and binds **PQClean**.

This is not a downgrade, and it is worth being able to explain why:

* **PQClean is the upstream source that liboqs itself imports** for these
  algorithms. Same code lineage.
* PQClean's *"clean"* implementations are **portable C with no AVX2 assembly** —
  which is *closer to what microcontroller firmware actually runs* than a
  vector-optimised desktop build.
* **Decisively:** the **pqm4** project (§8) compiles those *same* PQClean clean
  implementations for the Cortex-M4. So the desktop and embedded numbers in this
  project describe **one codebase measured on two CPUs**, which is the cleanest
  cross-platform comparison possible without owning the hardware.

The honest caveat, stated in the report: an AVX2-optimised liboqs build would be
several times faster in absolute terms. Conclusions therefore rest on *relative*
comparisons, and `SETUP.md` documents three routes (WSL, Build Tools, conda) to
reproduce with liboqs if desired.

Final environment: Windows 11, Python 3.14.3, `pqcrypto` 0.4.0,
`cryptography` 49.0.0 (OpenSSL-backed, for the classical baseline), matplotlib,
pandas.

---

## 5. Phase 2 — real benchmarks

**Addresses Gaps 2 and 3.** Script: `code/benchmark_pqc.py`.
Deep dive: `code/benchmark_pqc_EXPLAINED.md`.

### 5.1 The two things being measured

**A KEM (Key Encapsulation Mechanism)** is how two parties agree on a shared
secret. It has three operations:

* `keygen()` → (public key, secret key)
* `encapsulate(public key)` → (ciphertext, shared secret) — run by the *sender*
* `decapsulate(secret key, ciphertext)` → shared secret — run by the *receiver*

Note the asymmetry: only a *ciphertext* travels back, not a second public key.
A KEM never encrypts user data; it establishes a symmetric key, and the data then
goes under AES-GCM. This is called hybrid encryption (a confusingly overloaded
word — unrelated to the *hybrid key exchange* of §6).

**A digital signature scheme** proves identity and integrity:
`keygen()`, `sign(sk, message)` → signature, `verify(pk, message, signature)`
→ true/false. This is what the base paper uses Dilithium2 for.

### 5.2 What was benchmarked

**Classical (quantum-broken — baseline only):** RSA-2048 (OAEP for key
transport, PSS for signatures), ECDH P-256, ECDSA P-256, X25519, Ed25519.

**Post-quantum:** ML-KEM-512/768/1024, HQC-128 (the code-based backup),
ML-DSA-44/65, Falcon-512/1024, SPHINCS+-SHA2-128f and -128s.

To make the comparison fair, **ECDH and X25519 are benchmarked *as KEMs***:
encapsulation = generate an ephemeral keypair, serialise its public key (that
serialisation *is* the "ciphertext"), derive and hash the shared secret;
decapsulation = parse and validate the received point, then exchange and hash.
Those serialisation, validation and KDF steps are included deliberately, because
ML-KEM's timed C call includes its equivalents — leaving them out would quietly
flatter the classical side.

### 5.3 Getting the measurement right

This is the part most likely to be probed, and several details were forced by
mistakes that had to be fixed (§9):

* **`time.perf_counter_ns()`**, a monotonic high-resolution clock — never
  `time.time()`, which NTP can move mid-run.
* **Process pinned to one CPU core at high priority.** The i5-13500H is a
  *hybrid* CPU with fast P-cores and efficient E-cores; an unpinned benchmark
  migrates between them and produces meaningless bimodal data. (Before pinning,
  Falcon-512 signing measured 16 ms; pinned, 4.0 ms.)
* **Time-based warm-up** (≥ 0.25 s, not a fixed call count) so the CPU reaches
  its working frequency even for microsecond-scale operations.
* **Batched sampling for fast operations.** An operation taking 30 µs would
  finish 200 samples inside a single scheduler quantum, so what you'd measure is
  "whatever state the CPU was in for those 6 ms". Operations under 1 ms are
  therefore timed in batches sized so each *sample* spans ≥ 10 ms, and the sample
  is the batch mean. Operations over 1 ms are timed per-call, preserving genuine
  variance (RSA's prime search, Dilithium's retries).
* **Garbage collector disabled** inside the timed region so a GC pause never
  lands inside a sample.
* **The median is the headline statistic.** Operating-system noise is
  *one-sided*: preemption and interrupts only ever *add* time, never subtract it.
  The median resists that; the mean is dragged by outliers (RSA keygen: median
  41 ms, maximum 144 ms).
* **Correctness preflight.** Before timing, every KEM must round-trip its shared
  secret and every signature must verify — because ML-KEM's implicit rejection
  (§7.3) returns *wrong bytes* rather than raising on a mismatched key, so a bug
  would otherwise be benchmarked happily.
* **Calibration rows** measure fixed per-call overhead: an empty Python call
  (26 ns) and `os.urandom(32)` (133 ns).

### 5.4 The results

Medians from the canonical run (Intel i5-13500H, pinned P-core, portable-C PQC
vs optimised-assembly OpenSSL classical):

| Scheme | keygen | encaps / sign | decaps / verify |
|---|---|---|---|
| ECDH P-256 † | 0.030 | 0.143 | 0.112 |
| X25519 † | 0.050 | 0.111 | 0.056 |
| RSA-2048 † | 62.2 | 0.039 | 0.891 |
| **ML-KEM-512** | 0.138 | **0.154** | **0.064** |
| ML-KEM-768 | 0.174 | 0.201 | 0.090 |
| ML-KEM-1024 | 0.198 | 0.204 | 0.130 |
| HQC-128 | 2.82 | 5.40 | 8.07 |
| ECDSA P-256 † | 0.030 | 0.040 | 0.102 |
| Ed25519 † | 0.056 | 0.053 | 0.147 |
| **ML-DSA-44** | 0.238 | **0.572** | **0.141** |
| ML-DSA-65 | 0.360 | 0.872 | 0.228 |
| **Falcon-512** | 21.6 | 6.41 | **0.066** |
| Falcon-1024 | 66.4 | 14.2 | 0.130 |
| SPHINCS+-128f | 2.30 | 60.5 | 3.29 |
| **SPHINCS+-128s** | 168 | **1189** | 1.05 |

† not quantum-resistant. All times in milliseconds.

And the sizes — which turn out to be the real story:

| Scheme | public key | ciphertext / signature |
|---|---|---|
| X25519 † | 32 | 32 |
| ECDH P-256 † | 65 | 65 |
| Ed25519 † | 32 | 64 |
| RSA-2048 † | 294 | 256 |
| **ML-KEM-512** | **800** | **768** |
| ML-KEM-768 | 1,184 | 1,088 |
| HQC-128 | 2,249 | 4,433 |
| **ML-DSA-44** | 1,312 | **2,420** |
| **Falcon-512** | 897 | **~655 (variable; 752 max)** |
| SPHINCS+-128s | 32 | 7,856 |
| SPHINCS+-128f | 32 | 17,088 |

### 5.5 What the numbers mean

**The headline finding, and the project's central claim:**

> **ML-KEM-512 encapsulation (0.154 ms) sits within 8% of optimised-assembly
> ECDH P-256 (0.143 ms), and its decapsulation (0.064 ms) is nearly twice as
> fast — despite the post-quantum side running unoptimised portable C.**

A complete ML-KEM-512 key establishment costs about **0.36 ms of CPU**. Quantum
resistance, on CPU-class hardware, is essentially free in time.

What is *not* free is size. ML-KEM-512 puts **800-byte keys and 768-byte
ciphertexts** on the wire where X25519 puts **32 bytes**. Against IEEE 802.15.4's
~100-byte payloads, that is roughly 8 fragments for one key. So:

> **On CPU-class hardware the cost of post-quantum cryptography is bytes on the
> wire, not computation.**

This *reframes* the base paper. PQShield-IoT's optimisation layer is built around
saving computation (pruning, hardware acceleration). Our measurements say
computation was not the binding constraint at that class of device — bandwidth
was. (§8 shows where computation *does* become binding.)

Other results worth being able to explain:

* **The signature families are not interchangeable.** Falcon verifies in
  0.066 ms with a ~655-byte signature — the best *verification* profile measured
  — but signs in 6.4 ms with expensive key generation. (Falcon signatures use a
  **compressed, variable-length** encoding, so that size is a distribution, not
  a constant: ~655 B typical, 752 B PQClean buffer maximum, 666 B in the spec's
  fixed "padded" format. Quoting a single observed length as though it were
  exact was itself a review finding — §9.) SPHINCS+-128s signs in
  **1.19 s** with a 7.9 KB signature. Choosing by role, not by habit, is the
  point of Gap 3.
* **Dilithium's signing time varies** (median 0.572 ms, with visible spread
  even across batch means) because of **Fiat–Shamir with aborts**: signing loops,
  discarding candidate signatures that would leak information about the secret
  key, until one is safe. The variance is intrinsic to the algorithm. *Remember
  this — it is the key to §8's biggest finding.*
* **RSA is the classical outlier:** key generation is a randomised *prime search*
  with a heavy tail (median 62 ms, max 235 ms) — which is a good argument that
  IoT devices should never generate RSA keys on-device.
* **HQC costs 20–126× ML-KEM** (20× keygen, 35× encapsulation, 126×
  decapsulation — divide the rows in the table above). That is the price of the
  code-based backup, and it is why HQC is a hedge rather than a default.

### 5.6 One anomaly, honestly handled

Our measurements show ML-KEM **decapsulation faster than encapsulation**
(0.064 vs 0.154 ms). Every published cycle-count dataset shows the *opposite*,
and correctly so: decapsulation does strictly *more* work, because it decrypts
and then **re-encrypts** to check the result (§7.3).

So our number is a measurement artefact, and the diagnosis is instructive. The
encapsulation-minus-decapsulation gap is **90 / 111 / 75 µs** for ML-KEM-512 /
768 / 1024 in the current run — *the same order of magnitude throughout, not
scaling with the algorithm's cost* (on the earlier idle-machine run it was
nearly constant at 49 / 46 / 43 µs; background load adds jitter). An offset
that doesn't grow with the work is the signature of a **fixed additive
overhead**, and the operations that carry it (keygen, encapsulate, sign) are
exactly the *randomised* ones, which draw randomness inside the C library.

Two points of honesty, both of which came out of adversarial review:

1. The `os.urandom` calibration row measures **0.20 µs**, so it does **not**
   quantify a ~90 µs overhead. The magnitude is *inferred* from the
   not-scaling-with-work pattern, **not measured**.
2. Therefore, for sub-millisecond decapsulation-versus-encapsulation *ordering*,
   the project defers to pqm4's cycle counts rather than its own wall-clock
   numbers.

Being able to say "here is a number in my own data that is wrong, here is how I
know, and here is what I trust instead" is worth more in a viva than clean data.

---

## 6. Phase 3 — the hybrid handshake

**Addresses Gap 1.** Scripts: `code/hybrid_handshake.py`,
`code/test_handshake_security.py`. Deep dive:
`code/hybrid_handshake_EXPLAINED.md`.

### 6.1 The idea

A **hybrid** key exchange derives the session key from *two independent* key
exchanges — one classical, one post-quantum — so that breaking *either one alone*
is not enough. This is what TLS 1.3's deployed `X25519MLKEM768` group does.

It defends both directions at once:

* If **lattices** turn out to be breakable (the SIKE scenario), the X25519 leg
  still protects you.
* If a **quantum computer** arrives, X25519 falls but the ML-KEM leg still
  protects you — which is what defeats harvest-now-decrypt-later.

### 6.2 The protocol as implemented

A real TCP client/server, one round trip, mirroring TLS 1.3's `key_share`:

```
msg1  client → server : mode ‖ level ‖ [X25519 pub 32 B] ‖ [ML-KEM pub 800/1184 B]
msg2  server → client : [X25519 pub 32 B] ‖ [ML-KEM ciphertext 768/1088 B]

      both sides compute:
        transcript = SHA3-256(msg1 ‖ msg2)
        K = SHA3-256("CNS-hybrid-v1" ‖ mode ‖ level ‖ ss_x25519 ‖ ss_mlkem ‖ transcript)

msg3  client → server : AES-256-GCM_K(transcript), AAD "c-fin"
msg4  server → client : AES-256-GCM_K(transcript), AAD "s-fin"
```

Messages 3 and 4 are **key confirmation**: each side proves it derived the same
key over the same transcript. Frames are length-prefixed (TCP is a byte stream,
not a message stream), and `TCP_NODELAY` is set so Nagle's algorithm doesn't
batch our small frames and pollute the latency measurement.

### 6.3 Why the construction is secure — stated correctly

This is a place where precision matters, and where an early draft of this
project got it **wrong** (§9):

> Modelling SHA3-256 as a **random oracle** (equivalently, a secure KDF/PRF), the
> derived key is **indistinguishable from random** as long as **at least one** of
> the two shared secrets remains unknown to the attacker. Therefore the attacker
> must recover **both**.

The wrong version — which the first draft used — was "a *preimage-resistant* hash
means you need both secrets". That is not a valid reduction: a function can be
perfectly preimage-resistant and still leak whether the output correlates with a
known partial input. The property you need is **PRF / random-oracle
indistinguishability**, not preimage resistance. (Preimage resistance *is* the
right notion for a different question — whether Grover threatens SHA3-256 itself,
where the answer is that SHA3-256 retains ~128-bit post-quantum preimage
resistance.)

Two further design points:

* **Transcript binding.** The KDF consumes a hash of every handshake byte, which
  binds *both* ciphertexts. Giacon–Heuer–Poettering (2018) showed a concatenation
  combiner needs exactly this ciphertext binding to be robust. It also makes
  tampering fail closed, and it mirrors the base paper's own practice of binding
  identities and timestamps into its session key.
* **What this deliberately is *not*.** It is an **unauthenticated, ephemeral**
  key exchange — a demonstration of key *establishment*, not a full authenticated
  key exchange (AKE). A man-in-the-middle can sit in the middle of it.
  Authentication is a separate layer (certificates in TLS; the blockchain-
  registered Dilithium identities in the base paper; the signature costs measured
  in Phase 2). Say this before an examiner does.

### 6.4 The security properties, proven not asserted

`test_handshake_security.py` turns the claims into executed checks — all 8 pass:

1. Correct handshake → both sides derive identical keys.
2. The finished message verifies under that shared key.
3. A tampered transcript yields a **different** key.
4. The finished check **fails closed** on tampering (raises, does not silently pass).
5. Changing the classical secret changes the key.
6. Changing the post-quantum secret changes the key.
7. **Knowing only the post-quantum secret is insufficient** — the hybrid property.
8. A mode downgrade changes the key, so downgrade is **detected**.

### 6.5 The results

100 handshakes per configuration, localhost:

| Mode | median latency | client→server | server→client | **total bytes** |
|---|---|---|---|---|
| classical (X25519) | 1.056 ms | 102 | 100 | **202** |
| pure ML-KEM-512 | 1.394 ms | 870 | 836 | 1,706 |
| pure ML-KEM-768 | 1.642 ms | 1,254 | 1,156 | 2,410 |
| hybrid-512 | 2.076 ms | 902 | 868 | 1,770 |
| **hybrid-768** (= TLS `X25519MLKEM768`) | **2.256 ms** | 1,286 | 1,188 | **2,474** |

**The finding:**

> **Hybrid costs +64 bytes and about +0.6 ms over pure ML-KEM-768.**

(64 = a 32-byte X25519 public key in *each* direction. An early draft of the
write-up said "+32 B" by counting one direction — caught in review, §9.)

Two conclusions follow. First, **defence-in-depth is nearly free**, which makes
the base paper's pure-PQC choice something that needs justifying rather than
assuming. Second, going post-quantum at all costs about **2.2 KB** on the wire —
invisible on localhost, but roughly **25 fragments** over 802.15.4. That connects
Phase 2's size finding to a running protocol.

---

## 7. Phase 4 — timing side-channels

**Addresses Gap 4.** Script: `code/timing_analysis.py`. Deep dive:
`code/timing_analysis_EXPLAINED.md`.

### 7.1 The one idea

> **Timing is a side channel whenever execution time depends on secret data.**

An algorithm can be mathematically perfect and still leak its key through *how
long it takes*. The defence is **constant-time** code: runtime may depend on
public things (input length) but never on secret values or on whether a check
passed.

Which operations must be constant-time? **Every operation that processes secret
material**, which is most of them:

* **key generation** — it samples and manipulates the secret key (Falcon's
  Gaussian sampling over an NTRU trapdoor is the classic example of a keygen
  that must be constant-time);
* **encapsulation** — it generates the random message *and* the shared secret,
  so a leak here hands over the session key without ever touching the long-term
  key;
* **decapsulation** — it uses the secret key;
* **signing** — it uses the secret key;
* **MAC/tag comparison** — it compares against a secret tag.

The notable **exception is signature verification**, which consumes only public
inputs (public key, message, signature), so its variable timing is *not* a
vulnerability. That exception is the one worth volunteering unprompted, and it is
why Experiment B targets decapsulation rather than verification.

(An earlier draft of this document said "*only* decapsulation, signing and tag
comparison" — omitting keygen and encapsulation. That was wrong, and it was
caught in review; see §9.)

### 7.2 Experiment A — a leak you can watch happen

A server compares a received 32-byte MAC tag against the correct one. We measure
rejection time as a function of how many leading bytes the attacker already has
right, for three comparison functions.

| comparison | Δ(31 correct − 0 correct) | Pearson *r* | verdict |
|---|---|---|---|
| naive Python loop | **+2,081 ns** | **+1.000** | **LEAKS** |
| `bytes ==` (C memcmp) | +18 ns | +0.600 | no exploitable trend |
| `hmac.compare_digest` | +0.9 ns | +0.832 | no exploitable trend |

*(Values from `results/timing_analysis.csv`. The naive-loop row is stable across
runs; the two flat rows sit in the noise, so their exact Δ and r wobble
run-to-run — `compare_digest`'s r can even read high while its Δ is under a
nanosecond, which is why the verdict weighs the trend's *magnitude* against a
Welch-z significance gate rather than r alone.)*

The naive early-exit loop produces a **perfect straight line** (*r* = 1.000):
every additional correct byte costs ~67 ns more, because the loop runs one more
iteration before bailing out. That *is* the attack. An adversary tries all 256
values for byte 0, keeps the slowest (the one that made the loop continue), moves
to byte 1, and recovers a 32-byte tag in about **256 × 32 = 8,192 attempts**
instead of 2²⁵⁶.

`hmac.compare_digest` is flat because it accumulates a difference across the
*whole* buffer and checks only at the end — constant-time by construction. Use it
for every secret comparison.

`memcmp` also early-exits *in C*, so in principle it leaks too — and the data
mildly agrees (a weak positive *r* ≈ 0.60 over a ~18 ns spread). But that spread
is buried under Python's ~50–100 ns per-call dispatch noise, so it is not
*exploitable at the Python level*. That is the honest conclusion: the leak exists
in principle, is not measurable through this harness, and is exactly why C
servers must use `CRYPTO_memcmp` rather than `memcmp` for secret tags.

### 7.3 Experiment B — the security-critical post-quantum path

ML-KEM's IND-CCA2 security rests on the **Fujisaki–Okamoto transform with
implicit rejection**. On decapsulation the receiver decrypts, then
**re-encrypts** the recovered message and compares against the ciphertext it
received. On mismatch it does *not* return an error — it silently returns a
pseudorandom value derived from a secret. (Both variants are provably IND-CCA2:
*explicit* rejection returning ⊥ is not insecure. ML-KEM chose *implicit*
rejection because it admits tighter proofs in the quantum random-oracle model and
removes a secret-dependent branch that is hard to implement in constant time.)

The catch: if the valid path and the rejection path take **different amounts of
time**, the timing difference *becomes* the oracle, and chosen-ciphertext attacks
unravel the KEM. This is not hypothetical — it is the KyberSlash class of attack.

We timed ML-KEM-512 decapsulation over three ciphertext classes:

| class (vs valid) | Δ median | relative | *z* | verdict |
|---|---|---|---|---|
| 1 bit flipped | +25 ns | +0.03% | −1.5 | constant-time |
| random bytes | +5 ns | +0.01% | −0.3 | constant-time |

All three overlap within ±1σ. **No oracle detectable at this resolution** — the
expected result for PQClean's patched implementation, now confirmed rather than
assumed.

### 7.4 The methodology, which is the real contribution here

The first version of this experiment produced **wrong verdicts**, and fixing it
is the most instructive part of the phase.

**Trap 1 — a z-test alone over-claims.** With n = 300, |z| > 3 flags differences
of a few nanoseconds that are statistically real but far below anything
exploitable. The first run "found" `compare_digest` leaking at z = 37. The fix:
judge Experiment A by the **monotonic trend** (Pearson *r*) — the rising
staircase *is* the attack — with z as a secondary gate.

**Trap 2 — sequential measurement lets drift impersonate signal.** The first
version measured all of class 1, then class 2, then class 3. The machine warms up
across a run, so class *order* confounds the result. The fix is to
**interleave**: one batch of each class per round, round-robin, so drift spreads
evenly across all classes.

This is not merely asserted — the flawed design is preserved as a **reproducible
control**. Running `python timing_analysis.py --sequential` writes
`results/timing_analysis_sequential.csv`, and the sequential design manufactures
a **spurious "oracle risk" verdict** every time — in the current control run a
+0.18% phantom difference reported significant at **z = +4.7**, and in an
earlier recorded control as extreme as a −55% difference at **z = −18.9** —
caused purely by CPU-state drift, on the *identical operation* that the
interleaved design reports as constant-time (|z| ≤ 1.5). The magnitude and even
the sign of the phantom vary run to run, which is itself the tell: a real leak
would be stable, drift is not.

> A naive measurement design **invents a leak that is not there.** Notably,
> collecting *more samples* would not have helped — it would only have estimated
> the biased value more precisely. Removing a systematic confound requires
> changing the design, not the sample size.

**Trap 3 — reusing one input inflates z.** A single fixed input per class makes
within-class variance artificially tiny, so any per-object cache artefact reads
as hugely significant. The fix: each class cycles a pool of 16 fresh inputs.

### 7.5 What is honestly *not* claimed

The method resolves only leaks that are large relative to desktop timing noise —
Experiment A's hundreds-of-nanoseconds leak is comfortably visible. **KyberSlash
was a few-cycle division timing**, far below this floor, and Experiment B runs
only against already-patched constant-time code, so there is **no positive
control** at that scale. The project therefore does **not** claim it could have
caught KyberSlash; that needs `dudect`-style instruction-level tooling.

---

## 8. Phase 5 — from desktop to device

**Addresses Gap 5.** Script: `code/pqm4_extrapolation.py`. Deep dive:
`code/pqm4_extrapolation_EXPLAINED.md`.

### 8.1 Why this is legitimate and not hand-waving

The obvious objection to the whole project is: *"you measured a laptop; IoT
devices are not laptops."* Correct. So this phase bridges the gap using
**pqm4** — the community-standard benchmark of post-quantum cryptography on the
ARM Cortex-M4, which publishes cycle counts measured on real STM32 silicon.

The crucial detail: **pqm4's "clean" implementations are compiled from the same
PQClean C source that our desktop benchmark runs** (§4.2). So this is one
codebase measured on two CPUs, not a comparison across different libraries.

Honest caveats, stated up front:

* **Cycle counts are the exact metric** because they are clock-independent.
  Millisecond figures are given at **24 MHz** because that is pqm4's convention
  (chosen so flash wait-states don't distort cycle counts). A 168 MHz STM32F407
  would be roughly 5–7× faster, but *not* cleanly so, because of wait-states.
* Cross-platform millisecond comparisons are therefore **indicative, not exact**.
* **Falcon-512 is an asterisk**: its clean reference implementation does not fit
  pqm4's RAM, so its row uses the optimised `m4-ct` implementation. That
  memory-fit fact is itself evidence for the device matrix.

### 8.2 The desktop-to-device gap

| operation | desktop i5 | Cortex-M4 @ 24 MHz | slowdown |
|---|---|---|---|
| ML-KEM-512 encapsulate | 0.154 ms | 29.2 ms | ~190× |
| ML-KEM-512 decapsulate | 0.064 ms | 37.0 ms | ~580× |
| ML-DSA-44 sign | 0.572 ms | 330 ms | ~580× |
| SPHINCS+-128s sign | 1.19 s | **319 s** (5.3 min) | ~270× |

The ~160–580× spread brackets the raw clock ratio of ~190× (≈4.6 GHz vs
24 MHz); instruction-level parallelism, cache and memory bandwidth account for
the variation around it (and current background load on the desktop side pulls
the ratios down somewhat).

**This is where the base paper's framing becomes true.** Phase 2 concluded that
on CPU-class hardware the cost is bandwidth, not computation. On a Cortex-M4 that
partially inverts: ML-KEM is still comfortable at tens of milliseconds, but
ML-DSA signing takes ~330 ms and SPHINCS+ signing takes **minutes**. So
computation re-emerges as a binding constraint **as a function of device class**
— refining rather than contradicting Phase 2, and motivating the matrix in §8.4.

### 8.3 The reality check — the sharpest finding in the project

Now test the base paper's Table 6 against measured cycle counts. Doing this
correctly requires care, and getting it wrong is easy — an earlier draft of this
project did (§9).

**The trap: you must not mix clocks.** pqm4 reports milliseconds at **24 MHz**
(its convention). The paper's Table 3 declares its device as **"ARM Cortex-M4
(120 MHz)"**. Comparing the paper's numbers against pqm4's 24 MHz milliseconds
is a *clock-mismatch error* — it manufactures a discrepancy out of a unit
difference. At the paper's own 120 MHz, the picture is completely different:

| operation | paper | pqm4 @ 120 MHz | paper ÷ pqm4 |
|---|---|---|---|
| Kyber512 encapsulate | 28 ms | 5.84 ms | 4.80× (paper *slower*) |
| Kyber512 decapsulate | 31 ms | 7.41 ms | 4.19× (paper *slower*) |
| **Dilithium2 sign** | 42 ms | 66.05 ms | **0.64× (paper *faster*)** |
| Dilithium2 verify | 36 ms | 17.19 ms | 2.09× (paper *slower*) |

So the paper is *pessimistic* on three operations and *optimistic* on one. No
single scaling factor reconciles them.

**The clock-independent test.** Rather than argue about which clock to assume,
ask: *what clock would each Table 6 entry need in order to be a genuine
cycle-accurate measurement?* Divide pqm4's cycle count by the paper's
milliseconds:

| operation | pqm4 cycles | paper | **implied clock** |
|---|---|---|---|
| Kyber512 encapsulate | 700,605 | 28 ms | **25.0 MHz** |
| Kyber512 decapsulate | 888,653 | 31 ms | **28.7 MHz** |
| Dilithium2 sign | 7,925,955 | 42 ms | **188.7 MHz** |
| Dilithium2 verify | 2,063,096 | 36 ms | **57.3 MHz** |

> **The implied clocks span 25 MHz to 189 MHz — a 7.5× spread, for four
> operations in the same table on the same declared device.** No processor runs
> at four different frequencies at once. Therefore Table 6 **cannot** be
> cycle-accurate measurements of one device at one clock — *whatever* clock you
> assume.

This is the strongest form of the finding precisely because it is
**clock-independent**: it needs no assumption about what hardware or frequency
the paper used. It says the four numbers are *mutually* inconsistent.

**What it does and does not prove.** It does **not** prove the numbers were
fabricated, and you should not say that. The likely explanation is mundane: the
latencies came from some **unstated mapping** — a host measurement, a simulator's
timing model, a scaling factor — rather than from cycle-accurate execution on the
modelled device. That is precisely the Gap 2 complaint (§3): not "no library was
used", but "no methodology was reported, so the numbers cannot be attributed to
anything".

Note also that Dilithium **signing** is the one operation where the paper is
*faster* than measured silicon, and it is also the one operation whose cost is
**data-dependent** (Fiat–Shamir with aborts, §5.5) — the behaviour a fixed-cost
timing model is most likely to under-count. That is suggestive, not proven, and
should be offered as a hypothesis rather than a conclusion.

### 8.4 The device-class recommendation matrix

RFC 7228 classifies constrained devices by memory:

| class | RAM | Flash | character |
|---|---|---|---|
| Class 0 | ≪ 10 KiB | ≪ 100 KiB | motes — cannot run PQC alone; need a gateway |
| Class 1 | ~10 KiB | ~100 KiB | CoAP-class — PQC only with care |
| Class 2 | ~50 KiB | ~250 KiB | can host a PQC stack |
| > Class 2 | — | — | gateways / edge servers — anything |

The base paper's simulated node (64 KiB SRAM / 256 KiB flash) sits at the top of
Class 2. Blending pqm4 latency, published peak-stack usage, and wire size:

* **ML-KEM-512** — the practical KEM floor: ~3 KB stack, sub-40 ms/op. Fits
  Class 1 on compute, but its 800 B key + 768 B ciphertext fragment heavily over
  802.15.4. *The pinch is the radio, not the CPU.*
* **ML-DSA-44** — the binding constraint is its **~50+ KB signing stack**, which
  rules out Class 1 but is comfortable on Class 2 (the paper's node).
* **Falcon-512** — verification is tiny (~11 ms, ~655 B signature), making it
  excellent for **firmware-update verification** on constrained nodes; keygen
  (~3 s) and floating-point-heavy signing belong on a gateway.
* **SPHINCS+** — signing takes minutes on an M4, so only *verification* is
  deployable on-device. Conservative hash-only security, if you can split roles.
* **Hybrid X25519+ML-KEM-768** — +64 B and sub-millisecond over pure ML-KEM: the
  cheap insurance a Class 2 node should take. Below Class 2, offload to a gateway.

The one-line lesson: **match the scheme to the role and the device class.**
Falcon's 3-second key generation sounds disqualifying until you notice that a
sensor verifying firmware only ever runs Falcon *verify*.

---

## 9. How the work was quality-controlled

Benchmark code deserves the same scrutiny as the code it measures, because a
measurement bug produces confident wrong numbers rather than a crash. The project
ran **two independent adversarial review passes**, each using multiple reviewer
"lenses" (cryptographic correctness, measurement methodology, numeric
consistency, a strict-examiner perspective), with **every finding voted on by
three independent agents instructed to *refute* it**. Only findings surviving a
majority vote were treated as real.

**Result: 54 confirmed findings, all fixed** — 22 in a first pass over the
benchmark, 20 in a second over Phases 3–5 plus the report and survey, and 12 in a
third over this very document (which is where the two most serious errors in the
whole project were caught: the overstated Gap 2 claim and the clock-mismatch in
the headline finding).

The ones worth knowing, because they make excellent viva answers:

**Bugs in the measurement code**

* **`--quick` silently did nothing.** Python evaluates default arguments *once,
  at function definition*, so `def bench(fn, budget_s=TIME_BUDGET_S)` froze the
  full-run value; later reassigning the global had no effect. Worse, the
  environment record then *claimed* quick parameters while full ones were used.
  Fixed by reading configuration at call time.
* **Core pinning failed silently.** `GetCurrentProcess()` returns the
  pseudo-handle −1; without explicit `ctypes` type declarations it was truncated
  to 32 bits and both Win32 calls failed — returning `False`, which only got
  noticed because the status string was recorded and printed. *Always check the
  return value of a best-effort syscall.*
* **Unpinned measurement was meaningless** on a hybrid P-core/E-core CPU:
  Falcon-512 signing measured 16 ms unpinned, 4.0 ms pinned.
* **Fixed-count sampling measured the wrong thing** for fast operations (§5.3),
  fixed with batching.
* **Duplicate keygen rows disagreed** — RSA key generation measured twice, minutes
  apart, gave 38 ms and 280 ms as the machine warmed up. Fixed by measuring once
  and reporting the same row in both tables.

**Errors in the claims**

* **The combiner justification was cryptographically wrong** — "preimage
  resistance" where the correct notion is random-oracle/PRF indistinguishability
  (§6.3).
* **An unsupported number**: the report claimed a "~46 µs RNG overhead
  *quantified via calibration*", but the calibration measures `os.urandom` at
  0.13 µs — 350× smaller. Corrected to an explicitly *inferred* quantity (§5.6).
* **Inconsistent figures across files**: hybrid overhead written as +32 B in some
  documents and +64 B in others (the true total); ML-KEM-512's public key written
  as 768 B (that's the *ciphertext*; the key is 800 B).
* **Treating a variable-length value as a constant.** Falcon's signature was
  quoted as an exact figure and checked for equality, but Falcon's compressed
  encoding makes its length *vary per signature*. The benchmark now samples 100
  signatures and records mean/min/max, the documents quote a range, and the
  verifier range-checks that row instead of demanding equality.
* **A clock-mismatch error in the headline finding.** The paper's Table 6 was
  compared against pqm4 milliseconds computed at **24 MHz** while the paper
  declares a **120 MHz** device — which manufactured a "7.9×" discrepancy out of
  a unit mismatch. Replaced by the clock-*independent* implied-clock analysis
  (§8.3), which is both correct and stronger.
* **Two cryptographic misstatements in the explanation**: that *only*
  decapsulation/signing/tag-comparison need be constant-time (keygen and
  encapsulation do too), and that returning an explicit rejection error "would
  itself be an oracle" (both FO variants are provably IND-CCA2).
* **An overstated critique of the base paper.** An earlier draft claimed the
  paper used no real cryptographic library; its §3.6 explicitly names PQClean and
  liboqs. The critique was narrowed to what is actually defensible — that no
  measurement *methodology* is reported (§3, Gap 2).
* **An unreproducible claim.** The report cited a "z = 3.4 false positive" from a
  lost early run. Rather than soften the wording, a `--sequential` control mode
  was added so the effect regenerates on demand — and it turned out **far more
  dramatic** than the original claim (z = −18.9, §7.4).
* **An overclaim** that the method "can catch KyberSlash-scale leaks", removed
  for lack of a positive control (§7.5).

Finally, `code/verify_report_numbers.py` was written so this class of drift is
caught automatically: it re-checks every number quoted in the report against the
CSV it came from. It immediately caught a real problem — see §11.

---

## 10. What the project concludes

**The thesis, in one paragraph:**

> Post-quantum cryptography is *not* primarily a computational problem for IoT.
> On CPU-class hardware, standardised lattice cryptography costs microseconds —
> ML-KEM-512 encapsulation matches optimised elliptic-curve cryptography even
> when compiled as unoptimised portable C. The real cost is **bytes on the wire**:
> 800-byte keys and 2,420-byte signatures against radio frames carrying ~100
> bytes. Computation only becomes binding at microcontroller class, and even
> then only for the *signing*-heavy schemes, not for key establishment. The
> correct engineering response is therefore **role- and device-class-aware scheme
> selection** — plus hybrid key exchange, which costs 64 bytes and buys insurance
> against a cryptanalytic break.

**Against the base paper, specifically:**

1. Its cryptographic design choices are sound and its Kyber modelling matches
   real silicon within 20%.
2. Its optimisation layer optimises the resource that our measurements say was
   *not* the binding constraint at its own device class.
3. Its Table 6 latencies imply four different processor clocks spanning 25–189
   MHz, so they cannot be cycle-accurate measurements of the device it declares
   — the concrete cost of reporting cryptographic timings without a methodology.
4. Its pure-post-quantum design forgoes hybrid protection that our measurements
   price at 64 bytes.
5. It claims forward secrecy while encapsulating against **static** long-term
   KEM keys, which does not provide it — and our ephemeral Phase 3 handshake
   demonstrates the difference.

---

## 11. Current state

### What exists and is verified

* **All five gaps addressed**, each with a working script, a CSV of results, a
  figure, and a deep-dive explanation document.
* **Seven figures** (`results/fig1`–`fig7`), all regenerated from current data.
* **The IEEE report** (`report/report.tex`, IEEEtran + `references.bib`), ready
  to compile on Overleaf — no LaTeX toolchain is installed locally, and
  `report/README.md` gives step-by-step instructions and the figure manifest.
* **The literature survey** (`literature-survey/survey.md`), six threads mapping
  the field onto the gap analysis.
* **All security properties proven** — `test_handshake_security.py` passes 8/8.
* **All Python files compile**, and the full pipeline runs end-to-end.
* **The fixed-length size and byte-count values reconcile exactly** with the
  report (13 of them). Falcon's signature length is **not** among them, because
  it is genuinely variable — it is range-checked instead (§5.5).

### Which run the numbers come from (and how to refresh them)

Every number in this document, `report/report.tex`, `VIVA.md` and
`PROJECT_REPORT.html` traces to the CSVs from the **2026-07-27 full run**
(pinned P-core, browser and editor open — `system_info.txt` records the
environment), and `verify_report_numbers.py` reports **all values reconciled**
against it.

Two full runs are on record, and the difference between them is itself a
finding. The original **idle overnight run (2026-07-17)** measured ML-KEM-512
encapsulation at 0.084 ms; the current **browser-open run** measures 0.154 ms —
roughly **1.6× slower uniformly across every algorithm, classical and
post-quantum alike**, because busy cores drain the shared power/thermal budget
and the pinned core clocks down. Nothing *relative* moved: ML-KEM still sits
within ~8% of ECDH, hybrid still costs +64 B, decapsulation still beats
encapsulation by a fixed-overhead artefact, and the implied-clock finding never
depended on our timings at all. Uniform slowdown, invariant conclusions — live
evidence for the laptop-measurement limitation the report states.

**To refresh on an idle machine (recommended before submission, ~5 minutes):**

```powershell
# close the browser and other heavy apps first
cd "e:\Research Project\CNS\code"
python benchmark_pqc.py            # full run, NOT --quick
python hybrid_handshake.py         # 100 reps (the default)
python timing_analysis.py --sequential
python plot_results.py
python build_html_report.py        # regenerates PROJECT_REPORT.html from the CSVs
python verify_report_numbers.py    # will flag report.tex timing cells to update
```

The HTML report rebuilds itself from the CSVs; `report.tex` Tables I and III
and the verifier's expected values are the two places that need matching by
hand (the verifier's output lists exactly which cells).

One repair from this session worth knowing: the first full re-run crashed
writing `sizes.csv` — `csv.DictWriter` was given `sizes[0].keys()` as the
header, but only the variable-length signature rows carry
`observed_min_bytes`/`observed_max_bytes`, so the first Falcon row raised
`ValueError` (and the half-written file then broke the verifier). The fix
builds the header as the ordered union of keys across all rows with
`restval=""`. The bug was latent from the moment the Falcon range fix added
those fields — it could only trigger on the next *full* run, which is exactly
when it did.

---

## 12. Limitations

Stated plainly, and worth volunteering before an examiner asks:

1. **Implementation asymmetry.** The classical baseline is OpenSSL's hand-tuned
   assembly; post-quantum uses PQClean portable C with no AVX2. Relative
   orderings are trustworthy *within* each family, but classical-versus-PQC gaps
   are **upper bounds on post-quantum cost**. Note this cuts *for* the
   conclusion: ML-KEM matches ECDH *despite* the handicap.
2. **Laptop measurement.** Tens-of-percent variance despite pinning and high
   priority — as §11 demonstrated vividly. Medians, recorded environment, and
   interleaving mitigate but do not eliminate it.
3. **Cross-platform millisecond figures are indicative.** Cycles are the exact
   metric; the Cortex-M4 comparison is qualitative.
4. **The timing analysis is black-box.** It resolves gross leaks only, with no
   few-cycle resolution and no positive control at KyberSlash scale.
5. **The handshake is unauthenticated by design** — key establishment, not a full
   AKE.
6. **Standardised ≠ the paper's exact schemes.** This project benchmarks
   FIPS-final ML-KEM/ML-DSA; the paper cites round-3 Kyber512/Dilithium2. Same
   design lineage and near-identical cost, but **not bit-compatible** — and the
   project's own data proves it: ML-DSA-44's secret key is 2,560 B (the FIPS 204
   size), not round-3's 2,528 B. Similarly, `pqcrypto`'s SPHINCS+ is the v3.1
   submission, not final SLH-DSA.
7. **The blockchain layer was not reimplemented.** It is outside this project's
   cryptographic scope; the paper's inconsistencies there (§3) are noted, not
   investigated.

### Natural next steps

* Authenticated hybrid handshake — add ML-DSA or Falcon signatures over the
  transcript and measure the full AKE cost.
* On-hardware measurement on an actual Cortex-M4 board, replacing extrapolation
  with first-party data.
* Instruction-level constant-time verification (`dudect`, `valgrind --tool=ctgrind`).
* Fragmentation-level simulation over a real 6LoWPAN/802.15.4 stack, to convert
  bytes-on-wire into energy and packet-loss cost.
* An adaptive scheme-selection layer that consumes the device-class matrix — the
  natural realisation of the base paper's own "algorithmic pruning" idea, but
  driven by measured data.

---

## 13. Appendices

### 13.1 File-by-file reference — what every file is and why it exists

The tree first, then every file explained individually.

```
CNS/
├── EXPLANATION.md                      ← this file: the whole story
├── VIVA.md                             defence pack (revise from this)
├── README.md                           overview + gap table + run commands
├── SETUP.md                            environment, troubleshooting, hygiene
├── PROJECT_REPORT.html                 self-contained illustrated report (open in a browser)
├── base-paper/
│   └── s40998-025-01002-1.pdf          the paper being extended
├── literature-survey/
│   └── survey.md                       six-thread survey → gap synthesis
├── code/
│   ├── benchmark_pqc.py                Gap 2+3  primitive benchmarks
│   ├── hybrid_handshake.py             Gap 1    classical/PQ/hybrid handshake
│   ├── test_handshake_security.py      proves the handshake's security claims
│   ├── timing_analysis.py              Gap 4    side-channel analysis
│   ├── pqm4_extrapolation.py           Gap 5    M4 bridge + device matrix
│   ├── plot_results.py                 all seven figures
│   ├── verify_report_numbers.py        guards report numbers against the CSVs
│   ├── build_html_report.py            regenerates PROJECT_REPORT.html from the CSVs
│   ├── benchmark_pqc_EXPLAINED.md      ┐
│   ├── hybrid_handshake_EXPLAINED.md   │ per-script deep dives
│   ├── timing_analysis_EXPLAINED.md    │ (viva prep, one per experiment)
│   └── pqm4_extrapolation_EXPLAINED.md ┘
├── results/                            every number and figure (see §13.1.3)
└── report/
    ├── report.tex                      IEEE report — compile on Overleaf
    ├── references.bib                  bibliography
    ├── PROJECT_REPORT_template.html    the HTML report's template (numbers are filled from CSVs)
    └── README.md                       compile instructions + figure manifest
```

---

#### 13.1.1 The five top-level documents

**`EXPLANATION.md`** *(this file, ~1,050 lines)* — the complete narrative: why
quantum computers break today's cryptography, what the base paper does, the six
gaps, all five phases with their results, how the work was quality-controlled,
what it concludes, and what remains open. **Read this to understand the
project.** Everything else is either a summary of it or an artifact it
describes.

**`VIVA.md`** *(~184 lines)* — the revision document. Contains the 60-second
pitch, the gap→contribution→evidence table, the numbers to memorise, the four
concepts you must be able to explain on demand, ~10 likely examiner questions
with answers, the weaknesses to volunteer *before* being asked, and a live-demo
plan. **Read this the night before, and in the corridor outside.**

**`README.md`** *(~96 lines)* — the front door. Gap table, headline findings,
directory layout, the exact commands to reproduce everything, and the
pre-submission warning about background CPU load. This is what a marker opening
the folder sees first.

**`SETUP.md`** *(~89 lines)* — the environment. Why `pqcrypto` was used instead
of `liboqs-python` (no compiler on this machine), three documented fallback
routes if you ever need liboqs, a verification snippet, and the benchmarking
hygiene rules (AC power, close the browser). **Read this if anything won't
run.**

**`PROJECT_REPORT.html`** — the illustrated, self-contained report: the whole
project (problem → base paper → gaps → all five phases → QA → conclusions →
viva Q&A → glossary) with all seven figures inlined and every table generated
from the CSVs by `build_html_report.py`. Open it in any browser; nothing to
install. **The best single file to show someone, or to present from.**

---

#### 13.1.2 The code — eight Python programs

Each is standalone and runnable from `code/`. Listed in the order you'd run
them.

**`benchmark_pqc.py`** *(560 lines — the largest and most important)*
Closes **Gaps 2 and 3**. Benchmarks 16 schemes — classical (RSA-2048, ECDH
P-256, ECDSA P-256, X25519, Ed25519) against post-quantum (ML-KEM-512/768/1024,
HQC-128, ML-DSA-44/65, Falcon-512/1024, SPHINCS+-128f/s) — measuring
keygen/encapsulate/decapsulate for KEMs and keygen/sign/verify for signatures,
plus every key, ciphertext and signature size.
*Key parts:* `bench()` (the timing engine — time-based warm-up, GC disabled,
batched sampling for sub-millisecond operations), `pin_process()` (pins to one
P-core at high priority), `bench_calibration()` (measures the harness's own
overhead), and correctness preflights that assert every KEM round-trips before
it is timed.
*Produces:* `results/timings.csv`, `results/sizes.csv`, `results/system_info.txt`.
*Run:* `python benchmark_pqc.py` (~3 min) or `--quick` for a ~50 s smoke test
— but note `--quick` **overwrites the canonical CSVs**.

**`hybrid_handshake.py`** *(309 lines)*
Closes **Gap 1**. A real TCP client/server that performs a one-round-trip key
exchange in three modes — pure X25519, pure ML-KEM, and hybrid (the TLS 1.3
`X25519MLKEM768` construction) — then confirms the derived key with an
AES-256-GCM "finished" exchange. Measures handshake latency and *exact*
bytes-on-wire, including length prefixes.
*Key parts:* `derive_key()` (the concatenation combiner, binding mode, level,
both shared secrets and the transcript), `send_frame`/`recv_frame` (length-
prefixed framing, because TCP is a byte stream), `one_handshake()` (the client
side, timed).
*Produces:* `results/handshake_results.csv`.
*Run:* `python hybrid_handshake.py` (all modes, self-hosted server) or the
two-terminal `--server` / `--client` demo.

**`test_handshake_security.py`** *(78 lines)*
Turns the handshake's security *claims* into demonstrated *facts*. Eight
assertions run against the key schedule directly (no sockets): correct
handshakes agree on a key; a tampered transcript makes keys diverge and the
finished check **fail closed**; changing *either* shared secret changes the key
(so knowing only the post-quantum secret is insufficient — the hybrid property);
and a mode downgrade is detected.
*Produces:* PASS/FAIL output; exits non-zero on failure.
*Run:* `python test_handshake_security.py` (~1 s — the best thing to show live).

**`timing_analysis.py`** *(282 lines)*
Closes **Gap 4**. Two experiments. **A**: measures MAC-tag rejection time
against how many bytes an attacker has guessed correctly, for a naive
early-exit loop, C `memcmp`, and `hmac.compare_digest` — the naive loop's
rising staircase *is* the attack. **B**: tests ML-KEM-512 decapsulation for a
timing oracle across valid, one-bit-flipped and random ciphertexts.
*Key parts:* `collect_interleaved()` (measures classes round-robin so thermal
drift can't masquerade as a signal), `collect_sequential()` (the deliberately
flawed control), `pearson()` and `welch_z()` (verdict by monotonic *trend*, not
a raw z-test).
*Produces:* `results/timing_analysis.csv`, and with `--sequential` also
`results/timing_analysis_sequential.csv`.
*Run:* `python timing_analysis.py --sequential` (~2 min; the flag adds the
control that proves the methodology matters).

**`pqm4_extrapolation.py`** *(197 lines)*
Closes **Gap 5**. Bridges desktop measurements to real constrained hardware
using pqm4's published Cortex-M4 cycle counts — the *same PQClean source* this
project benchmarks. Also performs the **clock-independent test** that produced
the project's sharpest finding: dividing pqm4 cycles by the paper's reported
milliseconds yields the clock each figure would need to be genuine (25.0, 28.7,
188.7, 57.3 MHz — a 7.5× spread). Finally derives the RFC 7228 device-class
recommendation matrix.
*Key parts:* `PQM4_CYCLES` (the cited dataset, with its source recorded),
`BASE_PAPER_SIM` (the paper's Table 6), `DEVICE_MATRIX` (scheme → device class).
*Produces:* `results/pqm4_comparison.csv`, `results/device_class_matrix.csv`.
*Run:* `python pqm4_extrapolation.py` (instant — it does no benchmarking).

**`plot_results.py`** *(412 lines)*
Generates all seven report figures from the CSVs. Deliberately uses **dot plots
on log axes** rather than bars (bar *length* is meaningless on a log scale),
one colour per algorithm family, a dagger on quantum-broken schemes so family
is never encoded by colour alone, and direct labels only on extremes.
*Produces:* `results/fig1`–`fig7` PNGs.
*Run:* `python plot_results.py` (a few seconds; skips any figure whose CSV is
absent).

**`verify_report_numbers.py`** *(120 lines)*
The guard against the most embarrassing viva failure: a number in the report
that no longer matches its source CSV. Every headline value is listed with its
origin; sizes and byte counts must match **exactly**, timings are allowed a 20 %
laptop-drift band, and Falcon's signature is **range-checked** because its
compressed encoding is genuinely variable-length.
*Run:* `python verify_report_numbers.py` — **after any benchmark re-run**.

**`build_html_report.py`** *(~330 lines)*
Generates **`PROJECT_REPORT.html`** — the self-contained, illustrated project
report — from `report/PROJECT_REPORT_template.html` plus the CSVs and figures.
Every timing-dependent number and all eight data tables in the HTML are read
from the CSVs at build time (figures are inlined as base64), so the page cannot
drift from the data the way a hand-edited document can; it fails loudly if any
placeholder is left unresolved.
*Run:* `python build_html_report.py` — **after any benchmark re-run** (pairs
with the verifier).

---

#### 13.1.3 `results/` — every number and figure

**CSV data** (all human-readable; open them in Excel if you like):

| file | rows | what it holds |
|---|---|---|
| `timings.csv` | 51 | every operation's median/mean/stdev/min/max, sample count and batch size |
| `sizes.csv` | 17 | public key, secret key, ciphertext/signature and shared-secret sizes |
| `handshake_results.csv` | 6 | latency and bytes-on-wire for the five handshake configurations |
| `timing_analysis.csv` | 27 | Experiment A per-prefix timings + verdicts; Experiment B decaps classes |
| `timing_analysis_sequential.csv` | 6 | the flawed sequential control — proof that measurement design matters |
| `pqm4_comparison.csv` | 22 | desktop vs Cortex-M4, plus implied-clock analysis of the paper's numbers |
| `device_class_matrix.csv` | 9 | RFC 7228 class → scheme suitability, with rationale |
| `system_info.txt` | 16 | CPU model, core count, power plan, AC status, pinning status, library versions — the provenance record for a benchmark run |

**Figures** (all PNG, 200 dpi, generated by `plot_results.py`):

| figure | shows | the point it makes |
|---|---|---|
| `fig1_kem_timings.png` | KEM keygen/encaps/decaps, classical vs PQC | ML-KEM sits alongside ECDH |
| `fig2_sig_timings.png` | signature keygen/sign/verify | families differ by orders of magnitude |
| `fig3_sizes.png` | key and ciphertext/signature sizes | the real PQC cost is bytes |
| `fig4_sign_tradeoff.png` | sign time vs signature size (log-log) | why scheme choice is role-dependent |
| `fig5_handshake.png` | handshake latency + bytes by mode | hybrid costs +64 B |
| `fig6_timing.png` | the tag-comparison leak; decaps constancy | a leak demonstrated, a path shown safe |
| `fig7_pqm4.png` | desktop→M4 gap; implied-clock check | the paper's numbers imply 4 different clocks |

---

#### 13.1.4 `code/*_EXPLAINED.md` — the four per-script deep dives

These sit next to the scripts and explain them **block by block**, with the
reasoning behind each design decision and a rapid-fire Q&A. Use them when you
want to defend a specific experiment in detail; use `VIVA.md` when you want the
cross-cutting story.

* **`benchmark_pqc_EXPLAINED.md`** *(259 lines)* — the timing engine, why median
  over mean, the batching rule, the calibration rows, and the honest treatment
  of the decaps-vs-encaps anomaly.
* **`hybrid_handshake_EXPLAINED.md`** *(104 lines)* — the protocol message by
  message, the three security-critical design choices (combiner, transcript
  binding, and what it deliberately does *not* do), and the results.
* **`timing_analysis_EXPLAINED.md`** *(132 lines)* — both experiments, the three
  measurement traps that were avoided, and what is honestly *not* claimed.
* **`pqm4_extrapolation_EXPLAINED.md`** *(145 lines)* — why the pqm4 bridge is
  legitimate, the clock-mismatch trap and how the implied-clock test avoids it,
  and the device matrix reasoning.

---

#### 13.1.5 `report/`, `literature-survey/`, `base-paper/`

* **`report/report.tex`** *(403 lines)* — the IEEE-format report in `IEEEtran`
  (two-column conference style): abstract, introduction, background, methodology,
  results with three tables and seven figures, discussion, limitations,
  conclusion. **No LaTeX is installed on this machine — compile it on Overleaf**
  (instructions in `report/README.md`).
* **`report/references.bib`** *(181 lines)* — the bibliography: NIST FIPS
  203/204/205, RFC 7228, pqm4, TLS 1.3 hybrid drafts, KyberSlash, PQClean, plus
  the base paper and the works it cites.
* **`report/README.md`** *(49 lines)* — how to compile on Overleaf, which seven
  figures to upload and where, and which two are safest to drop if you hit a page
  limit.
* **`literature-survey/survey.md`** *(179 lines)* — the literature survey,
  organised as six threads (standardisation, constrained hardware, algorithm
  diversity, hybrids, side channels, blockchain+PQC), each ending in the gap it
  creates, followed by a synthesis table mapping threads to this project's
  contributions.
* **`base-paper/s40998-025-01002-1.pdf`** — Narayanan et al. (2026), the paper
  being extended. Every section reference in this document (§3.2, §3.6, §4.9,
  Table 3, Table 6) points here.

---

#### 13.1.6 Things you can ignore

* **`code/__pycache__/`** — Python's compiled bytecode cache, created
  automatically. Not part of the project; safe to delete at any time.
* **`.claude/`** — tooling state, not project content.

### 13.2 Command reference

```powershell
pip install pqcrypto cryptography matplotlib pandas

cd code
python benchmark_pqc.py              # Gap 2+3   (~3 min; --quick for a smoke test)
python hybrid_handshake.py           # Gap 1     (~30 s)
python timing_analysis.py            # Gap 4     (~2 min; --sequential adds the control)
python pqm4_extrapolation.py         # Gap 5     (instant)
python plot_results.py               # fig1–fig7
python test_handshake_security.py    # 8 security properties
python verify_report_numbers.py      # report ↔ CSV consistency
python build_html_report.py          # regenerate PROJECT_REPORT.html
```

Two-terminal handshake demo:
```powershell
python hybrid_handshake.py --server                              # terminal 1
python hybrid_handshake.py --client --mode hybrid --level 768    # terminal 2
```

### 13.3 Glossary

**AEAD** — authenticated encryption with associated data; AES-GCM provides both
confidentiality and integrity, and authenticates extra unencrypted metadata.

**AKE** — authenticated key exchange; key establishment *plus* proof of who you
are talking to. This project's handshake is deliberately *not* one (§6.3).

**Constant-time** — code whose runtime does not depend on secret values.

**Encapsulate / decapsulate** — the KEM operations that create and recover a
shared secret (§5.1).

**FIPS 203 / 204 / 205** — the NIST standards for ML-KEM, ML-DSA and SLH-DSA.

**FO transform (Fujisaki–Okamoto)** — the construction turning a weaker
(IND-CPA) encryption scheme into a strong (IND-CCA2) KEM, using re-encryption
plus implicit rejection (§7.3).

**Fiat–Shamir with aborts** — ML-DSA's signing loop, which retries until a
candidate signature leaks nothing about the secret key; the reason signing time
varies (§5.5) and, most likely, the reason the base paper's simulation was 8×
optimistic (§8.3).

**Harvest-now-decrypt-later** — recording encrypted traffic today to decrypt it
once quantum computers arrive (§1.2).

**Hybrid (key exchange)** — deriving a key from both a classical and a
post-quantum exchange (§6). *Not* to be confused with hybrid *encryption*
(public-key establishes a symmetric key, which then encrypts the data).

**IND-CCA2** — the strong security notion a KEM should meet: secure even against
an attacker who can submit chosen ciphertexts for decapsulation.

**KEM** — key encapsulation mechanism (§5.1).

**KyberSlash** — 2023–24 timing attacks recovering Kyber keys via
secret-dependent division timing (§3, §7).

**NIST security categories 1/2/3/5** — attack cost at least that of key search on
AES-128 / collision search on SHA-256 / key search on AES-192 / key search on
AES-256.

**PQClean** — the reference collection of clean, portable post-quantum C
implementations; the upstream that both `pqcrypto` and pqm4 build on (§4.2).

**pqm4** — the Cortex-M4 post-quantum benchmarking project whose published cycle
counts anchor Phase 5 (§8).

**RFC 7228** — the IETF document defining constrained-device Classes 0/1/2 (§8.4).

**Shor's / Grover's algorithms** — the quantum algorithms that break public-key
cryptography and weaken symmetric cryptography respectively (§1.1).

**SIKE** — a NIST candidate broken classically in 2022; the cautionary tale
motivating hybrids (§1.4).
