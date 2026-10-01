# Viva Defence Pack

One document to revise from. The `code/*_EXPLAINED.md` files go deep on each
script; this one is the cross-cutting narrative, the numbers to know cold, and
the questions you will actually be asked.

---

## 1. The 60-second pitch (memorise the shape, not the words)

> The base paper, PQShield-IoT, builds a quantum-resistant IoT framework from
> Kyber512, Dilithium2, AES-256-GCM and a permissioned blockchain. The design is
> sound, but **every performance number in it is simulated** — NS-3 and
> Contiki-NG on emulated Cortex-M4 profiles. It does say it used the PQClean and
> liboqs libraries, but it never reports *how* its latencies were obtained: no
> host, no timing method, no repetition count, no variance. It also fixes on one
> signature scheme, uses pure post-quantum rather than hybrid key exchange, and
> does no side-channel analysis.
>
> I addressed those four gaps with real measurements on a laptop, plus a fifth
> integrative contribution. My headline finding reframes the problem: **on
> CPU-class hardware, post-quantum cryptography is computationally cheap — its
> real cost is bytes on the wire.** ML-KEM-512 encapsulation takes 0.154 ms,
> within 8% of optimised ECDH on the same machine, but it puts 800-byte keys on
> a radio whose frames carry about 100 bytes. And when I checked the paper's four
> reported latencies against measured Cortex-M4 cycle counts, they imply four
> *different* processor clocks — 25, 29, 189 and 57 MHz — so they cannot be
> cycle-accurate measurements of the 120 MHz device the paper declares, whatever
> clock you assume.

---

## 2. Gap → contribution → evidence (the table to have in your head)

| # | Gap in the paper | What I built | The number that proves it |
|---|---|---|---|
| 1 | Pure PQC, no hybrid | Socket handshake: classical / PQ / hybrid | hybrid costs **+64 B, ~0.6 ms** over pure ML-KEM-768 |
| 2 | Results simulated, not measured | Benchmark suite, 16 schemes, real libraries | ML-KEM-512 encaps **0.154 ms** ≈ ECDH **0.143 ms** (within 8%) |
| 3 | Dilithium2 only | ML-DSA vs Falcon vs SPHINCS+, time *and* size | Falcon verify **0.066 ms**; SPHINCS+-128s sign **1.19 s** |
| 4 | No side-channel analysis | Tag-compare leak + ML-KEM decaps oracle test | leak **r = +1.000**; decaps **\|z\| ≤ 1.5** (constant-time) |
| 5 | — (integrative) | pqm4 Cortex-M4 extrapolation + RFC 7228 matrix | paper's 4 latencies imply **25–189 MHz** clocks (7.5× spread) |
| 6 | Claims forward secrecy with **static** KEM keys | ephemeral Phase-3 handshake | compromise of `sk_kem` would expose every recorded session |

---

## 3. Numbers to know cold

**Sizes (bytes) — the heart of the argument**

| | public key | ct/sig |
|---|---|---|
| X25519 / Ed25519 | 32 | 32 / 64 |
| ECDH P-256 | 65 | 65 |
| ML-KEM-512 | **800** | **768** |
| ML-DSA-44 | 1312 | **2420** |
| Falcon-512 | 897 | **~655** (variable; 752 max) |
| SPHINCS+-128s / -128f | 32 | 7 856 / 17 088 |

*802.15.4 frame payload ≈ 100 B → everything post-quantum fragments.*

**Times (desktop medians, ms — 2026-07-27 run)**: ML-KEM-512
keygen/encaps/decaps 0.138 / 0.154 / 0.064 · ML-DSA-44 sign 0.572, verify
0.141 · Falcon-512 sign 6.41, verify 0.066 · SPHINCS+-128s sign 1189 ·
RSA-2048 keygen 62 (max 235).

**Handshake (bytes / median ms)**: classical 202 / 1.06 · pure ML-KEM-768
2410 / 1.64 · hybrid-768 **2474 / 2.26**.

**Cortex-M4 @ 24 MHz (pqm4, cited)**: ML-KEM-512 encaps 29.2 ms, decaps 37.0 ms
· ML-DSA-44 sign 330 ms · SPHINCS+-128s sign **319 s**. Desktop→M4 slowdown
≈ 160–580×.

**Paper vs real silicon — the clock-independent test** (pqm4 cycles ÷ paper's ms
= the clock each entry would need): Kyber encaps **25.0 MHz** · Kyber decaps
**28.7 MHz** · Dilithium2 sign **188.7 MHz** · Dilithium2 verify **57.3 MHz**.
Paper declares **120 MHz** (its Table 3). A 7.5× spread — no single processor.

---

## 4. The four ideas you must be able to explain on demand

**KEM vs key exchange.** A KEM never encrypts user data. The sender
*encapsulates* against the receiver's public key, producing a ciphertext plus a
shared secret; the receiver *decapsulates* to recover the same secret. Data then
goes under AES-256-GCM. In classical DH both sides send public keys; in a KEM
only a ciphertext comes back — that asymmetry is the whole DH→KEM shift.

**Why hybrid.** A hybrid derives the session key from *both* an X25519 and an
ML-KEM secret, so an attacker must break ECDLP **and** Module-LWE. Under the
random-oracle model the key is indistinguishable from random while *either*
secret is unknown. This counters harvest-now-decrypt-later, and my measurement
says it costs 64 bytes.

**Why constant-time matters.** Timing is a side channel whenever runtime depends
on secret data. *Every* operation handling secret material must be constant-time
— key generation, encapsulation (it produces the shared secret), decapsulation,
signing, and secret-tag comparison. The notable exception is **signature
verification, which uses only public inputs, so its variable timing is not a
vulnerability**. Saying that exception unprompted scores well.

**Rejection sampling.** ML-DSA signs by Fiat–Shamir *with aborts* — it retries
until a candidate signature leaks nothing about the key. That's why sign time
varies, and it's my *hypothesis* (not a proven cause) for why signing is the one
operation where the paper's number falls on the optimistic side: a fixed-cost
timing model would under-count the retries.

---

## 5. Questions you will get, with answers

**"Your results are on a laptop. Why should I believe anything about IoT?"**
Two answers. First, I never claim laptop numbers *are* IoT numbers — I extend
them with pqm4's published Cortex-M4 cycle counts, compiled from the *same
PQClean C source* my benchmark runs, so it's one codebase on two CPUs. Second,
the base paper has no hardware measurement at all; measured-plus-cited is
strictly stronger evidence than simulated.

**"Your classical baseline is optimised assembly and your PQC is plain C. Isn't
that unfair?"** It is asymmetric, and I state it as a limitation — but it's
*conservative* for my conclusion. The handicap makes PQC look worse, so
"ML-KEM matches ECDH" holds despite it. What I do *not* claim is precise
classical-vs-PQC ratios; those are upper bounds on PQC cost.

**"Why is your decapsulation faster than encapsulation? The literature says the
opposite."** Correct, and it's a measurement artefact, not physics. Decaps does
more work (it decrypts *and* re-encrypts for the FO check). The randomised
operations (keygen/encaps) carry a fixed extra cost inside the C library, shown
by the encaps−decaps gap staying the same order (~75–110 µs this run; a nearly
constant 49/46/43 µs on the idle-machine run) while the algorithm's cost
scales. Crucially, my `os.urandom` calibration (0.20 µs) does **not** quantify
that gap — so I *infer* it rather than claim to have measured it, and for
decaps-vs-encaps ordering I defer to pqm4's cycle counts.

**"How do you know your timing analysis isn't measuring noise?"** Because I
built the control. Run `timing_analysis.py --sequential` and the flawed
non-interleaved design manufactures a phantom "oracle" verdict — **z = +4.7 in
the current control run, z = −18.9 in an earlier recorded one** — purely from
CPU-state drift; the interleaved design on the same operation reads |z| ≤ 1.5.
The phantom's size and even sign change run to run, which is exactly how you
know it's drift, not a leak. Interleaving removes a *systematic* confound that
more samples would only estimate more precisely.

**"You found ML-KEM constant-time. Would you have caught KyberSlash?"** No, and I
say so in the report. KyberSlash was a few-cycle division leak; my resolution
floor is set by desktop noise — hundreds of nanoseconds, which is why the
Experiment A leak is visible. I have no positive control at KyberSlash scale, so
that would need `dudect`-style instruction-level tooling.

**"Falcon keygen takes ~3 seconds on an M4. Why recommend it for IoT?"**
Because role matters more than scheme. A sensor verifying firmware updates only
ever runs Falcon *verify* — 11 ms on an M4 with a ~655-byte signature, the best
verify-side profile measured. Keygen and signing happen once, on the vendor's
gateway. That is precisely what the RFC 7228 matrix encodes.

**"Is your handshake secure?"** As a *key exchange*, yes — and I proved the
properties (`test_handshake_security.py`: tamper fails closed, downgrade
detected, knowing only the PQ secret is insufficient). But it is deliberately
**unauthenticated** — an ephemeral exchange, not a full AKE, so a MITM can sit
in the middle. Authentication is the signature layer's job; that's the paper's
blockchain-registered Dilithium identities, and my Phase-2 benchmarks price it.

**"What's wrong with the base paper?"** I'd avoid "wrong". Its integration and
primitive choices are reasonable. Two substantive issues: (1) its *evaluation
methodology* — it reports latencies with no host, no timing method, no repetition
count and no variance, and those four numbers imply mutually incompatible clocks
(25–189 MHz) against measured cycle counts; (2) it claims **forward secrecy**
while encapsulating against **static** long-term KEM keys, which does not provide
it — compromise of `sk_kem` would expose every recorded session. Separately, it
describes its ledger inconsistently (Fabric in Table 3, Sawtooth in §3.6, a
DAG-based ledger in the same section), its node counts vary (15 vs 50–200), and
its comparison table lists SIKE as quantum-resilient although SIKE was broken
classically in 2022. Those last ones I raise as limitations worth investigating,
not accusations.

**"Careful — doesn't the paper say it used real PQC libraries?"** Yes, and I say
so: §3.6 names PQClean and liboqs. My critique is *not* "no library was used" —
that would be false. It's that no measurement **methodology** is reported, so the
numbers can't be attributed to anything. And because the paper used PQClean,
which is the same source pqm4 compiles, my cycle-count comparison is
same-codebase — which makes it harder to dismiss, not easier.

**"What did you get wrong, and how do you know?"** Best question to be ready
for — see §6.

---

## 6. Weaknesses to raise *before* the examiner does

Volunteering these reads as competence, not weakness.

1. **Implementation asymmetry** (optimised OpenSSL vs portable-C PQC) — bounds
   every classical-vs-PQC ratio to an upper bound on PQC cost.
2. **Laptop measurement** — tens-of-percent variance despite core pinning and
   high priority; I report medians, record the environment, and interleave.
3. **Cross-platform ms are indicative** — cycles are the exact metric; the M4
   comparison is qualitative.
4. **The timing analysis is black-box** — gross leaks only, no few-cycle
   resolution, no positive control at KyberSlash scale.
5. **The handshake is unauthenticated by design** — key establishment, not AKE.
6. **Standardised ≠ the paper's schemes.** I benchmark FIPS-final ML-KEM/ML-DSA;
   the paper cites round-3 Kyber512/Dilithium2. Same design lineage,
   near-identical cost, but *not* bit-compatible — my own data shows it
   (ML-DSA-44 secret key is 2560 B, FIPS-204's size, not round-3's 2528 B).

**Bugs I found in my own work** (have one ready — it shows real engineering):
a `--quick` flag that silently did nothing because Python binds default
arguments at definition time; a core-pinning call that failed silently until I
gave ctypes an explicit `HANDLE` type; a Falcon sign time of 16 ms that became
4 ms once the process was pinned to a performance core; a `csv.DictWriter`
header taken from the first row that crashed the whole sizes export the first
time a variable-length Falcon row appeared; and a security justification I had
to correct from "preimage resistance" to random-oracle indistinguishability.
Three independent adversarial review passes over the code and write-ups
produced 54 confirmed findings in total, all fixed.

---

## 7. Live demo plan (if asked to show something)

Fastest, most impressive order — each is one command from `code/`:

1. `python test_handshake_security.py` — 8 security properties, ~1 s, all PASS.
2. `python hybrid_handshake.py` — the three modes with latency and bytes, ~30 s.
   (Two-terminal version: `--server` then `--client --mode hybrid --level 768`.)
3. `python timing_analysis.py --sequential` — the leak *and* the methodology
   control. If time is short, just show `results/fig6_timing.png`.
4. `python benchmark_pqc.py --quick` — the full suite, ~50 s.

Have `results/fig4_sign_tradeoff.png` and `fig7_pqm4.png` open in tabs: they
carry the two headline stories (role-based scheme choice; simulated vs measured).

---

## 8. If you have five minutes before you walk in

Read §1, then the three rows of §3 in bold, then the "what did you get wrong"
answer. Everything else you can reason out from the four ideas in §4.
