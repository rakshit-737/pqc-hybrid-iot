# `timing_analysis.py` — Explanation and Viva Prep

## 0. Why this exists (Gap 4)

PQShield-IoT does **no** side-channel or timing analysis. Yet timing is the
side channel that has broken real post-quantum code: **KyberSlash** (Dec 2023–
2024) recovered Kyber secret keys because reference decapsulation performed a
secret-dependent division whose time leaked; PQClean and the reference Kyber
were patched. A project that benchmarks these schemes but never asks "does the
runtime leak the secret?" is incomplete. This phase asks it two ways.

## 1. The one idea

> **Timing is a side channel whenever execution time correlates with secret
> data.** The fix is *constant-time* code: run time depends only on public
> things (input length), never on secret values or on whether a check passed.

Which operations must be constant-time? Only the ones that **touch secrets**:
decapsulation (secret key), signing (secret key), and MAC/tag comparison
(secret tag). **Signature *verification* uses only public inputs** (public
key, message, signature), so its variable time is *not* a vulnerability —
stating this distinction unprompted is worth marks, and it's why Experiment B
targets decapsulation, not verify.

## 2. Experiment A — a leak you can watch happen

**Setup.** A server compares a received MAC tag against the correct 32-byte
tag. We measure rejection time as a function of how many leading bytes the
attacker already guessed correctly (the *matching prefix*), for three
comparison functions.

**Result (this machine):**

| comparison | Δ(prefix31 − prefix0) | Pearson r | verdict |
|---|---|---|---|
| naive Python loop (`for x,y: if x!=y: return`) | **+2,081 ns** | **+1.000** | **LEAKS** |
| `bytes ==` (C memcmp) | +18 ns (noisy) | 0.600 | no exploitable trend |
| `hmac.compare_digest` | +0.9 ns | +0.832 | no exploitable trend |

*(The two flat rows sit in the noise, so their Δ and r wobble run to run —
`compare_digest`'s r can even read high while its Δ stays under a nanosecond,
which is why the verdict weighs the trend's magnitude against a z-gate, not r
alone.)*

**How to read it (and Fig 6, left panel):**

* The naive loop is a **perfect rising staircase** — each extra correct byte
  costs ~67 ns more, because the loop runs one more iteration before it
  exits. r = +1.000 is not a coincidence; it is the attack. An attacker tries
  all 256 values for byte 0, keeps the slowest (the one that made the loop
  proceed), moves to byte 1, and recovers a 32-byte tag in ~256 × 32 = 8,192
  tries instead of 2²⁵⁶. This is the classic *early-exit comparison* leak.
* `compare_digest` is **dead flat** (sub-nanosecond Δ): it always
  XOR-accumulates across the whole buffer and only checks the accumulator at
  the end, so time depends on length alone. This is what "constant-time by construction" looks
  like — use it for every secret comparison.
* `memcmp` early-exits *in C*, so in principle it also leaks — but the
  per-byte cost (~ns) is **below Python's ~50–100 ns per-call dispatch
  noise**, so no trend is measurable through the interpreter (high variance,
  r not significant). Honest conclusion: *at the Python level it is not
  exploitable; in a C server it would be* — which is exactly why C servers
  must use `CRYPTO_memcmp`, not `memcmp`, for tags.

## 3. Experiment B — the security-critical PQC path

**Setup.** ML-KEM's IND-CCA2 security rests on the Fujisaki–Okamoto
*implicit rejection*: decapsulation decrypts, **re-encrypts**, and compares to
the received ciphertext; on mismatch it returns a pseudorandom
`H(z ‖ ct)` **instead of erroring**. If the valid path and the rejection path
took different time, an attacker could feed crafted ciphertexts and learn from
the timing whether each decrypted "correctly" — a chosen-ciphertext oracle
that unravels the KEM. We time ML-KEM-512 decapsulation over three ciphertext
classes and test whether they differ.

**Result (this machine):**

| class (vs valid) | Δ median | relative | z | verdict |
|---|---|---|---|---|
| 1 bit flipped | +25 ns | +0.03% | −1.5 | constant-time |
| random bytes | +5 ns | +0.01% | −0.3 | constant-time |

All three overlap within ±1σ (Fig 6, right panel). No measurable
timing difference → **no oracle detectable at this resolution**. This is the
*expected* result for PQClean's patched implementation, and the phase confirms
it rather than assuming it. Caveat to state honestly: this is black-box
wall-clock timing on a desktop. It only resolves leaks that are **large
relative to the timing noise** — the hundreds-of-nanoseconds tag leak in
Experiment A is well within reach, but KyberSlash was a *few-cycle*
secret-dependent division, far below this floor. We have **no positive
control** at that scale (Experiment B runs only against already-patched
constant-time code), so we do **not** claim we could have caught KyberSlash — a
few-cycle audit needs `dudect`/instruction-level tooling, which is future work.

## 4. The methodology fixes — the real substance of this phase

The first version of this script produced **wrong verdicts**, and rescuing it
is itself the viva story (it shows you understand measurement, not just
crypto). Three traps, all now handled — see the module docstring:

1. **A z-test alone over-claims.** With n=300, |z|>3 flags differences of a
   few nanoseconds that are statistically real but far below anything
   exploitable. The first run "found" `compare_digest` leaking at z=37. Fix:
   Experiment A's verdict is the **monotonic trend** (Pearson r of time vs
   prefix) *weighted by its magnitude* — the rising staircase *is* the attack —
   with z as a secondary gate. compare_digest's sub-nanosecond Δ correctly
   reads as "no exploitable trend" even when its r wobbles high.
2. **Sequential measurement lets drift masquerade as signal.** Measuring all
   of class 1, then class 2, then class 3 lets the machine warm up across the
   run, so class order confounds the result. Fix: **interleave** the classes
   round-robin (one batch of each per round) so drift is spread evenly. This
   is not just asserted — the flawed design is kept as a **reproducible
   control**: run `python timing_analysis.py --sequential` and it writes
   `results/timing_analysis_sequential.csv`. The sequential design
   manufactures a **spurious "oracle risk" verdict** — in the current control
   run a +0.18 % phantom difference reported significant at **z = +4.7**, and
   in an earlier recorded control a −55 % difference at **z = −18.9** — pure
   CPU-state drift, while the interleaved run of the *same* operation reads
   constant-time (|z| ≤ 1.5). *That contrast is the single best evidence in
   the project that measurement design matters.* (The exact sequential z
   varies run to run — even its sign flips — because it is a drift artifact;
   the point is that it reports significance at all, and that it disappears
   under interleaving, both regenerable on demand.)
3. **Reusing one input inflates z.** A single fixed candidate per class makes
   within-class variance artificially tiny, so any per-object cache artifact
   reads as hugely significant. Fix: each class cycles a **pool of 16 fresh
   inputs**.

## 5. Statistics used (no scipy)

* **Batch-mean samples** (like the benchmark): each sample times a batch of
  calls and divides, lifting fast operations above timer granularity.
* **Welch z** = (mean₁−mean₂)/√(s₁²/n₁+s₂²/n₂): a two-sample difference test
  that does not assume equal variances; with n in the hundreds it is ≈ N(0,1)
  under the null, so |z|>3 ≈ 99.7% confidence *of a difference existing* (not
  of it being exploitable — hence the trend gate in A).
* **Pearson r**: correlation of median time with prefix length; the
  exploitability measure for the tag-comparison leak.

## 6. Rapid-fire viva Q&A

* **Q: Why not just use `==` for tag comparison?** In C it early-exits and
  leaks the tag byte-by-byte via timing (the naive-loop curve is that leak,
  made visible). Always `hmac.compare_digest` / `CRYPTO_memcmp` for secrets.
* **Q: Your memcmp didn't show a leak — so it's safe?** No — it's *below my
  measurement floor at the Python level*. The correct claim is "not
  detectable here", and the mitigation (constant-time compare) is used
  regardless, because a C deployment would expose it.
* **Q: Why is verify allowed to be variable-time but decaps is not?** Verify
  consumes only public inputs; there is no secret whose value could leak.
  Decaps consumes the secret key, so its time must not depend on secret data.
* **Q: What was KyberSlash?** A 2023–24 timing attack: reference Kyber
  decapsulation did a division whose operand depended on secret data, so its
  time leaked key bits. Patched in the reference code and PQClean — which is
  why my Experiment B, on current PQClean, shows constant time.
* **Q: Could a real attacker exploit a 150 ns difference over a network?**
  Network jitter (ms) dwarfs it, but attackers average over millions of
  queries to pull sub-ns signals out of noise (that's how Lucky-13 and
  KyberSlash worked). "Too small to matter" is never a safe defense — the
  code must be constant-time by construction.
* **Q: Why interleave instead of just running longer?** Running longer
  doesn't remove a *systematic* confound — if class 3 is always measured on a
  hotter CPU, more samples just estimate the biased value more precisely.
  Interleaving removes the bias itself.
