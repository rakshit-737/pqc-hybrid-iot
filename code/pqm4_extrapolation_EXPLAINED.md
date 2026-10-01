# `pqm4_extrapolation.py` — Explanation and Viva Prep

## 0. Why this exists (Gap 5, and the answer to "you have no hardware")

The base paper only *simulated* Cortex-M4F devices. We have no board either —
but we do not need to guess. **pqm4** is the community-standard benchmark of
PQC on the ARM Cortex-M4, and its "clean" cycle counts are compiled from the
**same PQClean C source** our desktop benchmark runs through `pqcrypto`. So
this phase is one codebase on two CPUs:

* our Intel i5-13500H (measured, Phase 2), and
* a real STM32 Cortex-M4 at 24 MHz (pqm4's published cycle counts).

That is the cleanest cross-platform statement possible without owning the
silicon, and it is grounded in *independent, real-hardware* numbers rather
than a simulator — which is precisely the evidence gap in the base paper.

## 1. The data and the honest caveats

* **Source:** pqm4 `benchmarks.md`, clean implementations, measured at
  **24 MHz** (github.com/mupq/pqm4). pqm4 uses 24 MHz deliberately so that
  flash wait-states do not distort the cycle counts.
* **Cycles are the primary metric** — they are clock-independent. We convert
  to milliseconds at 24 MHz because that is what pqm4 reports; a 168 MHz
  STM32F407 deployment is ~5–7× faster but pays flash wait-states, so it is
  *not* a clean 7×. Cross-platform millisecond comparisons are therefore
  **indicative, not exact** — say this out loud.
* **Falcon-512 is the one asterisk:** its clean reference implementation does
  not fit pqm4's RAM (Falcon's key generation needs large working memory), so
  its row uses the optimized `m4-ct` implementation. That memory-fit fact is
  itself evidence for the device matrix (Falcon keygen is a poor fit for
  constrained nodes), and it is flagged in the CSV `impl` column.

## 2. Result 1 — the desktop→device gap (Fig 7, left panel)

Same clean-C source, median latency:

| operation | desktop i5 | Cortex-M4 @24 MHz | slowdown |
|---|---|---|---|
| ML-KEM-512 encapsulate | 0.154 ms | 29.2 ms | ~190× |
| ML-KEM-512 decapsulate | 0.064 ms | 37.0 ms | ~580× |
| ML-DSA-44 sign | 0.572 ms | 330 ms | ~580× |
| SPHINCS+-128s sign | 1.19 s | **319 s** (5.3 min) | ~270× |

Two things to take from this:

1. **The slowdown is ~160–580×**, bracketing what you expect from a ~4.5 GHz
   wide superscalar P-core with megabytes of cache versus a 24 MHz in-order
   M4 (the raw clock ratio alone is ~190×; IPC, cache and memory bandwidth
   account for the variation around it).
2. **This is where the base paper's framing becomes true.** In Phase 2 the
   headline was "on CPU-class hardware, PQC cost is bytes-on-wire, not
   compute." On the M4 that inverts: ML-KEM is still fine (tens of ms), but
   ML-DSA signing is ~330 ms and SPHINCS+ signing is *minutes*. So compute
   re-emerges as a real constraint **as a function of device class** — which
   is exactly what the RFC 7228 matrix (§4) captures, and it refines rather
   than contradicts the Phase-2 conclusion.

## 3. Result 2 — the reality check on the paper's simulated numbers (right panel)

This is the sharpest finding — but only when done **clock-correctly**, and an
earlier version of this analysis got it wrong in a way worth understanding.

**The trap.** pqm4 reports milliseconds at **24 MHz** (its convention). The base
paper declares its device as **"ARM Cortex-M4 (120 MHz)"** (its Table 3).
Comparing the paper's numbers against pqm4's *24 MHz* milliseconds is a
**clock-mismatch error** — it manufactures a discrepancy out of a unit
difference. The earlier version of this document did exactly that and reported a
headline "7.9× optimistic" figure that does not survive scrutiny.

**At the paper's own declared 120 MHz:**

| operation | paper | pqm4 @ 120 MHz | paper ÷ pqm4 |
|---|---|---|---|
| Kyber512 encapsulate | 28 ms | 5.84 ms | 4.80× (paper slower) |
| Kyber512 decapsulate | 31 ms | 7.41 ms | 4.19× (paper slower) |
| Dilithium2 sign | 42 ms | 66.05 ms | **0.64× (paper faster)** |
| Dilithium2 verify | 36 ms | 17.19 ms | 2.09× (paper slower) |

Pessimistic on three, optimistic on one — no single scaling reconciles them.

**The clock-independent test (the real finding).** Instead of arguing about
which clock to assume, ask what clock each entry *would need* to be a genuine
cycle-accurate measurement — divide pqm4's cycles by the paper's milliseconds:

| operation | pqm4 cycles | paper | **implied clock** |
|---|---|---|---|
| Kyber512 encapsulate | 700,605 | 28 ms | **25.0 MHz** |
| Kyber512 decapsulate | 888,653 | 31 ms | **28.7 MHz** |
| Dilithium2 sign | 7,925,955 | 42 ms | **188.7 MHz** |
| Dilithium2 verify | 2,063,096 | 36 ms | **57.3 MHz** |

> The implied clocks span **25–189 MHz, a 7.5× spread**, for four operations on
> one declared device. No processor runs at four frequencies at once, so Table 6
> cannot be cycle-accurate measurements of one device — *whatever* clock is
> assumed. This is strong precisely because it needs **no** assumption about the
> hardware.

**Framing for the viva.** Not "the paper is wrong" and *certainly* not
"fabricated". The defensible claim: the four latencies are **mutually
inconsistent** with measured cycle counts, which points to their coming from an
**unstated mapping** (a host measurement, a simulator timing model, a scaling
factor) rather than cycle-accurate execution on the modelled device. That is
precisely the Gap-2 complaint: not that no library was used — the paper says it
used PQClean and liboqs — but that **no methodology was reported**, so the
numbers cannot be attributed to anything.

Worth adding as a *hypothesis, not a conclusion*: signing is both the lone
operation in the optimistic direction and the lone operation whose cost is
**data-dependent** (Fiat-Shamir with aborts — our Phase-2 data shows the
intrinsic variance), which is exactly what a fixed-cost timing model would
under-count.

## 4. Result 3 — the RFC 7228 device-class matrix (`device_class_matrix.csv`)

RFC 7228 classifies constrained devices by memory:

| class | RAM | Flash | example |
|---|---|---|---|
| Class 0 | ≪ 10 KiB | ≪ 100 KiB | motes — cannot run PQC alone, need a gateway |
| Class 1 | ~10 KiB | ~100 KiB | CoAP-class — PQC only with care |
| Class 2 | ~50 KiB | ~250 KiB | can host a PQC stack |
| > Class 2 | — | — | gateways / edge servers — anything, incl. hybrids |

The base paper's simulated node (64 KiB SRAM / 256 KiB Flash, Cortex-M4F)
sits at the **top of Class 2**. Suitability blends three costs — pqm4 latency,
published peak-stack usage, and wire size (from `sizes.csv`):

* **ML-KEM-512** is the practical KEM floor: ~3 KB stack, sub-40 ms/op. Fits
  Class 1 on compute, but its 800 B key + 768 B ciphertext *fragment heavily*
  over 802.15.4's ~100 B payloads — the wire cost, not the CPU, is the pinch.
* **ML-DSA-44**: the binding constraint is its **~50+ KB signing stack**,
  which is why it is "caution" on Class 1 but comfortable on Class 2 (the
  paper's node).
* **Falcon-512**: verification is tiny (~11 ms, ~655 B signature — variable
  length, 752 B max) → excellent for **firmware-update verification** on
  constrained nodes; but keygen (~3 s) and FP-heavy signing belong on a gateway.
* **SPHINCS+**: signing is minutes on the M4 → only its verification is
  deployable on-device; sign off-device. Conservative (hash-only) security
  when you can afford that split.
* **Hybrid X25519+ML-KEM-768** (Phase 3): +64 B total on the wire (+32 B each
  way) and sub-ms over pure ML-KEM — the cheap insurance a Class 2 node should
  take; below Class 2, offload.

The one-line recommendation the matrix encodes: **match the scheme to the
role and the device class** — ML-KEM everywhere it fits, ML-DSA for signing on
Class 2+, Falcon when the device mostly *verifies*, SPHINCS+ only where
signing is rare and off-device, and hybrids wherever the budget allows.

## 5. Rapid-fire viva Q&A

* **Q: You didn't run on hardware — why trust these M4 numbers?** They are
  pqm4's published, real-silicon cycle counts for the *same PQClean source*
  I benchmarked on desktop; I am citing an independent standard measurement,
  not simulating. Cross-platform ms are indicative; cycles are exact.
* **Q: Why 24 MHz — real M4s run faster?** pqm4's convention: at higher clocks
  flash wait-states make cycle counts non-comparable. Cycles are the honest
  metric; 24 MHz ms are a consistent reference, and I note the ~5–7× headroom.
* **Q: Your biggest finding here?** Divide pqm4's measured cycle counts by the
  paper's reported milliseconds and you get the clock each figure would need to
  be real: 25, 29, 189 and 57 MHz — a 7.5× spread on one declared 120 MHz
  device. They can't be cycle-accurate measurements, whatever clock you assume.
  It needs no assumption about the hardware, which is why it holds up.
* **Q: Why not just compare milliseconds directly?** Because pqm4 reports at
  24 MHz and the paper declares 120 MHz — comparing those directly is a
  clock-mismatch error that invents a discrepancy. An earlier draft of mine did
  exactly that and it was caught in review.
* **Q: The paper's device was 64 KB/256 KB — is that even constrained?** It's
  top-of-Class-2 in RFC 7228 — genuinely constrained but comfortable for
  ML-KEM + ML-DSA. My matrix shows what breaks one class *down* (Class 1),
  which is where their design would actually struggle.
* **Q: Why is Falcon good for IoT if its keygen takes 3 seconds?** Role
  matters: a device that *verifies* firmware signatures only ever runs Falcon
  verify (~11 ms, tiny signature). Keygen/sign happen once, on the vendor's
  gateway. Matching operation to device is the whole point of the matrix.
