# This Project, Explained Simply

*A plain-language walkthrough of the whole project. No cryptography background
needed. Read this once and you will be able to explain the project to anyone —
including a professor.*

> **Where this fits:** this is the *simple* version. The full technical story is
> in [EXPLANATION.md](EXPLANATION.md), the exam-prep pack is [VIVA.md](VIVA.md),
> and the illustrated report is `PROJECT_REPORT.html` (open it in a browser).

---

## The whole project in four sentences

1. Quantum computers, once big enough, will **break the encryption the internet
   uses today** — so the world is switching to new, "post-quantum" encryption.
2. A published 2026 paper (called **PQShield-IoT**) proposes how small smart
   devices (IoT) should adopt this new encryption — but all of its performance
   numbers come from a **simulation**, and it never explains how they were
   obtained.
3. **This project actually measured everything for real** — running the real
   encryption algorithms, building a real network handshake, testing for a real
   class of attack, and comparing against real microcontroller data.
4. The measurements reveal that the paper's numbers **cannot all be genuine
   measurements** (they are mathematically inconsistent with each other), and
   that the real bottleneck for IoT is not computation speed — it is the **size
   of the data** the new encryption has to send.

That is the elevator pitch. Everything below explains each piece slowly.

---

## Part 1 — The background story (why this field exists)

### 1.1 How today's internet security works

When your phone talks to a bank's server, two things must happen:

* **Key exchange** — the two sides agree on a secret number (a "key") that no
  eavesdropper can learn, even though they are talking over a public network.
  Think of it as two strangers shouting across a crowded room and somehow
  ending up with a shared secret nobody else in the room knows.
* **Digital signatures** — a way to prove *who* you are talking to, like a
  tamper-proof wax seal on a letter. If anyone alters the letter, the seal
  visibly breaks.

Both of these rely on math problems that are easy to do in one direction but
practically impossible to reverse. Example: multiplying two huge prime numbers
is easy; taking the result and finding the original primes is so slow it would
take normal computers longer than the age of the universe. The security of
**RSA** and **elliptic-curve cryptography (ECC)** — the systems protecting
almost everything today — rests on exactly that kind of one-way math.

### 1.2 Why quantum computers ruin this

In 1994 a mathematician named Peter Shor showed that a large enough **quantum
computer** could reverse those "impossible" math problems *quickly*. Not
slightly faster — so fast that the problems stop being protection at all. The
day such a machine exists, RSA and ECC are dead. You cannot fix them by using
bigger keys; the attack scales too well.

One important nuance (a professor may ask): quantum computers do **not** break
everything. Ordinary symmetric encryption like **AES** only gets *weakened*
(a second quantum algorithm, Grover's, effectively halves its strength), so
**AES-256 remains safe**. That is why the strategy everywhere — in this
project and in the paper we studied — is:

> **Replace the key exchange and signatures. Keep AES-256, keep the hash
> functions. Only the "public-key" parts need replacing.**

### 1.3 "But quantum computers don't exist yet — why act now?"

Two reasons, and this is one of the most convincing parts of the story:

* **Harvest now, decrypt later.** A spy can record your encrypted traffic
  *today*, store it cheaply, and decrypt it *in ten years* when the quantum
  computer arrives. It is like someone stealing a locked safe they cannot open
  yet — they just wait for the tool to be invented. Anything that must stay
  secret for a long time (medical data, industrial secrets) is effectively
  already at risk.
* **Devices live a long time.** A smart electricity meter installed today may
  run for 15–20 years and never get a software update. The encryption you ship
  it with is the encryption it dies with. So the switch has to happen *before*
  the threat is real.

### 1.4 The replacement standards

The US standards body **NIST** ran a years-long worldwide competition and in
**August 2024** published the winners as official standards:

| New name | Old name | Job |
|---|---|---|
| **ML-KEM** (FIPS 203) | Kyber | key exchange |
| **ML-DSA** (FIPS 204) | Dilithium | signatures |
| **SLH-DSA** (FIPS 205) | SPHINCS+ | signatures (backup, based only on hash functions) |

Two more names appear in this project: **Falcon** (a signature scheme with
very small signatures, standard still in draft) and **HQC** (a backup key
exchange chosen in 2025, deliberately built on *different* math so one
mathematical breakthrough cannot kill everything at once).

A cautionary tale worth remembering: a scheme called **SIKE** was a promising
finalist in the same competition — until 2022, when it was **completely broken
in about an hour on an ordinary laptop**. That shock is why nobody wants to
bet everything on one new algorithm, and it motivates the "hybrid" idea you
will meet in Part 4.

### 1.5 Why small IoT devices are the hard case

The new post-quantum algorithms are fast enough on laptops and servers. The
problem is the world's billions of tiny devices — sensors, smart meters,
medical wearables. They have three painful limits:

* **Tiny processors** — often a chip running at 24–120 MHz, thousands of times
  slower than a laptop.
* **Tiny memory** — kilobytes, not gigabytes. Some post-quantum operations
  need more working memory than the whole device has.
* **Tiny radio messages** — the radio standard these devices use
  (IEEE 802.15.4, the basis of Zigbee and similar) can carry only about **100
  useful bytes per message**. The new cryptography uses keys and signatures of
  **800 to 17,000 bytes**. Sending one post-quantum signature is like mailing
  a sofa through a letterbox — you must cut it into ~25 pieces, every piece
  can get lost, and every piece costs battery power (radio transmission is the
  single biggest battery drain on these devices).

So the real research question is not "is the new cryptography secure?" but
**"does it physically fit on these devices, and what does it cost?"** That
question can only be answered by *measuring* — which is exactly where the
paper we studied falls short.

---

## Part 2 — The base paper (what we built on)

**The paper:** Narayanan et al., *"Quantum-Resilient IoT Communication
Framework Using Post-Quantum Cryptography and Blockchain for Secure Edge
Devices"*, published 2026 in a legitimate Springer journal. Their framework is
called **PQShield-IoT**.

### What it proposes

A complete security architecture for IoT devices:

* **Kyber** for key exchange and **Dilithium** for signatures (good,
  standard-aligned choices);
* **AES-256** for the actual data encryption (also correct);
* a **blockchain** instead of a traditional certificate authority: every
  device is registered on a shared ledger together with a fingerprint of its
  firmware, so a tampered device fails authentication.

### What it claims

Concrete performance numbers — for example that Kyber encryption takes
**28 ms** and Dilithium signing takes **42 ms** on their IoT device, that
sessions establish in ~110–265 ms, with modest energy use. Sounds complete.

### The problem

**Every number comes from a computer simulation, and the paper never explains
how the numbers were produced.** No description of what hardware actually ran
the code, how times were measured, how many times each test was repeated —
nothing. In measurement science, a number without a method is not evidence;
it is an assertion. (To be fair — and we always are fair about this — the
paper *did* use real cryptographic code libraries inside its simulation. The
missing thing is the measurement *methodology*, not the code.)

### The six gaps we identified

Reading the paper closely, we found six specific shortcomings:

1. **No "hybrid" option.** It uses only new post-quantum crypto, while the
   real world (Chrome, Firefox, Cloudflare) runs old + new *together* for
   safety. The paper never asks what that safety would cost.
2. **Unverifiable performance numbers** — the core problem described above.
3. **Only one signature scheme considered.** It never compares Dilithium with
   Falcon or SPHINCS+, even though they have wildly different strengths.
4. **No side-channel analysis.** A real attack class (explained in Part 5) is
   never examined — even though exactly these algorithms suffered such an
   attack ("KyberSlash") in 2023–24.
5. **No bridge to real hardware.** Nothing connects the simulated numbers to
   any published measurement of real chips.
6. **A false security claim.** The paper claims "forward secrecy" (explained
   in Part 4) but its own protocol design makes that impossible.

Each gap became a phase of our project. Gaps → work → results.

---

## Part 3 — What we measured (the benchmarks)

*This addresses Gaps 2 and 3. Code: `code/benchmark_pqc.py`.*

We benchmarked **16 encryption schemes** — five classical ones (RSA, elliptic
curves) and eleven post-quantum ones — on a real machine, measuring both
**speed** and **size** of everything they produce.

### Doing the measurement honestly (this impresses examiners)

Timing a fast operation on a busy laptop is surprisingly easy to get wrong,
so the benchmark:

* pins itself to a single fast CPU core (modern laptops mix fast and slow
  cores; letting the test wander between them produces garbage data — we saw
  one algorithm appear 4× slower before pinning);
* warms the CPU up before measuring, and switches off Python's garbage
  collector so background cleanup never lands inside a measurement;
* reports the **median**, not the average — computer interruptions only ever
  *add* time, so the average is dragged upward by outliers while the median
  stays honest;
* verifies every algorithm actually *works* (encrypts and decrypts correctly)
  before timing it.

### The two headline results

**Result 1 — speed is a non-issue on normal computers.** The new ML-KEM key
exchange took **0.154 milliseconds** — within 8% of the classical elliptic-curve
method (0.143 ms), *even though* our post-quantum code was plain unoptimized C
while the classical code was hand-tuned assembly. Quantum-safe key exchange
is essentially **free in time** on anything laptop-class or above.

**Result 2 — size is the real cost.** The classical key exchange sends **32
bytes** over the network. ML-KEM sends **800-byte keys and 768-byte
ciphertexts**. A Dilithium signature is **2,420 bytes**. Remember the IoT
radio limit of ~100 bytes per message: what was one message becomes ~8–25
fragments. **The price of post-quantum security is bytes on the wire, not
computation** — and that directly contradicts the paper's focus, because its
whole optimization layer tries to save *computation*.

### The signature schemes are not interchangeable (Gap 3)

| Scheme | Personality |
|---|---|
| **ML-DSA (Dilithium)** | the all-rounder — decent at everything, big signatures (2,420 B) |
| **Falcon** | verifies extremely fast with small signatures (~655 B), but *creating* keys and signatures is slow and heavy |
| **SPHINCS+** | most conservative security, but signing took **1.2 seconds on a laptop** — minutes on a microcontroller — with 8–17 KB signatures |

Practical lesson: pick by *role*. A sensor that only ever needs to *verify*
firmware updates is perfect for Falcon (verification is its superpower); the
signing can happen on a powerful server. The paper never does this analysis.

---

## Part 4 — The hybrid handshake (belt and suspenders)

*This addresses Gaps 1 and 6. Code: `code/hybrid_handshake.py`.*

### The idea

Nobody fully trusts the new algorithms yet (remember SIKE, broken overnight in
2022). Nobody trusts the old ones against future quantum computers. The
industry answer: **use both at once**. Derive the session key from an old-style
exchange *and* a new-style exchange combined, so an attacker must break
**both** to learn anything. Two different locks on one door. This is exactly
what your browser already does today when it connects to Google or Cloudflare.

The paper skipped this entirely — and never measured what it would cost.

### What we built and found

A real client and server performing the handshake over an actual network
connection, in three modes: classical only, post-quantum only, and hybrid.
One hundred runs per mode. The finding:

> **The hybrid safety net costs just 64 extra bytes and ~0.6 milliseconds.**

In other words, defense-in-depth is *nearly free* — which turns the paper's
"post-quantum only" design from a simplification into something that needs
justifying. We also wrote an automated test suite that *proves* the
handshake's security properties (8 tests: tampering is detected, downgrade
attacks are detected, knowing one of the two secrets is not enough, and so on
— all pass; it runs in one second and is the best thing to demo live).

### The forward-secrecy catch (Gap 6 — our sharpest design critique)

**Forward secrecy** means: if someone steals your long-term key *today*, they
still cannot decrypt conversations they recorded *last year*. It is achieved
by generating a fresh, throwaway key for every session — like a hotel that
recodes the door lock for every guest, so a stolen master key does not open
records of past stays.

The paper *claims* forward secrecy. But its own protocol says each device uses
one **fixed, long-term** key for all key exchanges. Steal that key once and
every recorded past session opens up — the very "harvest now, decrypt later"
disaster this whole field is trying to prevent. The claim and the design
contradict each other. Our handshake uses **fresh keys for every single
connection**, so it actually delivers the property — we can demonstrate the
difference instead of just asserting it.

---

## Part 5 — Timing attacks (the invisible leak)

*This addresses Gap 4. Code: `code/timing_analysis.py`.*

### The idea in one sentence

An algorithm can be mathematically perfect and still betray its secrets by
**how long it takes to run**.

Imagine a guard checking a password letter by letter, who turns you away the
moment a letter is wrong. Wrong first letter → instant rejection. Correct
first letter, wrong second → *slightly slower* rejection. By simply timing the
guard with a stopwatch, you can crack the password one letter at a time —
never seeing anything, only measuring delays. This is a **timing side-channel
attack**, and it is not theory: the exact algorithm family in this project
(Kyber) suffered a real one, "KyberSlash", in 2023–24.

### Experiment A — watching a leak happen

We wrote three versions of a security check (comparing a secret
authentication code) and timed each while feeding it progressively "more
correct" guesses:

* The **naive** version leaked *perfectly*: every extra correct byte made it
  measurably slower, in a perfect straight line (statistical correlation
  = **+1.000**, as clean as data gets). Using that leak, an attacker cracks
  a 32-byte secret in ~8,000 tries instead of a number with 77 digits.
* The **properly written constant-time** version (Python's
  `hmac.compare_digest`): completely flat. No leak.

Same functionality, one implementation detail apart — one is an open door,
the other is safe.

### Experiment B — testing the post-quantum algorithm itself

ML-KEM's security depends on its decryption taking the **same time whether the
incoming ciphertext is valid or corrupted** (if rejection were faster, that
time difference itself becomes the "guard's hesitation" an attacker exploits).
We fed it valid, subtly corrupted, and random garbage inputs, thousands of
times, interleaved. Result: **no detectable timing difference** — the patched
modern implementation behaves correctly. Expected, but now *verified* rather
than assumed, which is the whole spirit of the project.

### A bonus finding about measurement itself

Our first version of this experiment produced a *false alarm* — it "detected"
a leak that wasn't there, because the laptop's speed drifts as it warms up,
and we tested the scenarios one after another instead of interleaved. We kept
the flawed version in the code as a switchable control: run it and it
manufactures a phantom leak every time; run the corrected interleaved version
and the leak vanishes. That is a live demonstration that **bad measurement
design invents results** — which is, of course, exactly the accusation this
project levels at the base paper's numbers. We hold ourselves to the standard
we demand.

---

## Part 6 — From laptop to microcontroller (the reality check)

*This addresses Gap 5. Code: `code/pqm4_extrapolation.py`.*

### The obvious objection, answered

"You measured a laptop — IoT devices are not laptops." Correct. So we bridged
the gap using **pqm4**, the community-standard public benchmark that measures
these algorithms on a real ARM Cortex-M4 microcontroller — the same chip class
the paper simulates. Crucial detail: pqm4 compiles **the exact same source
code** our laptop benchmark runs. Same code, two processors — the cleanest
possible comparison without owning the hardware.

The gap is real: the microcontroller is roughly **200–600× slower** than the
laptop. Key exchange stays comfortable (tens of milliseconds), but Dilithium
signing takes a third of a second, and SPHINCS+ signing takes **five
minutes**. So computation *does* become a bottleneck — but only on tiny chips,
and only for signing. This *refines* our Part 3 conclusion rather than
contradicting it: bytes are the cost on normal hardware; computation joins in
at the microcontroller level.

### The sharpest finding in the whole project

Now the trap springs on the base paper. Take its four claimed timings (Kyber
encrypt/decrypt, Dilithium sign/verify) and ask a simple question: given the
publicly known, measured number of processor cycles each operation takes on
this chip, **what processor speed would make each of the paper's numbers
true?**

The answers: **25 MHz, 29 MHz, 189 MHz, and 57 MHz.**

Four numbers, one claimed device, and they require **four different processor
speeds spanning a 7.5× range**. No processor runs at four speeds at once.
Therefore the paper's numbers **cannot be genuine measurements of one device —
no matter what hardware you assume**. The beauty of this test is that it needs
no assumptions at all: the four numbers are inconsistent *with each other*.

**Important nuance (say it exactly this way):** this does *not* prove the
numbers were faked, and we never claim that. The likely explanation is mundane
— they came from some unstated simulation model or scaling shortcut. But that
is precisely the point of Gap 2: **numbers reported without a methodology
cannot be trusted, and here is the concrete proof of why that matters.**

### The practical deliverable

We finished with a **device-class recommendation matrix**: for each standard
class of IoT device (from tiny motes to gateway boxes), which algorithm fits
which role — the practical guidance the paper never gives. One-line summary:
*match the scheme to the device and the role; a sensor that only verifies
firmware never needs to pay Falcon's heavy signing cost.*

---

## Part 7 — How we kept ourselves honest

Measurement code deserves the same suspicion as the thing it measures — a bug
in a benchmark does not crash; it produces confident wrong numbers. So the
project went through **multiple rounds of adversarial review** (independent
reviewers explicitly instructed to attack every claim, with findings accepted
only on majority agreement). **54 real problems were found and fixed**,
including:

* a command-line option that silently did nothing (a classic Python pitfall);
* CPU-pinning code that silently failed on Windows;
* an early draft *overstating* the case against the paper (claiming it used no
  real crypto library — false; it did; the fair critique is the missing
  methodology, and we corrected ourselves);
* a unit-mismatch bug in *our own* headline comparison, which was replaced by
  the cleaner clock-independent analysis above;
* a verification script that now automatically re-checks every number quoted
  in the report against the raw data files, so the documents can never
  silently drift out of sync with the measurements.

We also state our limitations openly (laptop timing noise, the classical
baseline being better-optimized than the PQC code, the microcontroller
comparison being indicative rather than exact, and the handshake deliberately
not including authentication). Volunteering weaknesses before being asked is a
strength, not a confession.

---

## Part 8 — The conclusion in one paragraph

> Post-quantum cryptography is ready for IoT — but not in the way the base
> paper frames it. On anything laptop-class, the new algorithms cost
> essentially nothing in time; the true cost is **size** — kilobyte keys and
> signatures squeezed through 100-byte radio messages. Computation only
> becomes the bottleneck on the smallest chips, and mainly for signing. The
> right engineering answer is to **choose schemes per device class and per
> role**, and to spend 64 cheap extra bytes on **hybrid** key exchange as
> insurance against the new math being broken. And the base paper's own
> numbers — four timings requiring four different processor speeds — are the
> best argument this project makes for why **real, methodologically documented
> measurement** must replace unexplained simulation figures.

---

## Part 9 — Questions your professor might ask (with answers)

**Q: What is your project's contribution, in one sentence?**
A: We replaced a published paper's unverifiable simulated performance claims
with real measurements across four dimensions — speed/size, hybrid handshake
cost, timing-attack resistance, and real microcontroller data — and in doing
so proved the paper's own numbers are mutually inconsistent.

**Q: Did you say the paper is fraudulent?**
A: No, and we are careful never to. We show its four timing numbers cannot
all be genuine measurements of the device it declares. The likely cause is an
undocumented simulation model. Our critique is about missing *methodology*,
not misconduct.

**Q: Why should anyone trust laptop measurements for IoT conclusions?**
A: Three protections. First, our conclusions are *relative* (scheme A vs
scheme B on identical hardware), which survives hardware changes. Second, the
sizes — our main finding — are exact mathematical constants, identical on any
hardware. Third, Part 6 anchors everything to published cycle-accurate
measurements of real microcontroller silicon running the *same source code*.

**Q: Why didn't you use real IoT hardware?**
A: None was available, so we used the community-standard pqm4 dataset —
measurements of real chips, running the same code we benchmark. That turns a
limitation into a controlled comparison. On-hardware measurement is our
top-listed future step.

**Q: What surprised you most?**
A: That quantum-safe key exchange is already as fast as classical — the speed
"problem" is mostly a myth on normal hardware. The real problem, size, gets
far less attention. Also, how easy it is for a *measurement* to lie: our own
first timing experiment produced a false leak until we fixed the experimental
design, which taught us to interrogate every number — including our own.

**Q: What is a KEM?**
A: A Key Encapsulation Mechanism — the modern packaging of key exchange.
One side publishes a public key (an open padlock). The other side generates a
secret, locks it with that padlock, and sends the locked box (the
"ciphertext") back. Only the padlock's owner can open it. Now both sides
share a secret, and the actual data flows under fast AES encryption.

**Q: Why keep AES at all? Isn't it broken by quantum computers too?**
A: No — quantum computers only *weaken* symmetric ciphers (Grover's algorithm,
a square-root speedup at best). Doubling the key length restores the margin,
so AES-256 remains safe. Only the public-key parts need replacement.

**Q: What would you do next?**
A: Four things: run the benchmark on an actual Cortex-M4 board; add
signatures to the handshake to make it fully authenticated and measure that
cost; use instruction-level tools (dudect) for finer side-channel analysis;
and simulate the radio fragmentation to convert bytes-on-wire into battery
cost.

**Q: What can you show me right now?**
A: Three demos, all under a minute: `python test_handshake_security.py`
(8 security proofs pass live), the two-terminal client/server handshake, and
`PROJECT_REPORT.html` with all figures. Full commands are in
[README.md](README.md).

---

## Part 10 — Mini-glossary (the ten terms that cover everything)

| Term | Plain meaning |
|---|---|
| **Post-quantum cryptography (PQC)** | New encryption designed to survive quantum computers |
| **Shor's algorithm** | The quantum algorithm that breaks RSA and elliptic curves |
| **Harvest now, decrypt later** | Record encrypted traffic today, decrypt when quantum computers arrive |
| **KEM** | Key Encapsulation Mechanism — modern key exchange (the padlock-and-box) |
| **ML-KEM / Kyber** | The standardized post-quantum key exchange |
| **ML-DSA / Dilithium** | The standardized post-quantum signature scheme |
| **Hybrid key exchange** | Old + new crypto combined; attacker must break both |
| **Forward secrecy** | Stolen keys today can't unlock recorded past conversations (needs fresh per-session keys) |
| **Side-channel / timing attack** | Stealing secrets by measuring *how long* operations take |
| **Constant-time code** | Code whose runtime never depends on secret data — the defense against timing attacks |

---

## Part 11 — What is in this folder

| File / folder | What it is |
|---|---|
| `SIMPLE_EXPLANATION.md` | this file — the plain-language story |
| [EXPLANATION.md](EXPLANATION.md) | the full technical narrative (read second) |
| [VIVA.md](VIVA.md) | quick-reference exam-defense pack |
| `PROJECT_REPORT.html` | illustrated report with all figures — best thing to present from |
| [README.md](README.md) | overview + exact commands to reproduce everything |
| `base-paper/` | the PQShield-IoT paper PDF |
| `code/` | the 8 Python programs (each has its own `*_EXPLAINED.md` deep dive) |
| `results/` | every measurement CSV and all 7 figures |
| `report/` | the formal IEEE-format report (compiles on Overleaf) |
| `literature-survey/` | the 6-thread literature survey |
