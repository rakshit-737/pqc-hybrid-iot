# Literature Survey — Post-Quantum Cryptography for Constrained IoT

Prepared as the background for a critical extension of Narayanan et al. (2026),
*"Quantum-Resilient IoT Communication Framework Using Post-Quantum Cryptography
and Blockchain for Secure Edge Devices"*, Iran. J. Sci. Technol. Trans. Electr.
Eng. 50:203–221. DOI 10.1007/s40998-025-01002-1 (hereafter **the base paper**
/ PQShield-IoT).

This survey organises the field into six threads, positions the base paper in
each, and shows how the gaps compound into the five contributions of this
project. Citations marked *(base ref)* appear in the base paper's own
reference list; others are standards or widely-cited works added here.

---

## 1. The quantum threat and the standardisation response

Shor's algorithm breaks the hardness assumptions under RSA and elliptic-curve
cryptography (integer factorisation, discrete log), so essentially all deployed
public-key cryptography is retro-actively insecure once a cryptographically
relevant quantum computer exists. Grover's algorithm only *halves* symmetric
security, so AES-256 and SHA3-256 remain adequate — which is why the base paper
(and this project) keep AES-256-GCM and SHA3 for the symmetric/KDF layers and
replace only the public-key primitives.

NIST's PQC standardisation concluded its main track in **August 2024** with
three final standards, each of which this project benchmarks in its
standardised form:

* **FIPS 203 — ML-KEM** (formerly CRYSTALS-Kyber): lattice (Module-LWE) key
  encapsulation. ML-KEM-512/768/1024 target NIST categories 1/3/5.
* **FIPS 204 — ML-DSA** (formerly CRYSTALS-Dilithium): lattice (Module-LWE/SIS)
  signatures, using Fiat–Shamir with aborts.
* **FIPS 205 — SLH-DSA** (formerly SPHINCS+): stateless hash-based signatures;
  security rests only on hash functions, the most conservative assumption.

**Falcon** was selected for standardisation as **FN-DSA** (FIPS 206, draft not
yet published at time of writing): compact lattice signatures via NTRU
trapdoor sampling. In **March 2025** NIST additionally selected **HQC**, a
*code-based* KEM, as a backup to ML-KEM specifically so that a future advance
against lattices would not compromise every standardised KEM at once
(Nguyen et al. 2025, *base ref*, surveys the lattice landscape).

**Base-paper positioning.** PQShield-IoT builds on Kyber512 and Dilithium2 in
their *round-3* form. Its schemes are the correct family, but the final FIPS
203/204 versions differ from round-3 in FO-transform / domain-separation
details and are not bit-compatible — a nuance this project makes explicit
(and confirms empirically: the installed ML-DSA-44 secret key is 2560 B, the
FIPS-204 size, not round-3's 2528 B).

---

## 2. PQC on constrained hardware — the evidence the base paper lacks

The decisive question for IoT is not "is PQC secure?" but "does it *fit* a
microcontroller?" The community benchmark is **pqm4** (Kannwischer et al.),
which measures every NIST candidate on the ARM Cortex-M4 in cycle counts,
code size, and peak stack. Independent testbed studies reach the constrained
setting from the protocol side:

* **Bozhko et al. (2023)** *(base ref)* evaluated NIST PQC inside TLS over
  Wi-Fi and BLE on an IoT testbed, reporting Kyber512 as the most efficient
  KEM and Falcon-512/Dilithium2 as the best signatures for BLE/Wi-Fi
  respectively — but confined to a controlled testbed.
* **Hanna et al. (2025)** *(base ref)* gave a realistic PQ-TLS evaluation on
  consumer IoT (certificate chains, OCSP/CRL, mutual auth), finding large
  latency/energy spread across algorithms and interfaces — but did not tackle
  heterogeneous-ecosystem scalability.
* **RFC 7228** provides the vocabulary this project uses to turn such numbers
  into deployment guidance: Class 0/1/2 constrained devices by RAM/Flash.

**Gap this creates (→ Project Gaps 2 & 5).** The base paper does *not* measure
its cryptography on hardware — it simulates ARM Cortex-M4F profiles in
Contiki-NG/NS-3. It does state (§3.6) that PQClean and liboqs supplied the
cryptographic code, so the defensible critique is not "no library was used" but
that **no measurement methodology is reported**: no execution host, no timing
procedure, no repetition count, no variance. This project supplies (a) real
desktop benchmarks of the same PQClean source (Phase 2) and (b) a comparison
against pqm4's published Cortex-M4 cycle counts (Phase 5). Because the paper
used PQClean and pqm4 compiles the same source, that comparison is
same-codebase — and it shows the paper's four reported latencies imply four
mutually incompatible processor clocks (25–189 MHz) on one declared 120 MHz
device, so they cannot be cycle-accurate measurements whatever clock is assumed.

---

## 3. Algorithm diversity — beyond a single signature scheme

The three signature families trade off very differently on constrained
devices, which is why fixing one scheme is a design risk:

| family | scheme | signature size | on-device cost profile |
|---|---|---|---|
| lattice | ML-DSA-44 | ~2.4 KB | balanced; ~50 KB signing stack |
| lattice | Falcon-512 | ~0.65 KB (variable) | tiny/fast **verify**; slow FP signing, heavy keygen |
| hash | SPHINCS+-128f/s | 17 / 7.9 KB | conservative security; signing seconds–minutes on M4 |

Wang and Long (2024) *(base ref)* combine Dilithium and Kyber for
authenticated key exchange in quantum networks; Sarkar and Nag (2024)
*(base ref)* and Kuang et al. (2025) *(base ref)* use lattice primitives for
blockchain-anchored IoT authentication — all fixing on a single lattice
signature without comparing the size/speed trade-offs above.

**Gap this creates (→ Project Gap 3).** The base paper commits to Dilithium2
with no Falcon/SPHINCS+ comparison, despite their order-of-magnitude different
profiles being decisive for constrained roles (e.g. Falcon's tiny fast verify
is ideal for firmware-update checking on a sensor; SPHINCS+ signing is
infeasible on-device). This project benchmarks all three by time *and* size
and maps them to device classes.

---

## 4. Hybrid PQC — defence in depth during migration

Because lattice cryptanalysis is younger than RSA/ECC cryptanalysis, deployed
migrations do not trust PQC alone. **TLS 1.3 hybrid key exchange** (IETF) and
its widely-deployed group **X25519MLKEM768** derive the session key from a
*concatenation* of an X25519 shared secret and an ML-KEM-768 shared secret, so
the channel survives unless *both* ECDLP and Module-LWE fall. This directly
counters **harvest-now-decrypt-later**: traffic recorded today under pure
classical crypto is decryptable post-quantum, whereas hybrid traffic is not.
The construction's safety is the standard concatenation-combiner argument:
modelling the KDF as a random oracle (secure PRF), the key is indistinguishable
from random while either secret is unknown, so the hybrid is at least as strong
as the stronger input — provided the KDF also binds both ciphertexts, which
Giacon–Heuer–Poettering (2018) showed is required for a robust combiner.

**Gap this creates (→ Project Gap 1).** PQShield-IoT uses *pure* Kyber with no
classical component — reasonable for a clean post-quantum design, but out of
step with how real systems de-risk the transition. This project implements a
classical/PQ/hybrid handshake over a socket and shows the hybrid costs only
+64 B total on the wire (+32 B each way) and sub-millisecond over pure ML-KEM —
i.e. the insurance is nearly free.

---

## 5. Side-channel and timing security — an omitted dimension

Constant-time implementation is as important as algorithm choice: if runtime
depends on secret data, timing leaks it. This is not theoretical for PQC —
the **KyberSlash** attacks (2023–2024) recovered Kyber secret keys from a
secret-dependent division in reference decapsulation, and the reference code /
PQClean were patched. The IND-CCA2 guarantee of ML-KEM specifically depends on
the Fujisaki–Okamoto implicit-rejection path being constant-time; a timing
difference between valid and invalid ciphertexts becomes a decryption oracle.
By contrast, signature *verification* consumes only public inputs, so its
variable timing is not a vulnerability — a distinction the literature is
careful about and examiners probe.

**Gap this creates (→ Project Gap 4).** The base paper performs no
side-channel or timing analysis. This project (Phase 4) demonstrates the
classic tag-comparison leak end-to-end (naive early-exit compare vs
`hmac.compare_digest`) and tests ML-KEM-512 decapsulation for a timing oracle
across valid/corrupted ciphertexts, finding it constant-time at desktop
resolution — while being explicit about the limits of black-box wall-clock
timing versus instruction-level tools (`dudect`).

---

## 6. Blockchain-integrated PQC for IoT — the base paper's own thread

The base paper sits in a line of work combining a permissioned ledger for
decentralised identity/access with PQC for the cryptographic layer:

* **Mollah et al. (2024)** *(base ref)* — STarEdgeChain: permissioned
  blockchain + edge + signcryption; assumes static topologies.
* **Khan et al. (2024)** *(base ref)* — THASSA: trusted-hardware edge security;
  not quantum-resilient and cost-intensive.
* **Sarkar and Nag (2024)**, **Kuang et al. (2025)**, **Prajapat et al.
  (2025)**, **Erukala et al. (2025)** *(base refs)* — lattice + blockchain
  authentication / encryption for IoT, variously lacking constrained-hardware
  evaluation, adversarial-condition testing, or low-latency validation.

A recurring critique across this thread — and one the base paper levels at
others — is the absence of empirical validation on real constrained devices.
The base paper does not fully escape it: its evaluation is simulation-only,
and (a secondary observation of this survey) it describes its own ledger
inconsistently — **Hyperledger Fabric** in Table 3, a **Hyperledger Sawtooth**
validator in §3.6, and an "adapted permissioned **DAG-based** ledger" in the
same section — while its node count varies between a 15-node network (§3.6)
and 50–200 nodes (Table 3 and the results). These are raised here as
limitations warranting scrutiny, not as accusations; the blockchain layer is
outside this project's cryptographic scope and is noted for completeness.

---

## 7. Synthesis — from gaps to contributions

| Thread | Established practice | Base-paper gap | This project |
|---|---|---|---|
| Standardisation (§1) | FIPS 203/204/205 finals | uses round-3 forms | benchmarks FIPS-final forms, notes non-equivalence |
| Constrained HW (§2) | pqm4, PQ-TLS testbeds | simulation only | real benchmarks + pqm4 extrapolation (Gaps 2, 5) |
| Algorithm diversity (§3) | Falcon/SPHINCS+ trade-offs known | Dilithium2 only | 3-family comparison + device matrix (Gap 3) |
| Hybrid migration (§4) | TLS 1.3 X25519MLKEM768 | pure PQC | classical/PQ/hybrid handshake (Gap 1) |
| Side channels (§5) | constant-time, KyberSlash | none | tag-compare leak + decaps oracle test (Gap 4) |
| Blockchain+PQC (§6) | permissioned-ledger identity | inconsistent platform, simulated | out of scope; documented as limitations |

The consistent finding across threads is that PQShield-IoT integrates the
right *components* but validates them only in simulation and only in a single
configuration. This project's contribution is to replace simulation with
measurement wherever a laptop allows, to widen the single choices (one
signature, no hybrid) into compared design spaces, and to add the missing
side-channel dimension — producing deployment guidance (the RFC 7228 matrix)
grounded in real numbers.

---

## Key references

*Standards & tooling (added):* NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS
205 (SLH-DSA); FN-DSA/FIPS 206 (draft); NIST HQC selection (2025); IETF TLS 1.3
hybrid key exchange & X25519MLKEM768; RFC 7228 (constrained-device classes);
pqm4 (Kannwischer et al., Cortex-M4 PQC benchmarks); KyberSlash (2023–24
timing attacks on Kyber); PQClean project.

*From the base paper's reference list (base refs):* Bozhko et al. (2023);
Hanna et al. (2025); Mollah et al. (2024); Khan et al. (2024); Sarkar and Nag
(2024); Kuang et al. (2025); Prajapat et al. (2025); Erukala et al. (2025);
Wang and Long (2024); Nguyen et al. (2025); plus Narayanan et al. (2026), the
base paper itself.
