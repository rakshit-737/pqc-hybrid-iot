# AHQR — Adaptive Hybrid Quantum-Resilient Ratchet

The project's novel contribution: a key-management protocol for 802.15.4-class IoT devices that combines classical and post-quantum cryptography at three layers, each running at its own cadence.

Code: [`code/ahqr.py`](code/ahqr.py) · Tests: [`code/test_ahqr.py`](code/test_ahqr.py) · Evaluation: [`code/ahqr_evaluation.py`](code/ahqr_evaluation.py)

---

## 1. Problem

The base paper (PQShield-IoT) runs one Kyber512 exchange per session and then encrypts every message under one static session key. Phases 1–5 of this project measured what that costs and what it leaves open:

| Observation (measured) | Consequence |
|---|---|
| PQC is cheap in CPU time but expensive on the wire: an ML-KEM-768 public key is 1184 B, or 15 IEEE 802.15.4 frames | Re-keying with PQC often is not affordable on a constrained radio |
| A hybrid X25519 + ML-KEM exchange adds only 64 B over pure ML-KEM | Running classical and PQ together costs almost nothing extra |
| A static session key gives no forward secrecy and no recovery after a device compromise | One state leak exposes the whole session |

Existing remedies each fix one part. Re-running a full hybrid handshake often restores healing but multiplies bandwidth by about 7. A Signal-style classical ratchet heals cheaply, but a quantum adversary breaks every X25519 step.

## 2. Design

```mermaid
sequenceDiagram
    participant D as IoT device
    participant G as Gateway
    Note over D,G: Layer 1: authenticated hybrid handshake (once)
    G->>D: X25519 pub, ML-KEM pub, Sig_G(transcript)
    D->>G: X25519 pub, ML-KEM ct, Sig_D(transcript)
    Note over D,G: rk = HKDF(ss_x || ss_pq, transcript); Sig = Ed25519 AND ML-DSA-44
    loop every message
        D->>G: AES-256-GCM(mk_i, reading); (ck, mk_i) = KDF(ck)
    end
    Note over D,G: Layer 2a: every C messages, classical step (+64 B)
    G->>D: fresh X25519 pub
    D->>G: fresh X25519 pub, rk = HKDF(rk, ss_x)
    Note over D,G: Layer 2b: every Q messages, hybrid step (+~2.3 KB)
    G->>D: fresh X25519 pub, fresh ML-KEM pub
    D->>G: X25519 pub, ML-KEM ct, rk = HKDF(rk, ss_x || ss_pq)
```

### Layer 1: authenticated hybrid handshake
* Key exchange: ephemeral X25519 plus ephemeral ML-KEM-512 or ML-KEM-768.
* Root key: `rk = HKDF-SHA3-256(salt=0, ikm = ss_x25519 || ss_mlkem, info = "AHQR-root" || transcript)`. The transcript binds both ciphertexts, which makes the concatenation combiner robust (Giacon–Heuer–Poettering 2018).
* Authentication uses a composite signature, Ed25519 AND ML-DSA-44, which verifies only if both halves verify. A forger has to break both schemes. This fills the base paper's gap where the key exchange is not bound to the identities.

### Layer 2: dual-cadence hybrid ratchet

| Cadence | Operation | Extra bytes | Property gained |
|---|---|---|---|
| every message | `(ck, mk) = HKDF(ck)`, a one-way chain | 0 | Per-message forward secrecy |
| every **C** messages | X25519 ratchet: `rk = HKDF(salt=rk, ikm=ss_x)` | 64 | Post-compromise healing against classical attackers |
| every **Q** messages | Hybrid ratchet: `rk = HKDF(salt=rk, ikm=ss_x‖ss_pq)` | ~2.3 KB (ML-KEM-768) | Post-compromise healing that also holds against a quantum attacker |

The old root is the HKDF salt and the fresh secrets are the IKM. If HMAC is modelled as a dual-PRF (the assumption behind TLS 1.3's key schedule), a new root is pseudorandom when **either** the old root **or** any fresh secret is unknown to the attacker.

### Layer 3: Mosca-adaptive policy
Mosca's inequality: data is at risk if **x + y > z**, where x is the data's shelf-life, y the migration time and z the years until a cryptographically relevant quantum computer (CRQC) exists. `policy()` uses it as follows:

* **Confidentiality** has to be PQ now whenever x + y > z, because of harvest-now-decrypt-later. This sets Q to daily rather than weekly.
* **Authentication** only has to hold at the moment of the handshake, since a recorded handshake cannot be forged after the fact. Until y ≥ z, the 2.4 KB ML-DSA signature is optional, which saves about 30 frames per handshake.
* **Device class** (RFC 7228) sets the KEM level. Class 0 nodes delegate PQ to the gateway.

## 3. Evaluation

The evaluation uses 1000 messages of 32 B each, C = 16 and Q = 256, with real PQClean and OpenSSL primitives. Each adversary is simulated by re-deriving keys with the same KDFs, and every key it derives is checked against the real one.

### Security: share of message keys each adversary recovers
![security](results/fig8_ahqr_security.png)

AHQR is the only low-cost design that scores 0 % or close to it in every column. Against a state leak combined with a quantum computer, the classical ratchet never recovers. AHQR recovers at the next hybrid step.

### Link cost
![link](results/fig9_ahqr_link_cost.png)

| Design | Bytes | 802.15.4 frames | PQ healing |
|---|---:|---:|:--:|
| PQShield-style static key | 58.5 KB | 1082 | no |
| Hybrid re-handshake every 16 | 512 KB | 6733 | yes |
| **AHQR (C=16, Q=256)** | **70 KB** | **1299** | **yes** |

AHQR uses 7.3× fewer bytes and 5.2× fewer frames than periodic hybrid re-handshaking. Compared with the base paper's design, it adds 20 % more frames and in return gets forward secrecy, hybrid security and post-compromise healing.

### Tunable trade-off
![tradeoff](results/fig10_ahqr_tradeoff.png)

The mean number of messages exposed after a state leak plus a CRQC is ≈ Q/2, while the overhead per message falls as 1/Q. Q is the operator's control for trading bandwidth against healing.

### Compute cost
![timings](results/fig11_ahqr_timings.png)

On a laptop CPU, a hybrid ratchet step costs about 2 ms and a message about 0.04 ms. As the earlier phases found, the binding cost is bandwidth, not CPU time.

## 4. Verified properties (`python code/test_ahqr.py`)

12 tests pass, including:
* the composite signature is rejected if either half is forged or stripped;
* a CRQC that breaks every X25519 recovers 0 keys, and an ML-KEM break alone recovers 0 keys;
* after a state leak at message t, no key before t is exposed (forward secrecy) and none after the next ratchet step;
* a state leak plus a CRQC is healed by the next hybrid step, and never healed by the classical ratchet;
* the Mosca policy tightens Q when x + y > z.

## 5. Honest positioning

Each building block already exists separately: hybrid KEMs (TLS 1.3 `X25519MLKEM768`, X-Wing), composite signatures (IETF LAMPS drafts), and PQ ratchets (Signal PQXDH and the SPQR triple ratchet). The contribution here is their **co-design for constrained IoT**:

1. a two-cadence ratchet whose PQ interval is an explicit bandwidth/healing parameter, with the trade-off measured;
2. an executable adversary simulator that computes, rather than asserts, which keys each attacker recovers;
3. a Mosca-driven policy that separates the PQ requirement for confidentiality from the one for authentication, and sets the cadences per RFC 7228 device class.

Limitations: endpoints are simulated in-process, so the bytes are real but no radio is involved; there is no formal (computer-checked) proof; there is no replay or reordering window for lost messages; timings come from an x86 host. Cortex-M estimates follow the pqm4 approach of Phase 5.
