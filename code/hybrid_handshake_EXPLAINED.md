# `hybrid_handshake.py` — Explanation and Viva Prep

## 0. Why this exists (Gap 1)

PQShield-IoT uses *pure* Kyber512 — if module-lattice cryptanalysis improves
(the way it did for SIKE, a NIST round-4 candidate broken classically in 2022
after years of scrutiny), every session key falls at once. Real migrations
hedge: TLS 1.3's deployed **`X25519MLKEM768`** group (default in Chrome and
Firefox since 2024) derives the session key from BOTH an X25519 exchange AND
an ML-KEM-768 encapsulation. The attacker must break **both** ECDLP **and**
Module-LWE. This script implements that idea over a real socket and *prices*
it, so the report can argue with numbers instead of opinions.

## 1. The protocol, message by message

```
msg1  C→S : mode ‖ level ‖ [X25519 pub, 32 B] ‖ [ML-KEM pub, 800/1184 B]
msg2  S→C : [X25519 pub, 32 B] ‖ [ML-KEM ciphertext, 768/1088 B]
            transcript = SHA3-256(msg1 ‖ msg2)
            key = SHA3-256("CNS-hybrid-v1" ‖ mode ‖ level ‖ ss_x ‖ ss_kem ‖ transcript)
msg3  C→S : nonce ‖ AES-256-GCM_key(transcript), AAD "c-fin"
msg4  S→C : nonce ‖ AES-256-GCM_key(transcript), AAD "s-fin"
```

* **One round trip**, exactly like TLS 1.3's `key_share`: the client sends its
  ephemeral public material, the server answers with its share/ciphertext.
  KEMs enable this non-interactive shape — no negotiation round needed.
* **The "ciphertext" asymmetry is the point of KEMs**: in the classical leg,
  both sides contribute a DH public key; in the KEM leg, the *server*
  encapsulates against the client's public key and only a ciphertext crosses
  the wire. Client decapsulates. That is the DH→KEM shift in one picture.
* **Key confirmation (msg3/msg4)**: each side proves knowledge of the derived
  key by AES-GCM-encrypting the transcript hash. If any handshake byte was
  tampered with, transcripts differ → keys differ → GCM authentication fails
  → handshake aborts. Fail-closed.

## 2. The three security-critical design choices

1. **Concatenation combiner.** `key = H(… ‖ ss_x25519 ‖ ss_mlkem ‖ …)`.
   Modelling `H` (SHA3-256) as a *random oracle* / secure PRF, the key is
   indistinguishable from random as long as at least one input secret is
   unknown — so recovering it requires *both*. (Careful: the operative
   property is **PRF/RO indistinguishability**, *not* preimage resistance —
   a hash can be preimage-resistant yet leak whether the key correlates with a
   known partial input, so "preimage-resistant ⇒ need both" is not a valid
   reduction. Examiners probe exactly this.) The combiner is robust because
   the transcript binds *both* ciphertexts (Giacon–Heuer–Poettering 2018);
   same construction as X25519MLKEM768. One-sentence viva answer: *"under the
   random-oracle model, the hybrid is at least as strong as the stronger of
   its two components."*
2. **Transcript binding.** The KDF eats SHA3-256 of every handshake byte —
   the same reason TLS binds its key schedule to the transcript, and the
   PQShield-IoT paper binds IDs/timestamps into its session key (its Eq. 5).
   Downgrade attempt (flipping `mode` to classical)? The mode byte is in both
   the transcript *and* the KDF label → keys diverge → finished fails.
3. **What it deliberately does NOT do: authentication.** This is an
   ephemeral, unauthenticated exchange — a MITM can sit in the middle of it.
   Authentication is an orthogonal layer (certificates in TLS; the
   blockchain-registered Dilithium identities in the base paper; our Phase-2
   signature benchmarks price it). Say this *before* the examiner does.

## 3. Measured results (localhost, 100 handshakes/config, medians)

| config | latency | c→s bytes | s→c bytes | total |
|---|---|---|---|---|
| classical (X25519) | 1.056 ms | 102 | 100 | **202 B** |
| pq-512 (ML-KEM-512) | 1.394 ms | 870 | 836 | 1,706 B |
| pq-768 | 1.642 ms | 1,254 | 1,156 | 2,410 B |
| hybrid-512 | 2.076 ms | 902 | 868 | 1,770 B |
| **hybrid-768** (≈ TLS X25519MLKEM768) | **2.256 ms** | 1,286 | 1,188 | **2,474 B** |

Three take-aways to say out loud:

* **Hybrid over pure-PQ costs +64 B and ~0.6 ms** (32 B X25519 key each way).
  The insurance against a lattice break is nearly free — which makes the base
  paper's pure-PQC design a *choice to justify*, not a necessity.
* **PQ over classical costs ~2.2 KB on the wire** but only ~0.6 ms of CPU
  and round-trip. On localhost that's invisible; over IEEE 802.15.4
  (~100 B usable payload per frame) a 2,474 B handshake is ~25 fragments each
  needing MAC-layer handling — the *radio*, not the crypto, is the IoT cost.
  This connects Phase 2's conclusion to a running protocol.
* Latency ordering (classical < pq < hybrid) tracks the Phase-2 primitive
  benchmarks; hybrid ≈ classical + pq work summed, as expected — nothing
  mysterious hides in the protocol layer.

## 4. Implementation details worth knowing

* **`TCP_NODELAY`** disables Nagle's algorithm — otherwise the kernel delays
  our small frames to coalesce them and we would measure Nagle, not crypto.
* **Length-prefixed frames** (4-byte big-endian) because TCP is a byte
  stream, not a message protocol; `recv()` may return partial data, hence
  `_recv_exact()` loops. Byte counts include prefixes — real wire bytes.
* The clock starts *before* client keygen: generating the ephemeral share is
  part of each session's work (that's what "ephemeral" means), so it belongs
  in the handshake cost.
* `--server` / `--client` run the same code across two terminals (or two
  machines: `--host`) for the live demo; the default mode self-hosts the
  server in a thread for one-command reproduction.

## 5. Rapid-fire viva Q&A

* **Q: Why is your hybrid KDF safe if SHA3-256 is quantum-attackable?**
  Grover gives at most a quadratic speedup on preimages: SHA3-256 keeps
  ~128-bit post-quantum preimage resistance — Category-1-adequate, same
  assumption the base paper makes for its SHA3 KDF.
* **Q: Harvest-now-decrypt-later — where does it show up here?** The pure
  classical handshake's traffic can be recorded today and decrypted once a
  quantum computer exists (X25519 falls to Shor). The hybrid's cannot, unless
  lattices *also* fall. That asymmetry is the entire migration argument.
* **Q: Why X25519 and not P-256 for the classical leg?** It's what deployed
  hybrid TLS uses, it was the fastest classical KEM in our Phase-2 data, and
  its 32-B keys make the hybrid overhead minimal.
* **Q: Could you have reused one TCP connection for all reps?** Yes, but a
  fresh connection per handshake models session establishment (the thing
  being priced); TCP setup is excluded from the timed window either way.
* **Q: What breaks if the server flips the mode byte to 'classical'?**
  Nothing silently: mode is inside both transcript and KDF input, so the
  keys diverge and the finished messages fail authentication — the downgrade
  is detected, not accepted.
