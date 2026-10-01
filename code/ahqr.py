"""
ahqr.py
=======
AHQR - Adaptive Hybrid Quantum-Resilient Ratchet for constrained IoT links.

This is the project's novel contribution. The base paper (PQShield-IoT)
uses pure PQC (Kyber512 + Dilithium2) and encapsulates against a static,
long-term Kyber key; there is no ephemeral KEM key anywhere in its protocol.
Phases 1-5 of this project showed three things about that design:

  * PQC's real cost on IoT is BYTES-ON-WIRE, not CPU time (an ML-KEM-768
    public key alone needs 15 IEEE 802.15.4 frames);
  * hybrids (classical + PQ) are almost free insurance;
  * static KEM keys give no forward secrecy (Gap 6), and its key rotation
    (Eq. 10, K = SHA3-256(ss || counter || T_rot)) re-hashes the same
    shared secret with public inputs, so no fresh secret ever enters and
    a compromised device never recovers.

AHQR combines classical and post-quantum cryptography at THREE layers, each
running at its own cadence, so that the expensive PQ material is sent only as
often as the threat model actually requires:

  Layer 1  Authenticated hybrid handshake (once per session)
           X25519 + ML-KEM key exchange, authenticated by a COMPOSITE
           signature Ed25519 AND ML-DSA-44 (valid only if BOTH verify).
           Session root key = HKDF-SHA3(ss_x25519 || ss_mlkem, transcript).

  Layer 2  Dual-cadence hybrid ratchet (during the session)
           * every message      : symmetric KDF chain step  (0 extra bytes)
                                  -> per-message forward secrecy
           * every C messages   : classical X25519 ratchet  (+84 B)
                                  -> cheap post-compromise healing
           * every Q messages   : hybrid X25519+ML-KEM step (+2.3 KB)
                                  -> post-compromise healing that also
                                     survives a quantum adversary
           Root update: rk' = HKDF(rk, ss_x25519 || ss_mlkem?, transcript)
           so a ratchet step is secure if the old root OR any fresh secret
           is unknown to the adversary.

  Layer 3  Mosca-adaptive policy
           Picks (KEM level, auth mode, C, Q) from the device class
           (RFC 7228), the data's confidentiality shelf-life x, the
           migration time y and the estimated time to a cryptographically
           relevant quantum computer z (Mosca's inequality x + y > z).
           Key observation used by the policy: CONFIDENTIALITY must be PQ
           today (harvest-now-decrypt-later), but AUTHENTICATION only has
           to resist an attacker at the moment of the handshake, so the
           2.4 KB ML-DSA signatures (60 frames per handshake) can be
           dropped while z is far away.

Everything below is real cryptography (PQClean via `pqcrypto`, OpenSSL via
`cryptography`); wire messages are real byte strings whose lengths are what
the evaluation counts.

Relation to prior work: hybrid KEMs (TLS 1.3 X25519MLKEM768, X-Wing),
composite signatures (IETF LAMPS drafts) and PQ ratchets (Signal PQXDH /
SPQR triple ratchet) each exist separately, and the base paper already has
an optimisation layer (algorithm pruning per device profile, key rotation
driven by energy and throughput). The contribution here is the co-design
for 802.15.4-class IoT: a two-cadence ratchet whose PQ interval is a
tunable bandwidth/healing trade-off, an adversary simulator that measures
exactly which message keys each attacker recovers, and a policy driven by
a threat model (Mosca) rather than by energy and throughput.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_512, ml_kem_768
from pqcrypto.sign import ml_dsa_44

KEMS = {512: ml_kem_512, 768: ml_kem_768}

# IEEE 802.15.4 (RFC 4944 sec. 4): 127 B frame - 25 B maximum MAC overhead
# - 21 B AES-CCM-128 link-layer security = 81 B for the adaptation layer.
# 6LoWPAN/UDP headers are ignored, so frame counts here are a lower bound.
FRAME_PAYLOAD = 81

# A ratchet offer sent downlink travels in its own AEAD-protected message:
# epoch/counter header (4 B) + AES-GCM tag (16 B). The device's reply is
# piggybacked on its next data message, which already carries both.
ENVELOPE = 4 + 16

NEVER = 0        # cadence value meaning "never"


# --------------------------------------------------------------------------
# KDF helpers
# --------------------------------------------------------------------------

def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA3_256(), length=length, salt=salt,
                info=info).derive(ikm)


def h(*parts: bytes) -> bytes:
    d = hashlib.sha3_256()
    for p in parts:
        d.update(len(p).to_bytes(4, "big"))
        d.update(p)
    return d.digest()


def kdf_root(rk: bytes, fresh: bytes, transcript: bytes) -> tuple[bytes, bytes]:
    """Root ratchet: (new root key, new chain key).

    rk is the HKDF salt and the fresh secrets are the IKM. HKDF-Extract is
    HMAC(salt=rk, ikm=fresh); modelling HMAC as a dual-PRF (Bellare 2006,
    the same assumption TLS 1.3's key schedule relies on) the output is
    pseudorandom if EITHER rk OR the fresh secret is unknown.
    """
    out = hkdf(fresh, rk, b"AHQR-root" + transcript, 64)
    return out[:32], out[32:]


def kdf_chain(ck: bytes) -> tuple[bytes, bytes]:
    """Symmetric ratchet: (next chain key, message key). One-way."""
    out = hkdf(ck, b"", b"AHQR-chain", 64)
    return out[:32], out[32:]


def nonce_for(epoch: int, ctr: int) -> bytes:
    return epoch.to_bytes(4, "big") + ctr.to_bytes(8, "big")


# --------------------------------------------------------------------------
# Composite (hybrid) signatures: Ed25519 AND ML-DSA-44
# --------------------------------------------------------------------------

@dataclass
class Identity:
    """Long-term device / gateway identity.

    mode "composite": Ed25519 + ML-DSA-44, verifier requires BOTH.
    mode "classical": Ed25519 only (Mosca policy may choose this while a
                      quantum attacker is not yet expected - see policy()).
    """
    mode: str = "composite"
    ed_sk: ed25519.Ed25519PrivateKey = field(init=False)
    pq_pk: bytes = field(init=False, default=b"")
    pq_sk: bytes = field(init=False, default=b"", repr=False)

    def __post_init__(self):
        self.ed_sk = ed25519.Ed25519PrivateKey.generate()
        if self.mode == "composite":
            self.pq_pk, self.pq_sk = ml_dsa_44.generate_keypair()

    @property
    def public(self) -> tuple[bytes, bytes]:
        return self.ed_sk.public_key().public_bytes_raw(), self.pq_pk

    def sign(self, msg: bytes) -> bytes:
        sig = self.ed_sk.sign(b"AHQR-ed" + msg)
        if self.mode == "composite":
            sig += ml_dsa_44.sign(self.pq_sk, b"AHQR-pq" + msg)
        return sig


def verify(public: tuple[bytes, bytes], msg: bytes, sig: bytes) -> bool:
    """AND-combiner: forging requires breaking Ed25519 AND ML-DSA."""
    ed_pk, pq_pk = public
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(ed_pk).verify(
            sig[:64], b"AHQR-ed" + msg)
    except Exception:
        return False
    if pq_pk:
        if len(sig) != 64 + ml_dsa_44.SIGNATURE_SIZE:
            return False
        try:
            return bool(ml_dsa_44.verify(pq_pk, b"AHQR-pq" + msg, sig[64:]))
        except Exception:
            return False
    return len(sig) == 64


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Config:
    name: str
    hs_classical: bool = True      # X25519 in the handshake
    hs_pq: bool = True             # ML-KEM in the handshake
    level: int = 768               # ML-KEM-512 or -768
    auth: str = "composite"        # composite | classical | none
    chain: bool = True             # per-message symmetric ratchet
    c_every: int = NEVER           # classical ratchet interval (messages)
    q_every: int = NEVER           # hybrid PQ ratchet interval (messages)
    rehandshake: bool = False      # ratchet steps are FULL new handshakes
                                   # (no old-root mixing; baseline only)


# Baselines + the proposed scheme, used throughout the evaluation.
def standard_configs(c: int = 16, q: int = 256) -> list[Config]:
    return [
        Config("PQShield-style (static ML-KEM key)", hs_classical=False,
               level=512, auth="composite", chain=False),
        Config("Hybrid handshake, static key", chain=False),
        Config("Classical ratchet (Signal-like)", hs_pq=False,
               auth="classical", c_every=c),
        Config(f"Hybrid re-handshake every {c}", c_every=c, q_every=c,
               rehandshake=True),
        Config(f"AHQR (C={c}, Q={c})", c_every=c, q_every=c),
        Config(f"AHQR (C={c}, Q={q})", c_every=c, q_every=q),
    ]


# --------------------------------------------------------------------------
# Session: both endpoints simulated in-process, real crypto, real bytes
# --------------------------------------------------------------------------

@dataclass
class StepLog:
    """What an eavesdropper records + what secrets each step depended on."""
    msg_index: int                 # first message protected by this step
    kind: str                      # handshake | classical | hybrid
    transcript: bytes
    ss_c: bytes | None             # fresh X25519 secret mixed (if any)
    ss_q: bytes | None             # fresh ML-KEM secret mixed (if any)
    mixes_old_root: bool
    root_after: bytes
    chain_after: bytes


class Session:
    """Device <-> gateway session running a Config.

    send(payload) returns the wire bytes of the uplink data message and
    accounts any ratchet material in uplink/downlink byte counters.
    """

    def __init__(self, cfg: Config, dev_id: Identity | None = None,
                 gw_id: Identity | None = None):
        self.cfg = cfg
        self.kem = KEMS[cfg.level]
        self.dev_id = dev_id or (Identity(cfg.auth) if cfg.auth != "none" else None)
        self.gw_id = gw_id or (Identity(cfg.auth) if cfg.auth != "none" else None)
        self.up = 0       # device -> gateway bytes
        self.down = 0     # gateway -> device bytes
        self.frames = 0   # 802.15.4 frames, both directions
        self.ratchet_events = {"classical": 0, "hybrid": 0}
        self.log: list[StepLog] = []
        self.msg_keys: list[bytes] = []
        self.epoch = 0
        self.ctr = 0
        self._handshake(0)

    # -- key exchange core shared by handshake and ratchet steps ----------
    def _exchange(self, use_c: bool, use_q: bool) -> tuple[bytes, bytes, bytes, bytes | None, bytes | None]:
        """Run one (hybrid) exchange; return (uplink, downlink, transcript,
        ss_c, ss_q). Gateway offers fresh keys downlink, device answers."""
        down = bytearray()
        up = bytearray()
        ss_c = ss_q = None
        if use_c:
            gw_x = x25519.X25519PrivateKey.generate()
            dev_x = x25519.X25519PrivateKey.generate()
            down += gw_x.public_key().public_bytes_raw()
            up += dev_x.public_key().public_bytes_raw()
            ss_c = dev_x.exchange(gw_x.public_key())
            assert ss_c == gw_x.exchange(dev_x.public_key())
        if use_q:
            pk, sk = self.kem.generate_keypair()        # gateway ephemeral
            ct, ss_dev = self.kem.encrypt(pk)            # device encaps
            ss_q = self.kem.decrypt(sk, ct)              # gateway decaps
            assert ss_q == ss_dev
            down += pk
            up += ct
        return bytes(up), bytes(down), h(bytes(down), bytes(up)), ss_c, ss_q

    def _handshake(self, msg_index: int) -> None:
        # Two flights. The gateway signs its ephemeral offer (like a signed
        # pre-key); the device signs the full transcript, which binds both
        # offers and its reply. The first data message gives implicit key
        # confirmation.
        cfg = self.cfg
        up, down, tr, ss_c, ss_q = self._exchange(cfg.hs_classical, cfg.hs_pq)
        if cfg.auth != "none":
            offer = b"offer" + h(down)
            sig_g = self.gw_id.sign(offer)
            sig_d = self.dev_id.sign(b"dev" + tr)
            assert verify(self.gw_id.public, offer, sig_g)
            assert verify(self.dev_id.public, b"dev" + tr, sig_d)
            down += sig_g
            up += sig_d
        fresh = (ss_c or b"") + (ss_q or b"")
        rk, ck = kdf_root(b"\x00" * 32, fresh, tr)
        self._commit_step(msg_index, "handshake", tr, ss_c, ss_q, False, rk, ck,
                          len(up), len(down))

    def _ratchet(self, msg_index: int, hybrid: bool) -> None:
        if self.cfg.rehandshake:
            self._handshake(msg_index)
            self.ratchet_events["hybrid" if hybrid else "classical"] += 1
            return
        up, down, tr, ss_c, ss_q = self._exchange(True, hybrid)
        fresh = (ss_c or b"") + (ss_q or b"")
        rk, ck = kdf_root(self.rk, fresh, tr)
        kind = "hybrid" if hybrid else "classical"
        self.ratchet_events[kind] += 1
        self._commit_step(msg_index, kind, tr, ss_c, ss_q, True, rk, ck,
                          len(up), len(down) + ENVELOPE)

    def _commit_step(self, idx, kind, tr, ss_c, ss_q, mixes, rk, ck, nup, ndown):
        self.rk, self.ck = rk, ck
        self.epoch += 1
        self.ctr = 0
        self.up += nup
        self.down += ndown
        self.frames += frames(nup) + frames(ndown)
        self.log.append(StepLog(idx, kind, tr, ss_c, ss_q, mixes, rk, ck))

    # -- data path --------------------------------------------------------
    def send(self, payload: bytes) -> bytes:
        i = len(self.msg_keys)
        cfg = self.cfg
        if i > 0:
            if cfg.q_every and i % cfg.q_every == 0:
                self._ratchet(i, hybrid=True)
            elif cfg.c_every and i % cfg.c_every == 0:
                self._ratchet(i, hybrid=False)
        if cfg.chain:
            self.ck, mk = kdf_chain(self.ck)
        else:
            mk = self.ck                       # static session key
        self.msg_keys.append(mk)
        header = self.epoch.to_bytes(2, "big") + self.ctr.to_bytes(2, "big")
        ct = AESGCM(mk).encrypt(nonce_for(self.epoch, self.ctr), payload, header)
        self.ctr += 1
        wire = header + ct
        self.up += len(wire)
        self.frames += frames(len(wire))
        return wire

    @property
    def total_bytes(self) -> int:
        return self.up + self.down


def frames(nbytes: int) -> int:
    return math.ceil(nbytes / FRAME_PAYLOAD)


# --------------------------------------------------------------------------
# Adversary simulator
# --------------------------------------------------------------------------

def adversary_recovers(sess: Session, break_classical: bool, break_pq: bool,
                       compromise_at: int | None = None) -> list[bool]:
    """Return, for every message, whether the adversary can derive its key.

    The adversary records every transcript. `break_classical` models a
    cryptographically-relevant quantum computer (learns every X25519 secret);
    `break_pq` models a cryptanalytic break of ML-KEM (learns every ML-KEM
    secret). `compromise_at=t` additionally leaks the device's full ratchet
    state (root + chain key) just before message t is sent - but not any
    ephemeral private key generated later.

    The adversary then RE-DERIVES keys with the same KDFs and every derived
    key is checked against the real one, so the result is computed, not
    asserted.
    """
    cfg = sess.cfg
    n = len(sess.msg_keys)
    known = [False] * n
    rk = None                        # adversary's view of the current root

    steps = sess.log
    bounds = [s.msg_index for s in steps] + [n]
    for si, step in enumerate(steps):
        start, end = bounds[si], bounds[si + 1]
        # Can the adversary compute this step's fresh secrets?
        need_c = step.ss_c is not None
        need_q = step.ss_q is not None
        fresh_known = (not need_c or break_classical) and (not need_q or break_pq)
        if step.mixes_old_root:
            if rk is not None and fresh_known:
                rk_new, ck = kdf_root(rk, (step.ss_c or b"") + (step.ss_q or b""),
                                      step.transcript)
            else:
                rk_new = ck = None
        else:
            if fresh_known:
                rk_new, ck = kdf_root(b"\x00" * 32,
                                      (step.ss_c or b"") + (step.ss_q or b""),
                                      step.transcript)
            else:
                rk_new = ck = None
        if rk_new is not None:
            assert rk_new == step.root_after, "adversary model diverged"
        rk = rk_new

        for m in range(start, end):
            if compromise_at is not None and m == compromise_at:
                # state leak: current root and the chain key for message m
                rk = step.root_after
                ck = _chain_key_before(sess, si, m)
            if ck is not None:
                if cfg.chain:
                    ck, mk = kdf_chain(ck)
                else:
                    mk = ck
                assert mk == sess.msg_keys[m], "adversary model diverged"
                known[m] = True
        if (compromise_at is not None and not cfg.chain
                and start <= compromise_at < end):
            # no chain ratchet: the leaked key also opens EARLIER messages
            for m in range(start, end):
                known[m] = True
    return known


def _chain_key_before(sess: Session, step_idx: int, m: int) -> bytes:
    """Recompute the chain key held just before message m (state leak)."""
    ck = sess.log[step_idx].chain_after
    if sess.cfg.chain:
        for _ in range(m - sess.log[step_idx].msg_index):
            ck, _mk = kdf_chain(ck)
    return ck


# --------------------------------------------------------------------------
# Layer 3: Mosca-adaptive policy
# --------------------------------------------------------------------------

def policy(device_class: str, shelf_life_y: float, migration_y: float = 5,
           crqc_y: float = 15, msgs_per_day: int = 96) -> dict:
    """Mosca-adaptive parameter choice.

    x = shelf_life_y (how long the data must stay secret)
    y = migration_y  (time to migrate the fleet)
    z = crqc_y       (estimated years until a CRQC)

      x + y > z  -> harvest-now-decrypt-later is a live threat
                    -> PQ key exchange REQUIRED now
      y >= z     -> forgery during the fleet's lifetime is plausible
                    -> PQ (composite) authentication required
    Cadences: a classical step about hourly; a hybrid PQ step daily when
    x + y > z, otherwise weekly; Class 1 devices double Q to save
    bandwidth. These intervals are heuristics, not derived from a model.
    """
    hndl = shelf_life_y + migration_y > crqc_y
    pq_auth = migration_y >= crqc_y or device_class == "Gateway"
    if device_class == "Class 0":
        # Cannot hold ML-KEM state (RFC 7228 class 0 ~ <10 KB RAM):
        # delegate to gateway, classical-only on the link.
        return dict(class_=device_class, kem="none (gateway proxy)",
                    auth="classical", C=max(1, msgs_per_day // 24),
                    Q=NEVER, hndl_threat=hndl, note="PQ terminated at gateway")
    level = 512 if device_class in ("Class 1",) else 768
    c = max(1, msgs_per_day // 24)                       # ~hourly
    q = msgs_per_day if hndl else msgs_per_day * 7       # daily / weekly
    if device_class == "Class 1":
        q *= 2                                           # bandwidth-starved
    return dict(class_=device_class, kem=f"ML-KEM-{level}",
                auth="composite" if pq_auth else "classical",
                C=c, Q=q, hndl_threat=hndl,
                note="HNDL: PQ KEX mandatory" if hndl else "PQ KEX as insurance")
