"""
hybrid_handshake.py
===================
Client-server key-establishment prototype: classical vs post-quantum vs
HYBRID key exchange over a real TCP socket, measuring handshake latency and
exact bytes-on-wire.

Fills Gap 1 of the project's gap analysis: the base paper (PQShield-IoT)
uses pure Kyber512+Dilithium2 with no classical component, whereas real
migrations run HYBRIDS - TLS 1.3's deployed `X25519MLKEM768` group derives
the session key from BOTH an X25519 exchange AND an ML-KEM encapsulation, so
the channel stays secure unless BOTH problems (elliptic-curve discrete log
AND module-lattice) fall. This script demonstrates and prices that design.

Protocol (one round trip + key confirmation, mirroring TLS 1.3 key_share)
--------------------------------------------------------------------------
  msg1  client -> server : mode || level || [X25519 pub 32 B] || [ML-KEM pub]
  msg2  server -> client : [X25519 pub 32 B] || [ML-KEM ciphertext]
        both sides:  transcript = SHA3-256(msg1 || msg2)
                     ikm  = ss_x25519 || ss_mlkem   (whichever the mode uses)
                     key  = SHA3-256("CNS-hybrid-v1" || mode || level
                                      || ikm || transcript)
  msg3  client -> server : AES-256-GCM_key(transcript), AAD "c-fin"
  msg4  server -> client : AES-256-GCM_key(transcript), AAD "s-fin"

The mutual "finished" messages prove both sides derived the same key over
the same transcript (key confirmation), and exercise the symmetric layer the
base paper also uses (AES-256-GCM with a SHA3-256-derived key).

Design notes to defend in the viva
----------------------------------
* X25519 carries the classical share - it is the curve in TLS 1.3's deployed
  hybrid (X25519MLKEM768), and our Phase-2 benchmarks show it is the fastest
  classical KEM on this machine.
* The hybrid secret is the KDF of the CONCATENATED shared secrets. Modelling
  SHA3-256 as a random oracle (equivalently, a secure KDF/PRF), the derived
  key is indistinguishable from random as long as AT LEAST ONE shared secret
  stays unknown, so an attacker must recover BOTH ss_x25519 AND ss_mlkem.
  (Preimage resistance alone is NOT the right property here - the guarantee
  is PRF/RO-style indistinguishability.) The transcript, which binds BOTH
  ciphertexts (msg1 || msg2), is fed into the KDF: Giacon-Heuer-Poettering
  (2018) showed a concatenation combiner needs this ciphertext binding to be
  robust. This is the argument used by X25519MLKEM768.
* The KDF binds mode, level, and the full transcript (like TLS's key
  schedule, and like the base paper's Eq. 5 binding IDs/timestamps into its
  session key): a MITM who tampers with any handshake byte lands both sides
  on different keys, and the finished exchange fails closed.
* Frames are length-prefixed (4-byte big-endian). Byte counts below include
  these prefixes - they are real wire bytes.
* Latency is measured client-side from "send msg1" to "server finished
  verified" - i.e. the cryptographic handshake including one network round
  trip, excluding TCP connection setup. On localhost the RTT is ~0.1 ms, so
  the numbers isolate crypto + serialization cost; over a real 802.15.4 link
  the radio (and fragmentation of the PQC shares!) would dominate - which is
  exactly the point the report makes with the bytes-on-wire column.

SECURITY NOTE: this is an ephemeral, UNAUTHENTICATED key exchange - a
demonstration of key establishment, not a full AKE. Without signatures or
pre-registered identities a MITM can sit in the middle (each leg is still
individually secure). Authentication is the base paper's blockchain/
Dilithium layer and Phase 2's signature benchmarks; composing them is
discussed in the report, not implemented here.

Usage
-----
  python hybrid_handshake.py                 # demo: all modes in-process,
                                             #       table + CSV
  python hybrid_handshake.py --server --port 9999          # terminal 1
  python hybrid_handshake.py --client --port 9999 \
         --mode hybrid --level 768 --reps 100              # terminal 2

Output: ../results/handshake_results.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import secrets
import socket
import statistics
import struct
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem import ml_kem_512, ml_kem_768

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

MODES = {"classical": 1, "pq": 2, "hybrid": 3}
MODE_NAMES = {v: k for k, v in MODES.items()}
LEVELS = {512: ml_kem_512, 768: ml_kem_768}
LEVEL_CODE = {512: 0, 768: 1}
CODE_LEVEL = {v: k for k, v in LEVEL_CODE.items()}

X25519_PUB = 32


# --------------------------------------------------------------------------
# Framing: every message is 4-byte big-endian length || payload.
# --------------------------------------------------------------------------

def send_frame(sock: socket.socket, payload: bytes) -> int:
    """Send one frame; return bytes put on the wire (incl. length prefix)."""
    frame = struct.pack(">I", len(payload)) + payload
    sock.sendall(frame)
    return len(frame)


def recv_frame(sock: socket.socket) -> tuple[bytes, int]:
    """Receive one frame; return (payload, wire bytes incl. prefix)."""
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length > 1 << 20:
        raise ValueError("frame too large")
    return _recv_exact(sock, length), 4 + length


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed mid-frame")
        buf.extend(chunk)
    return bytes(buf)


# --------------------------------------------------------------------------
# Key schedule
# --------------------------------------------------------------------------

def derive_key(mode: int, level_code: int, ss_classical: bytes,
               ss_pq: bytes, transcript: bytes) -> bytes:
    """key = SHA3-256(label || mode || level || ss_classical || ss_pq
                      || transcript).

    Concatenation combiner: modelling SHA3-256 as a random oracle / secure
    KDF, the key is indistinguishable from random while at least one input
    secret is unknown, so an attacker needs BOTH. (The operative property is
    PRF/RO indistinguishability, not preimage resistance.) The transcript
    binds both ciphertexts, which makes any tampered handshake byte fail
    closed at the finished check and makes the combiner robust
    (Giacon-Heuer-Poettering 2018).
    """
    h = hashlib.sha3_256()
    h.update(b"CNS-hybrid-v1")
    h.update(bytes([mode, level_code]))
    h.update(ss_classical)
    h.update(ss_pq)
    h.update(transcript)
    return h.digest()


def _fin(key: bytes, transcript: bytes, aad: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, transcript, aad)


def _check_fin(key: bytes, blob: bytes, transcript: bytes, aad: bytes) -> None:
    plaintext = AESGCM(key).decrypt(blob[:12], blob[12:], aad)
    if plaintext != transcript:
        raise ValueError("finished check failed: transcripts differ")


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------

def handle_connection(conn: socket.socket) -> None:
    msg1, _ = recv_frame(conn)
    mode, level_code = msg1[0], msg1[1]
    kem = LEVELS[CODE_LEVEL[level_code]]
    off = 2

    ss_classical = b""
    ss_pq = b""
    reply = bytearray()

    if mode in (MODES["classical"], MODES["hybrid"]):
        client_xpub = x25519.X25519PublicKey.from_public_bytes(
            msg1[off:off + X25519_PUB])
        off += X25519_PUB
        eph = x25519.X25519PrivateKey.generate()
        ss_classical = eph.exchange(client_xpub)
        reply += eph.public_key().public_bytes_raw()

    if mode in (MODES["pq"], MODES["hybrid"]):
        client_kem_pub = msg1[off:off + kem.PUBLIC_KEY_SIZE]
        ct, ss_pq = kem.encrypt(client_kem_pub)
        reply += ct

    msg2 = bytes(reply)
    send_frame(conn, msg2)

    transcript = hashlib.sha3_256(msg1 + msg2).digest()
    key = derive_key(mode, level_code, ss_classical, ss_pq, transcript)

    fin_c, _ = recv_frame(conn)
    _check_fin(key, fin_c, transcript, b"c-fin")
    send_frame(conn, _fin(key, transcript, b"s-fin"))


def run_server(host: str, port: int, ready: threading.Event | None = None,
               quiet: bool = False) -> None:
    srv = socket.create_server((host, port))
    if ready is not None:
        ready.port = srv.getsockname()[1]  # type: ignore[attr-defined]
        ready.set()
    if not quiet:
        print(f"server listening on {host}:{srv.getsockname()[1]} (Ctrl+C to stop)")
    while True:
        conn, _ = srv.accept()
        with conn:
            try:
                handle_connection(conn)
            except Exception as e:
                if not quiet:
                    print(f"  handshake failed: {e}")


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------

def one_handshake(host: str, port: int, mode: int, level: int
                  ) -> tuple[float, int, int]:
    """Run one handshake; return (kex ms, bytes client->server, bytes s->c)."""
    kem = LEVELS[level]
    with socket.create_connection((host, port)) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Build msg1 before starting the clock? No - key generation is part
        # of the handshake work a device performs per session, so the clock
        # starts before keygen.
        t0 = time.perf_counter_ns()

        parts = bytearray([mode, LEVEL_CODE[level]])
        xpriv = kem_priv = None
        if mode in (MODES["classical"], MODES["hybrid"]):
            xpriv = x25519.X25519PrivateKey.generate()
            parts += xpriv.public_key().public_bytes_raw()
        if mode in (MODES["pq"], MODES["hybrid"]):
            kem_pub, kem_priv = kem.generate_keypair()
            parts += kem_pub
        msg1 = bytes(parts)
        sent = send_frame(sock, msg1)

        msg2, rcvd = recv_frame(sock)
        off = 0
        ss_classical = b""
        ss_pq = b""
        if xpriv is not None:
            server_xpub = x25519.X25519PublicKey.from_public_bytes(
                msg2[off:off + X25519_PUB])
            off += X25519_PUB
            ss_classical = xpriv.exchange(server_xpub)
        if kem_priv is not None:
            ct = msg2[off:off + kem.CIPHERTEXT_SIZE]
            ss_pq = kem.decrypt(kem_priv, ct)

        transcript = hashlib.sha3_256(msg1 + msg2).digest()
        key = derive_key(mode, LEVEL_CODE[level], ss_classical, ss_pq, transcript)

        sent += send_frame(sock, _fin(key, transcript, b"c-fin"))
        fin_s, n = recv_frame(sock)
        rcvd += n
        _check_fin(key, fin_s, transcript, b"s-fin")

        elapsed_ms = (time.perf_counter_ns() - t0) / 1e6
    return elapsed_ms, sent, rcvd


def run_client(host: str, port: int, mode_name: str, level: int, reps: int,
               warmup: int = 5) -> dict:
    mode = MODES[mode_name]
    for _ in range(warmup):
        one_handshake(host, port, mode, level)
    times = []
    sent = rcvd = 0
    for _ in range(reps):
        ms, s, r = one_handshake(host, port, mode, level)
        times.append(ms)
        sent, rcvd = s, r  # constant per mode/level
    return {
        "mode": mode_name,
        "level": level if mode != MODES["classical"] else "-",
        "reps": reps,
        "median_ms": round(statistics.median(times), 4),
        "mean_ms": round(statistics.fmean(times), 4),
        "min_ms": round(min(times), 4),
        "max_ms": round(max(times), 4),
        "bytes_c2s": sent,
        "bytes_s2c": rcvd,
        "bytes_total": sent + rcvd,
    }


# --------------------------------------------------------------------------
# Demo mode: all configurations against an in-process server
# --------------------------------------------------------------------------

DEMO_CONFIGS = [
    ("classical", 768),   # level ignored for classical
    ("pq", 512),
    ("pq", 768),
    ("hybrid", 512),
    ("hybrid", 768),      # mirrors TLS 1.3 X25519MLKEM768
]


def run_demo(reps: int) -> None:
    ready = threading.Event()
    threading.Thread(target=run_server, args=("127.0.0.1", 0, ready, True),
                     daemon=True).start()
    ready.wait(5)
    port = ready.port  # type: ignore[attr-defined]

    rows = []
    for mode_name, level in DEMO_CONFIGS:
        label = mode_name if mode_name == "classical" else f"{mode_name}-{level}"
        print(f"  {label:13s} x{reps} handshakes ...", end="", flush=True)
        row = run_client("127.0.0.1", port, mode_name, level, reps)
        rows.append(row)
        print(f" median {row['median_ms']:7.3f} ms, "
              f"{row['bytes_total']:5d} B on wire")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / "handshake_results.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"\n{'config':<14}{'median ms':>10}{'min':>9}{'max':>9}"
          f"{'c->s B':>9}{'s->c B':>9}{'total B':>9}")
    for r in rows:
        label = r["mode"] if r["mode"] == "classical" else f"{r['mode']}-{r['level']}"
        print(f"{label:<14}{r['median_ms']:>10.3f}{r['min_ms']:>9.3f}"
              f"{r['max_ms']:>9.3f}{r['bytes_c2s']:>9}{r['bytes_s2c']:>9}"
              f"{r['bytes_total']:>9}")
    print(f"\nwrote {out}")


def main():
    ap = argparse.ArgumentParser(description="Classical / PQ / hybrid handshake demo")
    role = ap.add_mutually_exclusive_group()
    role.add_argument("--server", action="store_true")
    role.add_argument("--client", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--mode", choices=MODES, default="hybrid")
    ap.add_argument("--level", type=int, choices=LEVELS, default=768)
    ap.add_argument("--reps", type=int, default=100)
    args = ap.parse_args()

    if args.server:
        run_server(args.host, args.port)
    elif args.client:
        row = run_client(args.host, args.port, args.mode, args.level, args.reps)
        for k, v in row.items():
            print(f"{k:>12}: {v}")
    else:
        run_demo(args.reps)


if __name__ == "__main__":
    main()
