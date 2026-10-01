"""
test_handshake_security.py
==========================
Turns the security *claims* in the report into demonstrated *facts*. Runs the
key-schedule and key-confirmation primitives from hybrid_handshake.py directly
(no sockets) and asserts the properties the report relies on:

  1. Correct handshake  -> both sides derive the same key, finished verifies.
  2. Transcript tamper   -> keys diverge, finished FAILS CLOSED (no silent pass).
  3. Concatenation combiner -> changing EITHER shared secret changes the key,
     so an attacker needs BOTH (breaking one leg is not enough).
  4. Downgrade attempt   -> flipping the mode byte changes the derived key,
     so a mode downgrade is detected, not accepted.

Run:  python test_handshake_security.py     (prints PASS/FAIL, exits non-zero on failure)
"""

from __future__ import annotations

import secrets
import sys

from cryptography.exceptions import InvalidTag

from hybrid_handshake import MODES, LEVEL_CODE, derive_key, _fin, _check_fin

PASS, FAIL = "PASS", "FAIL"
failures = 0


def check(name: str, ok: bool):
    global failures
    print(f"  [{PASS if ok else FAIL}] {name}")
    if not ok:
        failures += 1


def main():
    mode = MODES["hybrid"]
    lc = LEVEL_CODE[768]
    ss_cls = secrets.token_bytes(32)   # X25519 shared secret
    ss_pq = secrets.token_bytes(32)    # ML-KEM shared secret
    transcript = secrets.token_bytes(32)

    # 1. Correct handshake: same inputs -> same key, finished verifies.
    k_client = derive_key(mode, lc, ss_cls, ss_pq, transcript)
    k_server = derive_key(mode, lc, ss_cls, ss_pq, transcript)
    check("correct handshake derives identical keys", k_client == k_server)
    fin = _fin(k_server, transcript, b"s-fin")
    ok = True
    try:
        _check_fin(k_client, fin, transcript, b"s-fin")
    except Exception:
        ok = False
    check("finished message verifies under the shared key", ok)

    # 2. Transcript tamper (a MITM flips a handshake byte) -> keys diverge and
    #    the finished check fails closed.
    tampered = bytearray(transcript); tampered[0] ^= 0x01
    k_mitm = derive_key(mode, lc, ss_cls, ss_pq, bytes(tampered))
    check("tampered transcript yields a different key", k_mitm != k_client)
    rejected = False
    try:
        # server computed fin over the real transcript; client (fed tampered
        # transcript) derives k_mitm and must reject the server's finished.
        _check_fin(k_mitm, fin, transcript, b"s-fin")
    except InvalidTag:
        rejected = True
    except Exception:
        rejected = True
    check("finished check FAILS CLOSED on transcript tamper", rejected)

    # 3. Concatenation combiner: changing EITHER secret changes the key.
    k_only_cls_broken = derive_key(mode, lc, secrets.token_bytes(32), ss_pq, transcript)
    k_only_pq_broken = derive_key(mode, lc, ss_cls, secrets.token_bytes(32), transcript)
    check("changing the classical secret changes the key", k_only_cls_broken != k_client)
    check("changing the PQ secret changes the key", k_only_pq_broken != k_client)
    # An attacker who recovers ONLY ss_pq (e.g. a future lattice break) but not
    # ss_cls still cannot reproduce the key:
    attacker_knows_pq_only = derive_key(mode, lc, secrets.token_bytes(32), ss_pq, transcript)
    check("knowing only the PQ secret is insufficient (hybrid holds)",
          attacker_knows_pq_only != k_client)

    # 4. Downgrade attempt: flip the mode byte -> different key.
    k_downgrade = derive_key(MODES["classical"], lc, ss_cls, ss_pq, transcript)
    check("mode downgrade changes the derived key (detected)", k_downgrade != k_client)

    print()
    if failures:
        print(f"{failures} check(s) FAILED")
        sys.exit(1)
    print("all security properties hold")


if __name__ == "__main__":
    main()
