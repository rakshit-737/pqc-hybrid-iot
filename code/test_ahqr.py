"""
test_ahqr.py
============
Security-property tests for the AHQR protocol (ahqr.py).

Each test runs real cryptography and checks a property claimed in the
report. Run:  python test_ahqr.py      (or: python -m pytest test_ahqr.py)
"""

from ahqr import (Config, Identity, Session, adversary_recovers, policy,
                  verify)

N = 200
C, Q = 10, 50


def run(cfg: Config, n: int = N) -> Session:
    s = Session(cfg)
    for i in range(n):
        s.send(i.to_bytes(4, "big") * 8)
    return s


AHQR = Config("ahqr", c_every=C, q_every=Q)


def test_composite_signature_needs_both_halves():
    ident = Identity("composite")
    sig = ident.sign(b"m")
    assert verify(ident.public, b"m", sig)
    assert not verify(ident.public, b"x", sig)
    bad_ed = bytes([sig[0] ^ 1]) + sig[1:]
    bad_pq = sig[:-1] + bytes([sig[-1] ^ 1])
    assert not verify(ident.public, b"m", bad_ed)   # classical half forged
    assert not verify(ident.public, b"m", bad_pq)   # PQ half forged
    assert not verify(ident.public, b"m", sig[:64])  # PQ half stripped


def test_message_keys_are_unique():
    s = run(AHQR)
    assert len(set(s.msg_keys)) == N


def test_ratchet_cadence():
    s = run(AHQR)
    assert s.ratchet_events["hybrid"] == (N - 1) // Q
    assert s.ratchet_events["classical"] == (N - 1) // C - (N - 1) // Q


def test_passive_adversary_learns_nothing():
    s = run(AHQR)
    assert not any(adversary_recovers(s, False, False))


def test_hndl_quantum_adversary_learns_nothing():
    # CRQC breaks every X25519 exchange; ML-KEM still protects everything
    s = run(AHQR)
    assert not any(adversary_recovers(s, break_classical=True, break_pq=False))


def test_mlkem_break_alone_learns_nothing():
    s = run(AHQR)
    assert not any(adversary_recovers(s, break_classical=False, break_pq=True))


def test_both_broken_learns_everything():
    s = run(AHQR)
    assert all(adversary_recovers(s, True, True))


def test_forward_secrecy_and_classical_healing():
    s = run(AHQR)
    t = 123
    k = adversary_recovers(s, False, False, compromise_at=t)
    assert not any(k[:t])                      # forward secrecy
    nxt = (t // C + 1) * C                     # next ratchet step
    assert all(k[t:nxt]) and not any(k[nxt:])  # heals at next step


def test_pq_healing_against_quantum_adversary():
    s = run(AHQR)
    t = 123
    k = adversary_recovers(s, True, False, compromise_at=t)
    nxt_q = (t // Q + 1) * Q
    assert all(k[t:nxt_q]) and not any(k[nxt_q:])


def test_classical_ratchet_never_heals_against_quantum():
    s = run(Config("cr", hs_pq=False, auth="classical", c_every=C))
    assert all(adversary_recovers(s, True, False))


def test_static_key_compromise_exposes_whole_session():
    s = run(Config("static", hs_classical=False, level=512, chain=False))
    assert all(adversary_recovers(s, False, False, compromise_at=150))


def test_policy_mosca():
    long_lived = policy("Class 2", shelf_life_y=20)
    short = policy("Class 2", shelf_life_y=0.1)
    assert long_lived["hndl_threat"] and not short["hndl_threat"]
    assert long_lived["Q"] < short["Q"]          # more frequent PQ healing
    assert policy("Class 0", 20)["Q"] == 0       # PQ proxied by gateway


if __name__ == "__main__":
    import sys
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            try:
                fn()
                print(f"  PASS  {name}")
            except AssertionError as e:
                fails += 1
                print(f"  FAIL  {name}  {e}")
    print(f"\n{'all tests passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)
