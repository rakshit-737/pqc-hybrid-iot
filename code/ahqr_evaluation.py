"""
ahqr_evaluation.py
==================
Evaluates the AHQR protocol (ahqr.py) against four baselines.

  E1  Security matrix   - % of message keys each adversary recovers
  E2  Link cost         - bytes and IEEE 802.15.4 frames per session
  E3  Cadence trade-off - PQ interval Q vs overhead vs healing window
  E4  Compute cost      - measured time of every protocol operation
  E5  Mosca policy      - parameters chosen per device class / shelf-life

Outputs (../results/):
  ahqr_security_matrix.csv, ahqr_link_cost.csv, ahqr_cadence_sweep.csv,
  ahqr_timings.csv, ahqr_policy.csv,
  fig8_ahqr_security.png, fig9_ahqr_link_cost.png,
  fig10_ahqr_tradeoff.png, fig11_ahqr_timings.png

Usage:  python ahqr_evaluation.py [--msgs 1000] [--reps 200]
"""

from __future__ import annotations

import argparse
import statistics
import time
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
import pandas as pd

from ahqr import (NEVER, Config, Identity, Session, adversary_recovers,
                  policy, standard_configs, verify)

RESULTS = Path(__file__).resolve().parent.parent / "results"
PAYLOAD = bytes(32)          # one 32-byte telemetry reading
DATA_MSG = 4 + len(PAYLOAD) + 16
C, Q = 16, 256

SURFACE, INK, INK_2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9"
ACCENT, BLUE, RED = "#1baf7a", "#2a78d6", "#d03b3b"
plt.rcParams.update({
    "font.family": ["Segoe UI", "DejaVu Sans"], "font.size": 9,
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE, "text.color": INK,
    "axes.edgecolor": "#c3c2b7", "xtick.color": INK_2, "ytick.color": INK_2,
    "axes.labelcolor": MUTED, "axes.spines.top": False,
    "axes.spines.right": False, "axes.grid": True, "grid.color": GRID,
    "grid.linewidth": 0.6, "axes.axisbelow": True,
})

# (label, X25519 broken, ML-KEM broken, device state leaked mid-session)
SCENARIOS = [
    ("Passive eavesdropper", False, False, False),
    ("Quantum computer (X25519 broken)", True, False, False),
    ("ML-KEM cryptanalysis", False, True, False),
    ("Device state leak", False, False, True),
    ("State leak + quantum computer", True, False, True),
]


def run_session(cfg: Config, n: int) -> Session:
    s = Session(cfg)
    for _ in range(n):
        s.send(PAYLOAD)
    return s


def overhead(s: Session, n: int) -> float:
    return round((s.total_bytes - n * DATA_MSG) / n, 1)


# --------------------------------------------------------------------------
# Experiments
# --------------------------------------------------------------------------

def e1_e2(n: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    sec, link = [], []
    for cfg in standard_configs(C, Q):
        s = run_session(cfg, n)
        row = {"config": cfg.name}
        for label, bc, bq, leak in SCENARIOS:
            k = adversary_recovers(s, bc, bq, compromise_at=n // 2 if leak else None)
            row[label] = round(100 * sum(k) / n, 1)
        sec.append(row)
        link.append({"config": cfg.name, "messages": n,
                     "bytes_up": s.up, "bytes_down": s.down,
                     "bytes_total": s.total_bytes,
                     "overhead_B_per_msg": overhead(s, n),
                     "frames_802154": s.frames,
                     "classical_steps": s.ratchet_events["classical"],
                     "hybrid_steps": s.ratchet_events["hybrid"]})
        print(f"  {cfg.name:42s} {s.total_bytes:>8d} B  {s.frames:>6d} frames")
    return pd.DataFrame(sec), pd.DataFrame(link)


def e3(n: int) -> pd.DataFrame:
    rows = []
    for q in [16, 32, 64, 128, 256, 512, NEVER]:
        s = run_session(Config(f"Q={q}", c_every=C, q_every=q), n)
        # average over many leak points so the result is not an artefact
        # of where the leak lands relative to the next PQ step
        exposed = [sum(adversary_recovers(s, True, False, compromise_at=t))
                   for t in range(1, n, 37)]
        rows.append({"Q": q or "never", "overhead_B_per_msg": overhead(s, n),
                     "frames_802154": s.frames,
                     "exposed_msgs_state_leak_plus_CRQC":
                         round(statistics.fmean(exposed), 1)})
    return pd.DataFrame(rows)


def timeit(fn, reps: int) -> tuple[float, float]:
    for _ in range(3):
        fn()
    t = []
    for _ in range(reps):
        t0 = time.perf_counter_ns()
        fn()
        t.append((time.perf_counter_ns() - t0) / 1e6)
    return statistics.median(t), min(t)


def e4(reps: int) -> pd.DataFrame:
    comp = Identity("composite")
    clas = (Identity("classical"), Identity("classical"))
    comp2 = (comp, Identity("composite"))
    sig = comp.sign(b"x" * 32)
    sess = Session(Config("t"))
    ops = {
        "Handshake, composite auth (Ed25519+ML-DSA-44)":
            lambda: Session(Config("h", auth="composite"), *comp2),
        "Handshake, classical auth (Ed25519)":
            lambda: Session(Config("h", auth="classical"), *clas),
        "Composite sign (Ed25519+ML-DSA-44)": lambda: comp.sign(b"x" * 32),
        "Composite verify": lambda: verify(comp.public, b"x" * 32, sig),
        "Classical ratchet step (X25519)": lambda: sess._ratchet(0, hybrid=False),
        "Hybrid ratchet step (X25519+ML-KEM-768)": lambda: sess._ratchet(0, hybrid=True),
        "Per message (chain step + AES-256-GCM)": lambda: sess.send(PAYLOAD),
    }
    rows = []
    for name, fn in ops.items():
        r = max(20, reps // 5) if name.startswith("Handshake") else reps
        med, mn = timeit(fn, r)
        rows.append({"operation": name, "median_ms": round(med, 4),
                     "min_ms": round(mn, 4), "reps": r})
        print(f"  {name:48s} {med:8.3f} ms")
    return pd.DataFrame(rows)


def e5() -> pd.DataFrame:
    rows = []
    for dc in ["Class 0", "Class 1", "Class 2", "Gateway"]:
        for x in [0.1, 5, 25]:
            p = policy(dc, shelf_life_y=x)
            rows.append({"device_class": dc, "shelf_life_years": x,
                         "kem": p["kem"], "auth": p["auth"],
                         "C_msgs": p["C"], "Q_msgs": p["Q"] or "never",
                         "hndl_threat": p["hndl_threat"], "note": p["note"]})
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------
# Figures
# --------------------------------------------------------------------------

def fig_security(df: pd.DataFrame) -> None:
    cols = [c for c in df.columns if c != "config"]
    data = df[cols].values
    fig, ax = plt.subplots(figsize=(9.6, 3.7))
    ax.grid(False)
    cmap = LinearSegmentedColormap.from_list(
        "s", ["#e6f5ee", "#f6e3b0", "#f0b9b0", RED])
    ax.imshow(data, cmap=cmap, vmin=0, vmax=100, aspect="auto")
    last = data.shape[0] - 1
    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            v = data[i, j]
            ax.text(j, i, f"{v:g}%", ha="center", va="center",
                    color=INK if v < 80 else "white", fontsize=9,
                    fontweight="bold" if i == last else "normal")
    ax.set_xticks(range(len(cols)),
                  [c.replace(" (", "\n(").replace(" + ", "\n+ ") for c in cols],
                  fontsize=8)
    ax.set_yticks(range(len(df)), df["config"], fontsize=8.5)
    ax.get_yticklabels()[last].set_fontweight("bold")
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("Share of message keys each adversary recovers (lower is better)",
                 loc="left", fontsize=11, color=INK, pad=10)
    fig.tight_layout()
    fig.savefig(RESULTS / "fig8_ahqr_security.png", dpi=200)
    plt.close(fig)


def fig_link(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(8.8, 3.2))
    y = list(range(len(df)))
    colors = [ACCENT if c.startswith("AHQR") else BLUE for c in df["config"]]
    ax.barh(y, df["frames_802154"], color=colors, height=0.6)
    for i, (f, b) in enumerate(zip(df["frames_802154"], df["bytes_total"])):
        ax.text(f, i, f"  {f:,} frames  ({b / 1024:.0f} KB)", va="center",
                fontsize=8.5, color=INK_2)
    ax.set_yticks(y, df["config"], fontsize=8.5)
    ax.invert_yaxis()
    ax.set_xlabel(f"IEEE 802.15.4 frames for {df['messages'][0]:,} "
                  "32-byte telemetry messages")
    ax.set_xlim(0, df["frames_802154"].max() * 1.4)
    ax.grid(axis="y", visible=False)
    ax.set_title("Link cost per session (both directions)", loc="left",
                 fontsize=11, color=INK)
    fig.tight_layout()
    fig.savefig(RESULTS / "fig9_ahqr_link_cost.png", dpi=200)
    plt.close(fig)


def fig_tradeoff(df: pd.DataFrame) -> None:
    d = df[df["Q"] != "never"]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(d["overhead_B_per_msg"], d["exposed_msgs_state_leak_plus_CRQC"],
            "-o", color=ACCENT, lw=1.6, ms=6)
    for _, r in d.iterrows():
        ax.annotate(f"Q={r['Q']}", (r["overhead_B_per_msg"],
                                    r["exposed_msgs_state_leak_plus_CRQC"]),
                    textcoords="offset points", xytext=(6, 4), fontsize=8,
                    color=INK_2)
    nv = df[df["Q"] == "never"].iloc[0]
    ax.axhline(nv["exposed_msgs_state_leak_plus_CRQC"], color=RED, lw=1, ls="--")
    ax.set_xscale("log")
    ax.text(ax.get_xlim()[1], nv["exposed_msgs_state_leak_plus_CRQC"],
            f"no PQ ratchet: never heals ({nv['overhead_B_per_msg']} B/msg)",
            ha="right", va="bottom", color=RED, fontsize=8)
    ax.set_xlabel("Ratchet overhead (bytes per message, log scale)")
    ax.set_ylabel("Mean messages exposed after\nstate leak + quantum computer")
    ax.set_title(f"AHQR cadence trade-off (classical step every C={C} msgs)",
                 loc="left", fontsize=11, color=INK)
    fig.tight_layout()
    fig.savefig(RESULTS / "fig10_ahqr_tradeoff.png", dpi=200)
    plt.close(fig)


def fig_timings(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(8.4, 3.3))
    y = list(range(len(df)))
    ax.scatter(df["median_ms"], y, color=ACCENT, s=36, zorder=3)
    for i, v in enumerate(df["median_ms"]):
        ax.text(v, i, f"   {v:.3f} ms", va="center", fontsize=8.5, color=INK_2)
    ax.set_xscale("log")
    ax.set_yticks(y, df["operation"], fontsize=8.5)
    ax.invert_yaxis()
    ax.set_xlim(df["median_ms"].min() / 2, df["median_ms"].max() * 8)
    ax.set_xlabel("Median time (ms, log scale) - real PQClean / OpenSSL on this host")
    ax.grid(axis="y", visible=False)
    ax.set_title("AHQR operation cost", loc="left", fontsize=11, color=INK)
    fig.tight_layout()
    fig.savefig(RESULTS / "fig11_ahqr_timings.png", dpi=200)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--msgs", type=int, default=1000)
    ap.add_argument("--reps", type=int, default=200)
    a = ap.parse_args()
    RESULTS.mkdir(exist_ok=True)

    print("E1+E2  security matrix and link cost")
    sec, link = e1_e2(a.msgs)
    print("E3     cadence sweep")
    sweep = e3(a.msgs)
    print("E4     operation timings")
    tim = e4(a.reps)
    pol = e5()

    for df, name in [(sec, "ahqr_security_matrix"), (link, "ahqr_link_cost"),
                     (sweep, "ahqr_cadence_sweep"), (tim, "ahqr_timings"),
                     (pol, "ahqr_policy")]:
        df.to_csv(RESULTS / f"{name}.csv", index=False)
    fig_security(sec)
    fig_link(link)
    fig_tradeoff(sweep)
    fig_timings(tim)
    with pd.option_context("display.width", 200, "display.max_columns", 20):
        print("\n", sec.to_string(index=False), "\n\n", link.to_string(index=False),
              "\n\n", sweep.to_string(index=False), "\n\n", pol.to_string(index=False))


if __name__ == "__main__":
    main()
