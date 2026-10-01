"""
plot_results.py
===============
Generate report figures from the CSVs produced by benchmark_pqc.py.

Design decisions (from the data-viz method used):
* Benchmark values span roughly four to five orders of magnitude (tens of
  microseconds to around a second), so we use Cleveland DOT PLOTS on a log
  axis: position encodes value, which stays honest on a log scale. Bars on a
  log axis are avoided - bar *length* stops meaning anything.
* One color per algorithm FAMILY (identity encoding, fixed order, validated
  colorblind-safe palette). Classical schemes additionally carry a dagger
  so family is never encoded by color alone.
* Dot = median; thin whisker = min..max of the timing samples (sub-ms ops
  are sampled as batch means - see benchmark_pqc.py - so their whiskers show
  steady-state spread; per-call ops like RSA keygen and Dilithium sign show
  raw per-call variance such as prime-search and rejection-sampling tails).
* Direct value labels only on the extremes of each panel; the CSVs are the
  full table view.
* Solid hairline grid, recessive axes, no dual axes.

Outputs (../results/):
    fig1_kem_timings.png, fig2_sig_timings.png,
    fig3_sizes.png, fig4_sign_tradeoff.png
"""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

RESULTS = Path(__file__).resolve().parent.parent / "results"

# Validated categorical palette (light mode), fixed slot order by family.
FAMILY_COLOR = {
    "Classical":  "#2a78d6",  # slot 1 blue
    "Lattice":    "#1baf7a",  # slot 2 aqua
    "Code-based": "#eda100",  # slot 3 yellow
    "Hash-based": "#008300",  # slot 4 green
}
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
BASELINE = "#c3c2b7"

plt.rcParams.update({
    "font.family": ["Segoe UI", "DejaVu Sans"],
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "text.color": INK,
    "axes.edgecolor": BASELINE,
    "xtick.color": INK_2,
    "ytick.color": INK_2,
    "axes.labelcolor": MUTED,
    "font.size": 9,
})


def fmt_ms(v: float) -> str:
    if v >= 1000:
        return f"{v / 1000:.2g} s"
    if v >= 1:
        return f"{v:.3g} ms"
    return f"{v:.2g} ms"


def display_name(row) -> str:
    # Dagger marks quantum-broken schemes so color is not the only encoding.
    return row["algorithm"] + (" †" if row["quantum_resistant"] == "no" else "")


def style_axis(ax):
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(BASELINE)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)  # solid hairline
    ax.yaxis.grid(False)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)


def dot_panel(ax, df_op: pd.DataFrame, order: list[str], title: str):
    """One Cleveland-dot panel: y = algorithm, x = median ms (log)."""
    d = df_op.set_index("display").reindex(order)
    y = range(len(order))
    for yi, (name, row) in zip(y, d.iterrows()):
        c = FAMILY_COLOR[row["family"]]
        ax.hlines(yi, row["min_ms"], row["max_ms"], color=c, lw=1.4, alpha=0.45)
        ax.plot(row["median_ms"], yi, "o", ms=7, color=c,
                markeredgecolor=SURFACE, markeredgewidth=1.2, zorder=3)
    ax.set_yticks(list(y), order)
    ax.set_xscale("log")
    ax.set_title(title, loc="left", fontsize=10, color=INK, pad=8)
    ax.set_xlabel("time, ms (log scale)")
    style_axis(ax)
    # Direct labels on the two extremes only; the CSV is the full table.
    med = d["median_ms"]
    for name in (med.idxmin(), med.idxmax()):
        row = d.loc[name]
        yi = order.index(name)
        ax.annotate(fmt_ms(row["median_ms"]),
                    (row["median_ms"], yi), xytext=(0, -11),
                    textcoords="offset points", ha="center",
                    fontsize=8, color=INK_2)


def family_legend(fig, families: list[str]):
    handles = [plt.Line2D([], [], marker="o", ls="", ms=7,
                          color=FAMILY_COLOR[f], markeredgecolor=SURFACE,
                          label=f) for f in FAMILY_COLOR if f in families]
    fig.legend(handles=handles, loc="upper right", frameon=False,
               ncol=len(handles), bbox_to_anchor=(0.99, 0.99), fontsize=9)


def fig_timings(t: pd.DataFrame, kind: str, ops: list[str],
                outfile: str, suptitle: str):
    sub = t[t["kind"] == kind].copy()
    sub["display"] = sub.apply(display_name, axis=1)
    order = list(pd.unique(sub["display"]))  # CSV order: classical first

    fig, axes = plt.subplots(1, len(ops), figsize=(12, 0.42 * len(order) + 2.2),
                             sharey=True)
    for ax, op in zip(axes, ops):
        dot_panel(ax, sub[sub["operation"] == op], order, op)
    axes[0].invert_yaxis()  # once: the y-axis is shared, panels must not re-invert
    lo = sub["min_ms"].min() * 0.5
    hi = sub["max_ms"].max() * 2.5
    for ax in axes:
        ax.set_xlim(lo, hi)
    fig.suptitle(suptitle, x=0.01, ha="left", fontsize=12, color=INK)
    fig.text(0.01, 0.008, "† not quantum-resistant · dot = median, "
             "line = min–max of samples · PQC: PQClean portable C; "
             "classical: OpenSSL optimized asm (gaps favour classical) · "
             "see system_info.txt", fontsize=7.5, color=MUTED)
    family_legend(fig, list(sub["family"].unique()))
    fig.tight_layout(rect=(0, 0.03, 1, 0.94))
    fig.savefig(RESULTS / outfile, dpi=200)
    plt.close(fig)
    print(f"wrote {outfile}")


def fig_sizes(s: pd.DataFrame):
    s = s.copy()
    s["display"] = s.apply(display_name, axis=1)
    panels = [
        ("public_key_bytes", "Public key"),
        ("observed_bytes", "Ciphertext (KEM) / signature (as produced)"),
    ]
    order = list(pd.unique(s["display"]))
    fig, axes = plt.subplots(1, 2, figsize=(11, 0.42 * len(order) + 2.2),
                             sharey=True)
    for ax, (col, title) in zip(axes, panels):
        d = s.set_index("display").reindex(order)
        for yi, (name, row) in enumerate(d.iterrows()):
            ax.plot(row[col], yi, "o", ms=7, color=FAMILY_COLOR[row["family"]],
                    markeredgecolor=SURFACE, markeredgewidth=1.2, zorder=3)
        ax.set_yticks(range(len(order)), order)
        ax.set_xscale("log")
        ax.set_title(title, loc="left", fontsize=10, color=INK, pad=8)
        ax.set_xlabel("bytes (log scale)")
        style_axis(ax)
        for name in (d[col].idxmin(), d[col].idxmax()):
            yi = order.index(name)
            ax.annotate(f"{int(d.loc[name, col]):,} B", (d.loc[name, col], yi),
                        xytext=(0, -11), textcoords="offset points",
                        ha="center", fontsize=8, color=INK_2)
    axes[0].invert_yaxis()  # once: shared y-axis
    fig.suptitle("Key and ciphertext/signature sizes — what each scheme "
                 "puts on the wire", x=0.01, ha="left", fontsize=12, color=INK)
    fig.text(0.01, 0.008, "† not quantum-resistant · IEEE 802.15.4 "
             "frame payload ≈ 100 B; 6LoWPAN fragments anything larger",
             fontsize=7.5, color=MUTED)
    family_legend(fig, list(s["family"].unique()))
    fig.tight_layout(rect=(0, 0.03, 1, 0.94))
    fig.savefig(RESULTS / "fig3_sizes.png", dpi=200)
    plt.close(fig)
    print("wrote fig3_sizes.png")


def fig_tradeoff(t: pd.DataFrame, s: pd.DataFrame):
    sig_t = t[(t["kind"] == "Signature") & (t["operation"] == "sign")]
    sig_t = sig_t.set_index("algorithm")
    sig_s = s[s["kind"] == "Signature"].set_index("algorithm")

    fig, ax = plt.subplots(figsize=(8.5, 6))
    placed: list[tuple[float, float]] = []
    for alg in sig_s.index:
        x = sig_t.loc[alg, "median_ms"]
        y = sig_s.loc[alg, "observed_bytes"]
        fam = sig_s.loc[alg, "family"]
        dagger = " †" if sig_s.loc[alg, "quantum_resistant"] == "no" else ""
        ax.plot(x, y, "o", ms=9, color=FAMILY_COLOR[fam],
                markeredgecolor=SURFACE, markeredgewidth=1.5, zorder=3)
        # If a neighbour sits close in log-log space, push this label away
        # from it vertically so names never overlap.
        ratio = lambda a, b: max(a, b) / min(a, b)
        near = [py for px, py in placed if ratio(x, px) < 3 and ratio(y, py) < 1.8]
        dy = 5 if not near else (10 if y >= max(near) else -16)
        ax.annotate(alg.split(" (")[0] + dagger, (x, y), xytext=(7, dy),
                    textcoords="offset points", fontsize=8.5, color=INK_2)
        placed.append((x, y))
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("sign time, median ms (log)")
    ax.set_ylabel("signature size, bytes (log)")
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_title("The signature trade-off space — lower-left is better "
                 "for constrained IoT", loc="left", fontsize=12, color=INK, pad=10)
    style_axis(ax)
    family_legend(fig, list(sig_s["family"].unique()))
    fig.text(0.01, 0.008, "† not quantum-resistant · ML-DSA-44 = "
             "Dilithium2, the base paper's choice", fontsize=7.5, color=MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 0.95))
    fig.savefig(RESULTS / "fig4_sign_tradeoff.png", dpi=200)
    plt.close(fig)
    print("wrote fig4_sign_tradeoff.png")


def fig_handshake():
    """Latency + bytes-on-wire for the Phase-3 handshake prototype."""
    h = pd.read_csv(RESULTS / "handshake_results.csv")
    labels = [r["mode"] if r["mode"] == "classical" else f"{r['mode']}-{r['level']}"
              for _, r in h.iterrows()]
    y = range(len(h))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 0.55 * len(h) + 2.2))

    # Panel 1: handshake latency (dot = median, whisker = min-max)
    for yi, (_, r) in zip(y, h.iterrows()):
        ax1.hlines(yi, r["min_ms"], r["max_ms"], color=FAMILY_COLOR["Classical"],
                   lw=1.4, alpha=0.45)
        ax1.plot(r["median_ms"], yi, "o", ms=7, color=FAMILY_COLOR["Classical"],
                 markeredgecolor=SURFACE, markeredgewidth=1.2, zorder=3)
        ax1.annotate(f"{r['median_ms']:.2f} ms", (r["median_ms"], yi),
                     xytext=(0, -12), textcoords="offset points",
                     ha="center", fontsize=8, color=INK_2)
    ax1.set_yticks(list(y), labels)
    ax1.invert_yaxis()
    ax1.set_xlim(0, h["max_ms"].max() * 1.15)
    ax1.set_title("Handshake latency (localhost)", loc="left",
                  fontsize=10, color=INK, pad=8)
    ax1.set_xlabel("ms — dot = median, line = min–max")
    style_axis(ax1)

    # Panel 2: bytes on the wire, stacked by direction (linear, zero-based)
    left = [0] * len(h)
    for col, name, color in [("bytes_c2s", "client → server", "#2a78d6"),
                             ("bytes_s2c", "server → client", "#1baf7a")]:
        ax2.barh(list(y), h[col], left=left, height=0.5, color=color,
                 label=name, edgecolor=SURFACE, linewidth=2)
        left = [a + b for a, b in zip(left, h[col])]
    for yi, total in zip(y, h["bytes_total"]):
        ax2.annotate(f"{total:,} B", (total, yi), xytext=(5, 0),
                     textcoords="offset points", va="center",
                     fontsize=8, color=INK_2)
    ax2.set_yticks(list(y), labels)
    ax2.invert_yaxis()
    ax2.set_xlim(0, h["bytes_total"].max() * 1.18)
    ax2.set_title("Bytes on the wire (entire handshake)", loc="left",
                  fontsize=10, color=INK, pad=8)
    ax2.set_xlabel("bytes")
    ax2.legend(frameon=False, fontsize=8.5, loc="upper right")
    style_axis(ax2)

    fig.suptitle("Classical vs post-quantum vs hybrid key exchange — "
                 "the price of hybrid insurance", x=0.01, ha="left",
                 fontsize=12, color=INK)
    lvl = h["level"].astype(str)
    d_ms = (h.loc[(h["mode"] == "hybrid") & (lvl == "768"), "median_ms"].iloc[0]
            - h.loc[(h["mode"] == "pq") & (lvl == "768"), "median_ms"].iloc[0])
    fig.text(0.01, 0.008, "hybrid-768 mirrors TLS 1.3 X25519MLKEM768 · "
             f"hybrid adds only 64 B and ~{d_ms:.1f} ms over pure ML-KEM-768",
             fontsize=7.5, color=MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 0.92))
    fig.savefig(RESULTS / "fig5_handshake.png", dpi=200)
    plt.close(fig)
    print("wrote fig5_handshake.png")


def fig_timing():
    """Side-channel analysis: prefix-timing leak + ML-KEM decaps constancy."""
    df = pd.read_csv(RESULTS / "timing_analysis.csv")
    a = df[df["experiment"] == "A:tag-compare"].copy()
    a["prefix"] = a["input_class"].str.extract(r"prefix=(\d+)").astype(int)
    b = df[df["experiment"] == "B:mlkem-decaps"].copy()

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Panel 1: median time vs matching-prefix length, one line per comparer.
    cmap = {"naive Python loop": FAMILY_COLOR["Code-based"],   # the leaky one
            "bytes == (memcmp)": FAMILY_COLOR["Classical"],
            "hmac.compare_digest": FAMILY_COLOR["Lattice"]}
    for fn_name, g in a.groupby("function"):
        g = g.sort_values("prefix")
        ax1.plot(g["prefix"], g["median_ns"], "-o", ms=5, lw=2,
                 color=cmap[fn_name], markeredgecolor=SURFACE,
                 markeredgewidth=1, label=fn_name)
        last = g.iloc[-1]
        ax1.annotate(fn_name, (last["prefix"], last["median_ns"]),
                     xytext=(6, 0), textcoords="offset points",
                     va="center", fontsize=8.5, color=INK_2)
    ax1.set_title("Exp. A — MAC-tag rejection time vs bytes guessed correctly",
                  loc="left", fontsize=10.5, color=INK, pad=8)
    ax1.set_xlabel("matching prefix length (bytes correct)")
    ax1.set_ylabel("median rejection time, ns/call")
    ax1.set_xlim(-1, 42)
    style_axis(ax1)
    ax1.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax1.annotate("naive loop leaks:\nrising time reveals\nthe secret byte-by-byte",
                 (8, a[a["function"] == "naive Python loop"]["median_ns"].max()),
                 xytext=(10, -60), textcoords="offset points", fontsize=8,
                 color=cmap["naive Python loop"],
                 arrowprops=dict(arrowstyle="->", color=cmap["naive Python loop"]))

    # Panel 2: ML-KEM-512 decapsulation time by ciphertext class (mean ± std).
    order = ["valid ct", "1 bit flipped", "random bytes"]
    b = b.set_index("input_class").reindex(order)
    us = b["mean_ns"] / 1000.0
    err = b["stdev_ns"] / 1000.0
    ys = range(len(order))
    ax2.errorbar(us, list(ys), xerr=err, fmt="o", ms=9,
                 color=FAMILY_COLOR["Lattice"], ecolor=BASELINE,
                 elinewidth=1.5, capsize=4, markeredgecolor=SURFACE,
                 markeredgewidth=1.2)
    ax2.set_yticks(list(ys), order)
    ax2.invert_yaxis()
    ax2.set_title("Exp. B — ML-KEM-512 decapsulation time by ciphertext class",
                  loc="left", fontsize=10.5, color=INK, pad=8)
    ax2.set_xlabel("mean decapsulation time, µs (whisker = ±1 std)")
    lo = float((us - err).min()); hi = float((us + err).max())
    pad = (hi - lo) * 0.6
    ax2.set_xlim(lo - pad, hi + pad)
    style_axis(ax2)
    ax2.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax2.annotate("valid vs corrupted overlap within ±1σ →\n"
                 "implicit-rejection path is constant-time\n(|z| < 0.3, no oracle)",
                 (float(us.mean()), 1.5), xytext=(0, 0), textcoords="offset points",
                 ha="center", fontsize=8, color=INK_2)

    fig.suptitle("Timing side-channel analysis (Gap 4) — a leak demonstrated, "
                 "and a critical path shown safe", x=0.01, ha="left",
                 fontsize=12, color=INK)
    fig.text(0.01, 0.008, "300 interleaved batch-mean samples, pinned P-core · "
             "Exp. A verdict by trend (Pearson r), not raw z · "
             "signature verify is public-input, so its variance is not a leak",
             fontsize=7.5, color=MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 0.94))
    fig.savefig(RESULTS / "fig6_timing.png", dpi=200)
    plt.close(fig)
    print("wrote fig6_timing.png")


def fig_pqm4():
    """Desktop vs Cortex-M4 (same clean-C source) + base-paper reality check."""
    c = pd.read_csv(RESULTS / "pqm4_comparison.csv")
    clean = c[c["impl"] == "clean"].copy()
    clean["label"] = clean["algorithm"].str.replace(r" \(.*\)", "", regex=True) \
        + " " + clean["operation"]
    clean = clean[clean["desktop_ms"] != ""]
    clean["desktop_ms"] = pd.to_numeric(clean["desktop_ms"])
    clean = clean.sort_values("m4_ms_at_24mhz")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 0.36 * len(clean) + 2.4),
                                   gridspec_kw={"width_ratios": [1.7, 1]})

    # Panel 1: desktop -> M4 dumbbell, log x.
    y = range(len(clean))
    for yi, r in zip(y, clean.itertuples()):
        ax1.plot([r.desktop_ms, r.m4_ms_at_24mhz], [yi, yi], "-",
                 color=BASELINE, lw=1.6, zorder=1)
        ax1.plot(r.desktop_ms, yi, "o", ms=7, color=FAMILY_COLOR["Classical"],
                 markeredgecolor=SURFACE, markeredgewidth=1.2, zorder=3)
        ax1.plot(r.m4_ms_at_24mhz, yi, "o", ms=7, color=FAMILY_COLOR["Code-based"],
                 markeredgecolor=SURFACE, markeredgewidth=1.2, zorder=3)
    ax1.axvline(1000, color=FAMILY_COLOR["Red"] if "Red" in FAMILY_COLOR else "#e34948",
                lw=1.2, ls="-", alpha=0.7)
    ax1.text(1000, len(clean) - 0.3, " 1 s: interactive limit", fontsize=8,
             color="#e34948", va="bottom", ha="left")
    ax1.set_yticks(list(y), clean["label"])
    ax1.set_xscale("log")
    ax1.invert_yaxis()
    ax1.set_title("Same clean-C source: desktop i5 vs Cortex-M4 @ 24 MHz",
                  loc="left", fontsize=10.5, color=INK, pad=8)
    ax1.set_xlabel("median latency, ms (log)")
    style_axis(ax1)
    handles = [plt.Line2D([], [], marker="o", ls="", ms=7, markeredgecolor=SURFACE,
                          color=FAMILY_COLOR["Classical"], label="desktop i5-13500H"),
               plt.Line2D([], [], marker="o", ls="", ms=7, markeredgecolor=SURFACE,
                          color=FAMILY_COLOR["Code-based"], label="Cortex-M4 @24 MHz (pqm4)")]
    ax1.legend(handles=handles, frameon=False, fontsize=8.5, loc="lower right")

    # Panel 2: the CLOCK-INDEPENDENT test. For each of the paper's Table 6
    # entries, the clock it would need to be a real cycle-accurate measurement.
    # Empty CSV cells read as NaN, so keep only rows carrying a paper value.
    b = c.dropna(subset=["base_paper_sim_ms"]).copy()
    b["implied_clock_mhz"] = pd.to_numeric(b["implied_clock_mhz"])
    b["label"] = b["algorithm"].str.replace(r" \(.*\)", "", regex=True) \
        + "\n" + b["operation"]
    yb = list(range(len(b)))
    PAPER_CLOCK = 120
    for yi, r in zip(yb, b.itertuples()):
        far = abs(r.implied_clock_mhz - PAPER_CLOCK) / PAPER_CLOCK > 0.35
        col = "#e34948" if far else FAMILY_COLOR["Lattice"]
        ax2.hlines(yi, PAPER_CLOCK, r.implied_clock_mhz, color=BASELINE, lw=1.6)
        ax2.plot(r.implied_clock_mhz, yi, "o", ms=9, color=col,
                 markeredgecolor=SURFACE, markeredgewidth=1.2, zorder=3)
        ax2.annotate(f"{r.implied_clock_mhz:.0f} MHz",
                     (r.implied_clock_mhz, yi), xytext=(0, -14),
                     textcoords="offset points", ha="center", fontsize=8.5,
                     color=col)
    ax2.axvline(PAPER_CLOCK, color=INK_2, lw=1.3)
    ax2.annotate("paper's declared\n120 MHz (Table 3)", (PAPER_CLOCK, -0.62),
                 xytext=(4, 0), textcoords="offset points", fontsize=8,
                 color=INK_2, va="center")
    ax2.set_yticks(yb, b["label"])
    ax2.set_xscale("log")
    ax2.set_ylim(len(b) - 0.4, -1.05)
    ax2.set_xlim(15, 400)
    ax2.set_title("Clock implied by each of the paper's Table 6 latencies",
                  loc="left", fontsize=10.5, color=INK, pad=8)
    ax2.set_xlabel("implied clock = pqm4 cycles / paper's ms (log)")
    style_axis(ax2)

    fig.suptitle("From desktop to device (Gap 5) — and a reality check on the "
                 "paper's simulated numbers", x=0.01, ha="left",
                 fontsize=12, color=INK)
    fig.text(0.01, 0.008, "pqm4 clean-C cycle counts (github.com/mupq/pqm4) · "
             "cross-platform ms are indicative · the paper's four latencies imply "
             "clocks spanning 25–189 MHz (7.5×), so they cannot all be "
             "cycle-accurate measurements of one device at one frequency",
             fontsize=7.5, color=MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 0.93))
    fig.savefig(RESULTS / "fig7_pqm4.png", dpi=200)
    plt.close(fig)
    print("wrote fig7_pqm4.png")


def main():
    t = pd.read_csv(RESULTS / "timings.csv")
    s = pd.read_csv(RESULTS / "sizes.csv")
    fig_timings(t, "KEM", ["keygen", "encapsulate", "decapsulate"],
                "fig1_kem_timings.png",
                "Key-establishment (KEM) performance — classical vs post-quantum")
    fig_timings(t, "Signature", ["keygen", "sign", "verify"],
                "fig2_sig_timings.png",
                "Digital-signature performance — classical vs post-quantum")
    fig_sizes(s)
    fig_tradeoff(t, s)
    if (RESULTS / "handshake_results.csv").exists():
        fig_handshake()
    if (RESULTS / "timing_analysis.csv").exists():
        fig_timing()
    if (RESULTS / "pqm4_comparison.csv").exists():
        fig_pqm4()


if __name__ == "__main__":
    main()
