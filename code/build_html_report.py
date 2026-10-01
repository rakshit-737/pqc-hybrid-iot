"""Generate PROJECT_REPORT.html from the template + the CSVs in results/.

Single source of truth: every timing-dependent number in the HTML report is
read from the CSVs at build time, so the page can never drift from the data
the way a hand-edited document can. Re-run after any benchmark re-run:

    python build_html_report.py

Reads   report/PROJECT_REPORT_template.html  +  results/*.csv  +  results/fig*.png
Writes  PROJECT_REPORT.html  (project root, self-contained, figures inlined)
"""
from __future__ import annotations

import base64
import csv
import datetime as dt
import html
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
TEMPLATE = ROOT / "report" / "PROJECT_REPORT_template.html"
OUT = ROOT / "PROJECT_REPORT.html"


def read_csv(name: str) -> list[dict]:
    with (RESULTS / name).open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def fmt_ms(v: float) -> str:
    """3 significant-ish figures across the µs-to-seconds range."""
    if v >= 100:
        return f"{v:,.0f}"
    if v >= 10:
        return f"{v:.1f}"
    if v >= 1:
        return f"{v:.2f}"
    return f"{v:.3f}"


def esc(s: str) -> str:
    return html.escape(s, quote=False)


# --------------------------------------------------------------------------
# Load data
# --------------------------------------------------------------------------
timings = read_csv("timings.csv")
sizes = read_csv("sizes.csv")
handshake = read_csv("handshake_results.csv")
tanalysis = read_csv("timing_analysis.csv")
pqm4 = read_csv("pqm4_comparison.csv")
matrix = read_csv("device_class_matrix.csv")

med = {(r["algorithm"], r["operation"]): float(r["median_ms"]) for r in timings}
tmax = {(r["algorithm"], r["operation"]): float(r["max_ms"]) for r in timings}
size_by_alg = {r["algorithm"]: r for r in sizes}

# display name, csv name, family class, dagger
KEMS = [
    ("ECDH P-256", "ECDH P-256", "c", True),
    ("X25519", "X25519", "c", True),
    ("RSA-2048 (OAEP)", "RSA-2048 (OAEP)", "c", True),
    ("ML-KEM-512", "ML-KEM-512 (Kyber512)", "p", False),
    ("ML-KEM-768", "ML-KEM-768 (Kyber768)", "p", False),
    ("ML-KEM-1024", "ML-KEM-1024 (Kyber1024)", "p", False),
    ("HQC-128", "HQC-128", "p", False),
]
SIGS = [
    ("ECDSA P-256", "ECDSA P-256", "c", True),
    ("Ed25519", "Ed25519", "c", True),
    ("RSA-2048 (PSS)", "RSA-2048 (PSS)", "c", True),
    ("ML-DSA-44", "ML-DSA-44 (Dilithium2)", "p", False),
    ("ML-DSA-65", "ML-DSA-65 (Dilithium3)", "p", False),
    ("Falcon-512", "Falcon-512", "p", False),
    ("Falcon-1024", "Falcon-1024", "p", False),
    ("SPHINCS+-128f", "SPHINCS+-SHA2-128f", "p", False),
    ("SPHINCS+-128s", "SPHINCS+-SHA2-128s", "p", False),
]
HILIGHT = {"ECDH P-256", "ML-KEM-512 (Kyber512)"}


def name_cell(disp: str, fam: str, dagger: bool) -> str:
    d = ' <span class="dagger">†</span>' if dagger else ""
    return f'<td class="fam-{fam}">{esc(disp)}{d}</td>'


# --------------------------------------------------------------------------
# Tables
# --------------------------------------------------------------------------
def timings_table() -> str:
    def rows(schemes, ops):
        out = []
        for disp, alg, fam, dg in schemes:
            cls = ' class="hl"' if alg in HILIGHT else ""
            cells = "".join(
                f'<td class="n">{fmt_ms(med[(alg, op)])}</td>' for op in ops
            )
            out.append(f"<tr{cls}>{name_cell(disp, fam, dg)}{cells}</tr>")
        return "\n".join(out)

    return f"""<div class="tablewrap"><table>
<caption>Report table 1 — KEM timings, median ms (results/timings.csv)</caption>
<thead><tr><th>Scheme</th><th class="n">keygen</th><th class="n">encapsulate</th><th class="n">decapsulate</th></tr></thead>
<tbody>{rows(KEMS, ["keygen", "encapsulate", "decapsulate"])}</tbody>
</table></div>
<div class="tablewrap"><table>
<caption>Report table 2 — signature timings, median ms (results/timings.csv)</caption>
<thead><tr><th>Scheme</th><th class="n">keygen</th><th class="n">sign</th><th class="n">verify</th></tr></thead>
<tbody>{rows(SIGS, ["keygen", "sign", "verify"])}</tbody>
</table></div>
<p class="small">† quantum-broken (baseline). Medians over ≥300 batched samples on a pinned
P-core; see system_info.txt for the run's environment record. Highlighted rows: the
headline comparison.</p>"""


def sizes_table() -> str:
    out = []
    for disp, alg, fam, dg in KEMS + SIGS:
        r = size_by_alg.get(alg)
        if not r:
            continue
        ct = r["ciphertext_or_signature_bytes"]
        note = ""
        if r.get("observed_min_bytes"):
            note = (
                f'~{r["observed_bytes"]} <span class="small">(var. '
                f'{r["observed_min_bytes"]}–{r["observed_max_bytes"]}; buf {ct})</span>'
            )
        cls = ' class="hl"' if alg in HILIGHT else ""
        out.append(
            f"<tr{cls}>{name_cell(disp, fam, dg)}"
            f'<td class="n">{int(r["public_key_bytes"]):,}</td>'
            f'<td class="n">{int(r["secret_key_bytes"]):,}</td>'
            f'<td class="n">{note or f"{int(ct):,}"}</td></tr>'
        )
    return f"""<div class="tablewrap"><table>
<caption>Report table 3 — sizes in bytes (results/sizes.csv)</caption>
<thead><tr><th>Scheme</th><th class="n">public key</th><th class="n">secret key</th><th class="n">ciphertext / signature</th></tr></thead>
<tbody>{"".join(out)}</tbody>
</table></div>
<p class="small">† quantum-broken. Falcon signatures use a compressed, genuinely
variable-length encoding — the benchmark samples 100 signatures and records the
distribution; the spec's fixed "padded" format is 666 B (Falcon-512).
One IEEE 802.15.4 frame carries ~100 B of payload.</p>"""


def handshake_table() -> str:
    label = {
        ("classical", "-"): ("classical (X25519 only)", "c", ""),
        ("pq", "512"): ("pure ML-KEM-512", "p", ""),
        ("pq", "768"): ("pure ML-KEM-768", "p", ""),
        ("hybrid", "512"): ("hybrid-512 (X25519+ML-KEM-512)", "h", ""),
        ("hybrid", "768"): ("hybrid-768 = TLS X25519MLKEM768", "h", ' class="hl"'),
    }
    out = []
    for r in handshake:
        disp, fam, cls = label[(r["mode"], r["level"])]
        out.append(
            f'<tr{cls}><td class="fam-{fam}">{esc(disp)}</td>'
            f'<td class="n">{float(r["median_ms"]):.3f}</td>'
            f'<td class="n">{int(r["bytes_c2s"]):,}</td>'
            f'<td class="n">{int(r["bytes_s2c"]):,}</td>'
            f'<td class="n">{int(r["bytes_total"]):,}</td></tr>'
        )
    reps = handshake[0]["reps"]
    return f"""<div class="tablewrap"><table>
<caption>Report table 4 — handshake latency and bytes-on-wire, {reps} reps each, localhost TCP (results/handshake_results.csv)</caption>
<thead><tr><th>Mode</th><th class="n">median ms</th><th class="n">client→server B</th><th class="n">server→client B</th><th class="n">total B</th></tr></thead>
<tbody>{"".join(out)}</tbody>
</table></div>"""


def timing_a_table() -> str:
    out = []
    for r in tanalysis:
        if r["experiment"] != "A:verdict":
            continue
        leak = "LEAKS" in r["verdict"]
        v = (
            f'<span style="color:var(--danger);font-weight:600">{esc(r["verdict"])}</span>'
            if leak
            else esc(r["verdict"])
        )
        out.append(
            f'<tr><td><code>{esc(r["function"])}</code></td>'
            f'<td class="n">{float(r["median_ns"]):+,.0f}</td>'
            f'<td class="n">{float(r["pearson_r"]):+.3f}</td><td>{v}</td></tr>'
        )
    return f"""<div class="tablewrap"><table>
<caption>Report table 5 — Experiment A: 32-byte tag comparison, rejection time vs correct prefix (results/timing_analysis.csv)</caption>
<thead><tr><th>Comparison</th><th class="n">Δ ns (31 − 0 correct)</th><th class="n">Pearson r</th><th>Verdict</th></tr></thead>
<tbody>{"".join(out)}</tbody>
</table></div>
<p class="small">The verdict weighs the trend's <i>magnitude</i> against a Welch-z significance
gate, not r alone — a flat-but-noisy comparison can show a high r over a sub-nanosecond Δ,
which is not an exploitable leak (the naive loop's Δ is three orders of magnitude larger).</p>"""


def timing_b_table() -> str:
    med_ns = {r["input_class"]: float(r["median_ns"]) for r in tanalysis
              if r["experiment"] == "B:mlkem-decaps"}
    valid = med_ns["valid ct"]
    out = []
    for r in tanalysis:
        if r["experiment"] != "B:verdict":
            continue
        cls = r["input_class"].replace(" vs valid", "")
        delta = float(r["median_ns"])
        out.append(
            f'<tr><td>{esc(cls)}</td>'
            f'<td class="n">{delta:+,.0f} ns</td>'
            f'<td class="n">{delta / valid:+.2%}</td>'
            f'<td class="n">{float(r["welch_z"]):+.1f}</td>'
            f'<td class="fam-p">{esc(r["verdict"].split(" (")[0])}</td></tr>'
        )
    return f"""<div class="tablewrap"><table>
<caption>Report table 6 — Experiment B: ML-KEM-512 decapsulation by ciphertext class, Δ vs valid (results/timing_analysis.csv)</caption>
<thead><tr><th>class (vs valid)</th><th class="n">Δ median</th><th class="n">relative</th><th class="n">z</th><th>verdict</th></tr></thead>
<tbody>{"".join(out)}</tbody>
</table></div>"""


def pqm4_table() -> str:
    picks = [
        ("ML-KEM-512 (Kyber512)", "encapsulate", "ML-KEM-512 encapsulate"),
        ("ML-KEM-512 (Kyber512)", "decapsulate", "ML-KEM-512 decapsulate"),
        ("ML-DSA-44 (Dilithium2)", "sign", "ML-DSA-44 sign"),
        ("Falcon-512", "verify", "Falcon-512 verify *"),
        ("SPHINCS+-SHA2-128s", "sign", "SPHINCS+-128s sign"),
    ]
    by = {(r["algorithm"], r["operation"]): r for r in pqm4}
    out = []
    for alg, op, disp in picks:
        r = by[(alg, op)]
        m4 = float(r["m4_ms_at_24mhz"])
        m4s = f"{m4/1000:,.0f} s ({m4/60000:.1f} min)" if m4 >= 10000 else f"{fmt_ms(m4)} ms"
        out.append(
            f'<tr><td class="fam-p">{esc(disp)}</td>'
            f'<td class="n">{fmt_ms(float(r["desktop_ms"]))} ms</td>'
            f'<td class="n">{m4s}</td>'
            f'<td class="n">~{float(r["m4_vs_desktop_x"]):,.0f}×</td></tr>'
        )
    return f"""<div class="tablewrap"><table>
<caption>Report table 7 — one PQClean codebase, two CPUs (results/pqm4_comparison.csv; pqm4 cycles from real STM32 silicon)</caption>
<thead><tr><th>Operation</th><th class="n">desktop i5-13500H</th><th class="n">Cortex-M4 @ 24 MHz</th><th class="n">slowdown</th></tr></thead>
<tbody>{"".join(out)}</tbody>
</table></div>
<p class="small">* Falcon's clean build does not fit pqm4's RAM; its row uses the optimised
m4-ct implementation — that memory-fit fact is itself device-matrix evidence.</p>"""


def clock_table() -> str:
    out = []
    for r in pqm4:
        if not r["implied_clock_mhz"]:
            continue
        op = {
            "encapsulate": "Kyber512 encapsulate",
            "decapsulate": "Kyber512 decapsulate",
            "sign": "Dilithium2 sign",
            "verify": "Dilithium2 verify",
        }[r["operation"]]
        out.append(
            f'<tr><td>{esc(op)}</td>'
            f'<td class="n">{int(r["m4_cycles"]):,}</td>'
            f'<td class="n">{r["base_paper_sim_ms"]} ms</td>'
            f'<td class="n"><b>{float(r["implied_clock_mhz"]):.1f} MHz</b></td></tr>'
        )
    return f"""<div class="tablewrap"><table>
<caption>Report table 8 — the implied-clock test: pqm4 measured cycles ÷ the base paper's Table 6 ms = the clock each entry would need (device declared: 120 MHz)</caption>
<thead><tr><th>Operation</th><th class="n">pqm4 cycles</th><th class="n">paper's latency</th><th class="n">implied clock</th></tr></thead>
<tbody>{"".join(out)}</tbody>
</table></div>"""


def matrix_table() -> str:
    def cell(v: str) -> str:
        t = v.strip()
        low = t.lower()
        if low == "yes" or low.startswith("yes"):
            bg, fg = "var(--pq-soft)", "var(--pq)"
        elif low == "no":
            bg, fg = "var(--danger-soft)", "var(--danger)"
        else:
            bg, fg = "var(--classical-soft)", "var(--classical)"
        return (
            f'<td><span style="background:{bg};color:{fg};border-radius:4px;'
            f'padding:.1rem .5rem;font-size:.78rem;font-weight:600;'
            f'white-space:nowrap">{esc(t)}</span></td>'
        )

    out = []
    for r in matrix:
        out.append(
            f'<tr><td>{esc(r["scheme"])}<div class="small">{esc(r["role"])}</div></td>'
            + cell(r["RFC7228_class0"]) + cell(r["RFC7228_class1"]) + cell(r["RFC7228_class2"])
            + f'<td class="small">{esc(r["rationale"])}</td></tr>'
        )
    return f"""<div class="tablewrap"><table>
<caption>Report table 9 — RFC 7228 device-class recommendations (results/device_class_matrix.csv)</caption>
<thead><tr><th>Scheme</th><th>Class 0<br><span style="text-transform:none">≪10 KiB RAM</span></th><th>Class 1<br><span style="text-transform:none">~10 KiB</span></th><th>Class 2<br><span style="text-transform:none">~50 KiB</span></th><th>Rationale</th></tr></thead>
<tbody>{"".join(out)}</tbody>
</table></div>"""


# --------------------------------------------------------------------------
# Inline numbers
# --------------------------------------------------------------------------
def inline_numbers() -> dict[str, str]:
    n = {}
    n["N_MLKEM512_ENC"] = fmt_ms(med[("ML-KEM-512 (Kyber512)", "encapsulate")])
    n["N_MLKEM512_DEC"] = fmt_ms(med[("ML-KEM-512 (Kyber512)", "decapsulate")])
    n["N_ECDH_ENC"] = fmt_ms(med[("ECDH P-256", "encapsulate")])
    total = sum(med[("ML-KEM-512 (Kyber512)", op)] for op in ("keygen", "encapsulate", "decapsulate"))
    n["N_KEM_TOTAL"] = f"{total:.1f}"
    n["N_MLDSA_SIGN"] = fmt_ms(med[("ML-DSA-44 (Dilithium2)", "sign")])
    n["N_FALCON_SIGN"] = fmt_ms(med[("Falcon-512", "sign")])
    n["N_FALCON_VER"] = fmt_ms(med[("Falcon-512", "verify")])
    n["N_SPHS_SIGN"] = fmt_ms(med[("SPHINCS+-SHA2-128s", "sign")])
    n["N_RSA_KG_MED"] = fmt_ms(med[("RSA-2048 (OAEP)", "keygen")])
    n["N_RSA_KG_MAX"] = fmt_ms(tmax[("RSA-2048 (OAEP)", "keygen")])

    gaps = [
        (med[(a, "encapsulate")] - med[(a, "decapsulate")]) * 1000
        for a in ("ML-KEM-512 (Kyber512)", "ML-KEM-768 (Kyber768)", "ML-KEM-1024 (Kyber1024)")
    ]
    n["N_GAPS"] = " / ".join(f"{g:.0f}" for g in gaps)
    n["N_GAP_AVG"] = f"{statistics.fmean(gaps):.0f}"
    n["N_URANDOM"] = f"{med[('os.urandom(32)', 'call')] * 1000:.2f}"

    hs = {(r["mode"], r["level"]): float(r["median_ms"]) for r in handshake}
    n["N_HYBRID_DMS"] = f"{hs[('hybrid', '768')] - hs[('pq', '768')]:.1f}"
    n["N_HS_CLASSICAL"] = f"{hs[('classical', '-')]:.3f}"
    n["N_HS_HYBRID768"] = f"{hs[('hybrid', '768')]:.3f}"

    verdicts = {r["function"]: r for r in tanalysis if r["experiment"] == "A:verdict"}
    naive = verdicts["naive Python loop"]
    n["N_PEARSON_NAIVE"] = f"{float(naive['pearson_r']):+.3f}"
    n["N_SLOPE"] = f"{float(naive['median_ns']) / 31:.0f}"
    memcmp = verdicts["bytes == (memcmp)"]
    n["N_R_MEMCMP"] = f"{float(memcmp['pearson_r']):.2f}"
    n["N_D_MEMCMP"] = f"{abs(float(memcmp['median_ns'])):.0f}"
    zs = [abs(float(r["welch_z"])) for r in tanalysis if r["experiment"] == "B:verdict"]
    n["N_Z_DECAPS"] = f"{max(zs):.1f}"
    seq = read_csv("timing_analysis_sequential.csv")
    verdicts_seq = [r for r in seq if r["experiment"].endswith("verdict")]
    worst = max(verdicts_seq, key=lambda r: abs(float(r["welch_z"])))
    n["N_Z_SEQ"] = f"{float(worst['welch_z']):+.1f}"
    seq_valid = next(float(r["median_ns"]) for r in seq
                     if r["experiment"].endswith("mlkem-decaps") and r["input_class"] == "valid ct")
    n["N_SEQ_PCT"] = f"{float(worst['median_ns']) / seq_valid:+.2%}"

    n["DATE"] = dt.date.today().isoformat()
    return n


# --------------------------------------------------------------------------
# Assemble
# --------------------------------------------------------------------------
def main() -> int:
    page = TEMPLATE.read_text(encoding="utf-8")

    subs = {
        "TIMINGS_TABLE": timings_table(),
        "SIZES_TABLE": sizes_table(),
        "HANDSHAKE_TABLE": handshake_table(),
        "TIMING_A_TABLE": timing_a_table(),
        "TIMING_B_TABLE": timing_b_table(),
        "PQM4_TABLE": pqm4_table(),
        "CLOCK_TABLE": clock_table(),
        "MATRIX_TABLE": matrix_table(),
        **inline_numbers(),
    }
    for i in range(1, 8):
        png = sorted(RESULTS.glob(f"fig{i}_*.png"))[0]
        b64 = base64.b64encode(png.read_bytes()).decode("ascii")
        subs[f"FIG{i}"] = f"data:image/png;base64,{b64}"

    for key, val in subs.items():
        page = page.replace("{{" + key + "}}", val)

    leftovers = [ln for ln in page.splitlines() if "{{" in ln]
    if leftovers:
        print("UNRESOLVED PLACEHOLDERS:")
        for ln in leftovers:
            print("  ", ln.strip()[:100])
        return 1

    OUT.write_text(page, encoding="utf-8")
    print(f"wrote {OUT}  ({OUT.stat().st_size/1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
