# Compiling the IEEE Report

No LaTeX toolchain is installed on this machine, so the report is written to
compile on **Overleaf** (free, no install) — the standard route for a college
IEEE-format submission.

## Fastest path (Overleaf)

1. Go to overleaf.com → **New Project → Upload Project**.
2. Upload these three things:
   * `report.tex`
   * `references.bib`
   * the **seven figures** from `../results/` (list below).
3. Put the figures either in the project root or in a folder named `figures/`
   — `report.tex` already sets `\graphicspath{{figures/}{../results/}}`, so
   either works. (Overleaf can't read `../results/`, so the figures must be
   uploaded into the Overleaf project.)
4. Set the compiler to **pdfLaTeX** (Menu → Compiler). Overleaf runs
   LaTeX → BibTeX → LaTeX → LaTeX automatically. Click **Recompile**.

The document class is `IEEEtran` (`[conference]`), which Overleaf ships by
default — nothing to install.

## Figures to upload (from `results/`)

Upload **all seven** — the `.tex` references every one:

| file | used as | shows |
|------|---------|-------|
| `fig1_kem_timings.png` | Fig. 1 | KEM performance, classical vs PQC |
| `fig2_sig_timings.png` | Fig. 2 | signature performance by operation |
| `fig3_sizes.png` | Fig. 3 | key/ciphertext/signature sizes |
| `fig4_sign_tradeoff.png` | Fig. 4 | signature time-vs-size trade-off |
| `fig5_handshake.png` | Fig. 5 | classical/PQ/hybrid handshake |
| `fig6_timing.png` | Fig. 6 | timing side-channel analysis |
| `fig7_pqm4.png` | Fig. 7 | desktop→M4 + simulated-vs-measured |

If your course caps the page count, `fig2` and `fig3` are the two safest to
drop (their content is summarised in Tables I–II); remove the `figure`
blocks and the `Fig.~\ref{fig:sig}` / `Fig.~\ref{fig:sizes}` mentions.

## If you later install LaTeX locally

Install MiKTeX (Windows) or TeX Live, then from `report/`:

```powershell
pdflatex report
bibtex report
pdflatex report
pdflatex report
```

Copy the `results/*.png` files next to `report.tex` (or into `report/figures/`)
first, since local pdfLaTeX also cannot read `../results/` on all setups —
though `\graphicspath` includes `../results/`, which works in most local trees.

## Numbers in the report

Every table value is traceable to a CSV in `results/`:
`timings.csv`, `sizes.csv`, `handshake_results.csv`, `timing_analysis.csv`,
`pqm4_comparison.csv`, `device_class_matrix.csv`. If you re-run the scripts on
your machine, update the corresponding table cells (the qualitative story is
stable; absolute ms will shift with your CPU).
