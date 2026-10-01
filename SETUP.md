# Environment Setup — What This Machine Runs and Why

Project: real-machine benchmarking of classical vs post-quantum cryptography
(gap analysis of Narayanan et al. 2026, "PQShield-IoT", DOI 10.1007/s40998-025-01002-1).

## The environment actually in use (verified working, 2026-07-16)

| Component      | Version / choice | Notes |
|----------------|------------------|-------|
| OS             | Windows 11 Home 10.0.26200 | laptop, no admin toolchain installs needed |
| Python         | 3.14.3 (CPython, 64-bit) | |
| `pqcrypto`     | 0.4.0 | **prebuilt `cp314-win_amd64` wheel — no compiler needed.** Python bindings over **PQClean** reference C implementations |
| `cryptography` | 49.0.0 | OpenSSL-backed classical crypto (RSA, ECDH/ECDSA, X25519/Ed25519) |
| `matplotlib`   | latest wheel | figures |
| `pandas`       | latest wheel | CSV handling in plots |

Install command (the only one needed):

```powershell
pip install pqcrypto cryptography matplotlib pandas
```

## Why not `liboqs-python` (the originally planned library)?

`pip install liboqs-python` succeeds (it's a pure-Python wrapper), but **on first
`import oqs` it downloads and compiles the liboqs C library from source**. That
requires CMake + a C compiler (MSVC or MinGW). This machine has neither
(verified: no `cmake`, no `cl`, no `gcc`, no VS Build Tools, no WSL, no conda),
and installing Visual Studio Build Tools is a multi-GB, admin-rights download.

`pqcrypto` sidesteps the whole problem: it ships **prebuilt Windows wheels**
(including Python 3.14) and binds the same family of implementations —
**PQClean** is the upstream codebase that liboqs itself imports for these
algorithms, and the codebase that the pqm4 Cortex-M4 benchmarking project
ports to embedded targets. For this project that is arguably a *better* fit:

* PQClean "clean" implementations are **portable C without AVX2 assembly** —
  closer to what constrained IoT firmware actually runs, and directly
  comparable to the public pqm4 dataset used in the report's extrapolation.
* Zero build friction → the demo runs on any Windows/Linux/macOS machine with
  `pip`.

**Honest caveat for the report:** liboqs/OpenSSL builds with AVX2 optimizations
would be several times faster in absolute terms for the lattice schemes. Our
desktop numbers characterize the *portable-C* implementations; conclusions are
drawn from relative comparisons, and this is stated in the report.

Algorithms exposed by `pqcrypto` 0.4.0 (all used or available):
ML-KEM-512/768/1024, HQC-128/192/256, Classic McEliece (6 sizes),
ML-DSA-44/65/87, Falcon-512/1024 (+padded), SPHINCS+-SHA2/SHAKE (12 variants).

## Fallback routes (documented, NOT needed on this machine)

If you ever need liboqs itself (e.g., to cross-check numbers against an
AVX2-optimized build), pick ONE of:

1. **WSL (recommended, simplest full toolchain)**
   ```powershell
   wsl --install          # reboot when prompted
   ```
   then inside Ubuntu:
   ```bash
   sudo apt update && sudo apt install -y build-essential cmake git python3-pip
   pip install liboqs-python   # builds liboqs automatically (~5 min)
   ```

2. **Native Windows toolchain**
   * Install "Visual Studio Build Tools 2022" → workload *Desktop development
     with C++* (includes CMake). ~7 GB, needs admin.
   * Then `pip install liboqs-python` and let the first `import oqs` build.

3. **Conda** — `conda install -c conda-forge liboqs` provides a prebuilt C
   library; pair with the `liboqs-python` wrapper (`OQS_INSTALL_PATH` env var
   pointed at the conda env).

## Verification snippet (run after any install)

```powershell
python -c "from pqcrypto.kem import ml_kem_512 as k; pk,sk = k.generate_keypair(); ct,ss = k.encrypt(pk); assert k.decrypt(sk,ct)==ss; print('ML-KEM-512 roundtrip OK')"
```

## Reproducing the results

```powershell
cd "e:\Research Project\CNS\code"
python benchmark_pqc.py           # ~1.5-4 min -> ../results/*.csv + system_info.txt
python plot_results.py            # -> ../results/fig*.png
```

> **Before a canonical run, close your browser and other heavy apps.** This is
> not boilerplate — it was measured. With ~31% background CPU load (a browser
> with several processes plus VS Code), *every* scheme in the suite came out
> **~2.5× slower**, classical and post-quantum alike, because on a laptop the
> busy cores eat the shared power/thermal budget and the benchmark's pinned
> core clocks down. Sizes and byte counts are unaffected (they are
> deterministic); only timings move. After any re-run, execute
> `python verify_report_numbers.py` — it re-checks every number quoted in the
> report against the CSVs and tells you if they have drifted.

Benchmarking hygiene (matters on a laptop):
* Plug in AC power and set the Windows power mode to "Best performance"
  before a canonical run — `system_info.txt` records the active power plan
  and AC status so a reviewer can check this.
* Close heavy background apps; do not run other tasks during the benchmark.
* The script pins itself to one CPU core at high priority (best effort,
  recorded in `system_info.txt`), uses time-based warm-up, and batches
  sub-millisecond operations so samples reflect steady state — but expect
  residual run-to-run variance of tens of percent on a consumer laptop
  (turbo boost, thermal throttling). Median + min–max spread are reported,
  and calibration rows in `timings.csv` quantify the fixed per-call
  overhead (Python dispatch + OS RNG syscall) baked into sub-ms rows.
