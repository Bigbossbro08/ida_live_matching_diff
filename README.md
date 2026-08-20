# IDA Live Matching Diff

A live binary matching and diffing tool. It compares **MSVC-compiled `.obj` files** against corresponding functions in a **live IDA Pro database**, powered by the high-fidelity native **`objdiff`** matching engine.

```
               Local Machine                               IDA Pro
  ┌──────────────────────────────────────┐        ┌──────────────────────────────┐
  │ ida-match / ida-watch / match_unit   │  HTTP  │ Live Matcher Plugin          │
  │   - objdiff-py engine (Rust / PyO3)  │ ─────► │   ida_server.py (:28000)     │
  │   - live synthetic COFF generation   │        │   exports bytes & fixups     │
  └──────────────────────────────────────┘        └──────────────────────────────┘
```

---

## Quick Start (3 Steps)

### Step 1: Install `ida_matcher`

**For Development / Source Install:**
```bash
# Clone with submodules (includes vendor/objdiff)
git clone --recurse-submodules https://github.com/Bigbossbro08/ida_live_matching_diff.git
cd ida_live_matching_diff

# Build and install editable package via Maturin
pip install -e . --no-build-isolation
```

**For Distribution / Packaging:**
Run `build_wheels.bat` (Windows) or `maturin build --release` to generate `.whl` packages in `dist/`.

---

### Step 2: Enable the Server in IDA Pro

Choose one of the two options:

* **Option A (Automatic Plugin - Recommended):**  
  Copy [`ida_live_matcher_plugin.py`](ida_live_matcher_plugin.py) into your IDA Pro `plugins/` directory (e.g. `C:\Program Files\IDA Professional 9.1\plugins\`). It starts automatically when opening an IDB.
* **Option B (Manual):**  
  In IDA Pro, open *File → Script file…* and select `ida_matcher/matcher/ida_server.py`, or run in the IDA Python console:
  ```python
  exec(open(r"C:\path\to\ida_live_matching_diff\ida_matcher\matcher\ida_server.py").read())
  ```

*You should see: `IDA Live Matcher Server running on port 28000 (Threaded, Hot-Reload Enabled)...`*

---

### Step 3: Run the Matcher

#### Match a single object file:
```bash
ida-match path/to/compiled.obj
```

#### Match a specific function:
```bash
ida-match path/to/compiled.obj --func "?Foo@@YAXXZ"
```

#### Watch mode (re-matches automatically on compilation):
```bash
ida-watch path/to/compiled.obj
ida-watch path/to/compiled.obj --func "?Foo@@YAXXZ"
```

---

## Features

- **Native Objdiff Parity** — Powered by `objdiff-py` (Rust/PyO3 bindings for `objdiff-core`), providing byte-for-byte fidelity and decomp.me scoring parity.
- **Live IDA Matching** — Query open IDA databases over a local HTTP server with zero manual export steps.
- **COFF Synthetic Objects** — Automatically synthesizes valid COFF objects from IDA database records, including exact relative/absolute relocation addend adjustments.
- **Relocation-Aware Diffing** — Distinguishes between concrete instruction differences and expected virtual address remappings.
- **Multi-Architecture Support** — Supports x86 (MSVC 6.0/7.0/etc.) and x64 object matching.
- **Robust Parsing** — LIEF backed `.obj` parser with a zero-dependency pure-Python fallback.

---

## CLI Options

| Flag | Applies to | Description |
|---|---|---|
| `--func <name>` | `ida-match`, `ida-watch` | Focus and diff a single function by mangled symbol name |
| `--json` | `ida-match` | Emit machine-readable JSON summary for CI integration |
| `--strict` | `ida-match` | Exit with status code 1 if any function is < 100% matched |
| `--parser <auto\|lief\|pure>` | both | COFF parser backend (`auto` selects LIEF if available) |
| `--reloc-mode <none\|nameaddress\|datavalue\|all>` | both | Control relocation comparison strictness |
| `--no-color` | both | Disable ANSI color codes |

---

## Project Structure

```
ida_live_matching_diff/
├── ida_matcher/
│   └── matcher/
│       ├── ida_server.py       # IDA plugin server (HTTP :28000, hot-reloading)
│       ├── ida_logic.py        # IDA extraction logic (bytes, fixups, jump tables)
│       ├── match_core.py       # Core matching engine & objdiff-py bridge
│       ├── run_match.py        # ida-match CLI entry point
│       ├── watch.py            # ida-watch CLI entry point
│       ├── coff_parser.py      # COFF parser facade (LIEF / pure)
│       ├── coff_lief.py        # LIEF-backed parser
│       ├── coff_pure.py        # Pure-Python struct parser
│       └── tests/              # Offline pytest suite (179 tests)
├── vendor/
│   ├── objdiff/                # Upstream objdiff submodule (objdiff-core)
│   └── objdiff-py/             # Rust PyO3 bindings for objdiff-core & ObjectBuilder
├── ida_live_matcher_plugin.py  # Drop-in IDA Pro plugin entrypoint
├── build_wheels.bat            # Windows release build script
└── pyproject.toml              # Maturin package definition
```

---

## Running Tests

Run the full offline test suite (no IDA instance required):

```bash
python -m pytest ida_matcher/matcher/tests -q
```