# Project Layout & Architecture

This document describes the internal structure and architecture of `ida_live_matching_diff`.

## Directory Overview

```
ida_live_matching_diff/
├── ida_matcher/
│   └── matcher/
│       ├── ida_server.py       # IDA Pro HTTP server (:28000, multi-threaded, hot-reloading)
│       ├── ida_logic.py        # IDA extraction logic (bytes, fixups, jump tables)
│       ├── match_core.py       # Core matching engine & objdiff-py bridge
│       ├── run_match.py        # `ida-match` CLI entry point
│       ├── watch.py            # `ida-watch` CLI entry point
│       ├── config.py           # Project config & symbol/reloc mapping parser (ida_watch.json)
│       ├── coff_parser.py      # COFF parser facade (LIEF / pure-Python dispatch)
│       ├── coff_lief.py        # LIEF-backed COFF parser
│       ├── coff_pure.py        # Pure-Python struct COFF parser fallback
│       ├── engine/             # Comparison, alignment, and display helper utilities
│       │   ├── align.py        # Sequence alignment & LCS diff logic
│       │   ├── arch_x86.py     # x86 disassembler & instruction scoring
│       │   ├── data.py         # Data section matching
│       │   ├── diff_code.py    # Code diff rendering
│       │   ├── display.py      # Terminal formatting & ANSI color handling
│       │   └── types.py        # Common dataclasses and enum definitions
│       ├── export_baseline.py  # Offline baseline exporter (GET /baseline -> JSON)
│       └── tests/              # Full offline pytest suite (179 tests)
│           ├── fixtures/       # Synthetic and real MSVC COFF object fixtures
│           ├── conftest.py     # Pytest configuration & test helpers
│           ├── test_coff_lief.py
│           ├── test_coff_parser.py
│           ├── test_config.py
│           ├── test_data.py
│           ├── test_ida_server.py
│           ├── test_match_core.py
│           ├── test_objdiff_py.py
│           └── test_x64.py
├── vendor/
│   ├── objdiff/                # Upstream objdiff git submodule (objdiff-core crate)
│   └── objdiff-py/             # PyO3 Rust extension bridging objdiff-core and ObjectBuilder
├── ida_live_matcher_plugin.py  # Drop-in IDA Pro plugin entry point
├── build_wheels.bat            # Windows release wheel build script
└── pyproject.toml              # Maturin package & build specification
```

---

## Architectural Workflow

```
               Local Machine                               IDA Pro
  ┌──────────────────────────────────────┐        ┌──────────────────────────────┐
  │ ida-match / ida-watch / match_unit   │  HTTP  │ Live Matcher Plugin          │
  │   - objdiff-py engine (Rust / PyO3)  │ ─────► │   ida_server.py (:28000)     │
  │   - live synthetic COFF generation   │        │   exports bytes & fixups     │
  └──────────────────────────────────────┘        └──────────────────────────────┘
```

1. **Client Request**: `ida-match` or `ida-watch` reads the local compiled `.obj` file via `coff_parser.py` (LIEF / pure-struct) and extracts the target function's bytes and relocations.
2. **IDA Server Query**: The client queries the live IDA server via HTTP (`GET /func?name=...`).
3. **Database Extraction**: `ida_server.py` and `ida_logic.py` run inside IDA Pro to extract the ground-truth function bytes, jump tables, and relocation fixup records.
4. **Synthetic COFF Generation**: `ida_logic.synthetic_obj_from_record` uses `objdiff-py`'s `ObjectBuilder` to construct an in-memory COFF `.obj` representing the IDA ground truth with exact relocation addend math (e.g. `REL32` adjust `-4`).
5. **Objdiff Engine Comparison**: Both the synthetic IDA object and the locally compiled object are passed into the native `diff_objects` Rust engine, producing byte-for-byte fidelity and exact decomp.me scoring.
