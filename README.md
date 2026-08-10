# IDA Live Matching Diff

A live binary matching and diffing tool. It compares **MSVC-compiled `.obj` files** against the corresponding functions in a **live IDA Pro database**, so you can verify at build time that your recompiled code still matches the binary you are reversing — or see exactly where it does not.

```
               local machine                                IDA machine
  ┌───────────────────────────────┐           ┌──────────────────────────────┐
  │ ida-match / ida-watch          │   HTTP    │ ida_server.py (in IDA)       │
  │   CLI client (pure Python)     │ ────────► │   threads byte/fixup/switch  │
  │   parses your .obj            │ :28000    │   data for every function    │
  └───────────────────────────────┘           └──────────────────────────────┘
```

## Features

- **Live matching** — query the open IDA database in real time via a small HTTP server plugin; no baseline export step.
- **Side-by-side diff** — per-function view with a Capstone instruction diff and a 16-byte aligned hex dump.
- **Relocation-aware comparison** — relocations are parsed straight from the `.obj` and matched against IDA fixups, so different virtual addresses (or changed call targets like `printf` → `puts`) do not produce false matches.
- **No external tooling on the client** — the `.obj` parser is pure Python (`struct`); no `dumpbin.exe`, no MSVC toolchain on the path.
- **Headless testable** — all matching logic is a pure-Python package; the included pytest suite runs with no IDA and no server.

## Requirements

- Python 3.9+
- `capstone` (`pip install capstone`) — only needed for the side-by-side instruction diff, not the summary
- IDA Pro 7.x+ with Python support (for the server plugin only)

## Installation

```bash
pip install -e .
```

This installs two console commands: `ida-match` (one-shot) and `ida-watch` (re-run on every rebuild). To run without installing, use the module entry points instead:

```bash
python -m ida_matcher.matcher.run_match <file.obj>
python -m ida_matcher.matcher.watch <file.obj>
```

## 1. Start the IDA-side server

1. Open your target binary in IDA Pro.
2. Run the server plugin from the IDA Python console:

   ```python
   exec(open(r"<path-to-repo>\ida_matcher\matcher\ida_server.py").read())
   ```

   (Otherwise: IDA *File → Script file…* and pick `ida_matcher/matcher/ida_server.py`.)

3. You should see `IDA Live Matcher Server running on port 28000 (Hot-Reload Enabled)...`

The server listens on `http://127.0.0.1:28000` and:

- serves byte/fixup/switch data for every **named** function in the database,
- **hot-reloads** `ida_logic.py` whenever it changes on disk (no IDA restart needed),
- rebuilds its name cache when the client asks (`GET /refresh`) and on a cache miss.

If any reverse-engineering makes the client talk to the wrong name, remember the lookup is by the **exact mangled name** IDA stores.

## 2. Match once (summary)

```bash
ida-match path/to/compiled.obj
```

Prints one line per function:

```
==================================================
MATCHING RESULTS
==================================================
[100.00%] ?Foo@@YAXXZ (23 bytes)
[ 92.86%] ?Bar@@YAXH@Z (56 bytes)
[THNK   ]?Baz@@YAXXZ (IDA thunk/forwarder - skipped)
[????   ]   ?Renamed@@YAXXZ (Not found in Live IDA Database)
```

- 100% green, ≥ 80% yellow, < 80% red.
- Exact mangle-name match required; functions renamed in IDA report `[????]`.
- If the IDA server is not running, the client says so up front instead of failing per function.

## 3. Diff one function

```bash
ida-match path/to/compiled.obj --func "?Foo@@YAXXZ"
```

Shows the hex-dump comparison then a side-by-side instruction diff:

```
Base (IDA Database)                      | Local Compiled (.obj)
------------------------------------------+------------------------------------
mov      eax, ds:<_printf>                | mov      eax, ds:<_printf>
[RELOC≠ _puts != _printf] call  ...        | ...
```

Relocated bytes are shown in yellow with the target symbol; a reloc whose symbol changed is flagged `[RELOC≠ …]` instead of counting as a match.

## 4. Machine-readable summary

```bash
ida-match path/to/compiled.obj --json
```

```json
{
  "obj": "compiled.obj",
  "connected": true,
  "functions": [
    {"name": "?Foo@@YAXXZ", "status": "match", "match_pct": 100.0, "count": 23},
    {"name": "?Baz@@YAXXZ", "status": "thunk",  "match_pct": null,  "count": null},
    {"name": "?Renamed@@YAXXZ", "status": "not_found", "match_pct": null, "count": null}
  ]
}
```

## 5. Watch mode

Re-run the match automatically whenever the `.obj` file is rebuilt:

```bash
ida-watch path/to/compiled.obj                       # summary on each change
ida-watch path/to/compiled.obj --func "?Foo@@YAXXZ"  # diff one function
```

The watcher keeps running even if a match fails (e.g. server momentarily down). Press `Ctrl+C` to stop.

## 6. Common options

| Flag | Applies to | Meaning |
|---|---|---|
| `--func <mangled>` | `ida-match`, `ida-watch` | Diff a single function instead of the summary |
| `--json` | `ida-match` | Machine-readable JSON summary (summary mode only) |
| `--no-color` | both | Disable ANSI colors (also honours the `NO_COLOR` env var) |

## How it works

1. **COFF parsing (client)** — `coff_parser.py` parses the compiler header, section headers, symbols, and relocations of the `.obj` directly (pure `struct`). For every function-like symbol it records the raw bytes, the relocation offsets (with their 2- or 4-byte widths), and the reloc target symbol names.
2. **HTTP lookup (client → IDA)** — the client asks the server for each function it found: `GET /funcs?names=a,b,c` (batch) or `GET /func?name=…` (single). The server answers with bytes, IDA fixup offsets, and jump-table info.
3. **IDA-side extraction** — `ida_logic.py` walks each function chunk with `ida_ua.decode_insn` and the IDA fixup table to locate absolute-address bytes, and pulls switch/jump-table targets, so both sides describe the code the same way.
4. **Comparison** — bytes that belong to a relocation/fixup on both sides are compared symbolically (normalized names, `__imp_`/`j_`/`_` prefixes stripped); if both sides know the target it is treated as a match only when the symbols agree. Concrete bytes are compared directly, and any length difference lowers the score.
5. **Diff rendering** — Capstone disassembles both byte streams; `difflib` aligns them and the mismatched instructions are highlighted inline.

## Project layout

```
ida_matcher/
  matcher/
    ida_server.py      # IDA plugin: HTTP server + hot reload
    ida_logic.py       # IDA-side extraction (bytes/fixups/switches/thunks)
    coff_parser.py     # pure-Python COFF .obj parser (client)
    match_core.py      # comparison engine + CLI entry
    run_match.py       # ida-match one-shot entry point
    watch.py           # ida-watch polling entry point
    match.py           # legacy shim -> match_core
    export_baseline.py # optional offline IDA export (not used by live flow)
    tests/             # offline pytest suite (no IDA needed)
```

More detail: `CURRENT_STATE.md` (architecture + change log), `IMPLEMENTATION_PLAN.md` (API map + fix list).

## Testing

```bash
python -m pytest ida_matcher/matcher/tests -q
```

Runs entirely offline (no IDA, no server) and covers the COFF parser, the comparison logic, reloc normalization, and the summary output path.