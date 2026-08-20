# IDA Live Matching Diff — API Map

Map of the current public interface: HTTP contract (client ↔ IDA server),
package modules, key function signatures, CLI, and data contracts.

## 1. Layout

```
ida_matcher/
  matcher/
    run_match.py        # CLI entry: ida-match (argparse -> match_core.main-like)
    watch.py            # CLI entry: ida-watch (argparse, polls .obj mtime/size)
    match.py            # compatibility shim -> match_core
    match_core.py       # client engine: fetch, compare, match_summary/match_focus
    coff_parser.py      # parser dispatch (auto/lief/pure) -> load_obj()
    coff_lief.py        # LIEF-backed .obj parser
    coff_pure.py        # pure-struct .obj parser
    config.py           # objdiff-style project config (units, mappings, watch)
    export_baseline.py  # offline baseline JSON export (IDA side)
    ida_logic.py        # [IDA-side] byte/fixup/switch/thunk extraction
    ida_server.py       # [IDA-side] HTTP server (threaded, hot-reload)
    engine/
      types.py          # data classes + penalties + reloc modes
      arch_x86.py       # Capstone scan/process (x86/x64)
      align.py          # patience-diff instruction alignment
      diff_code.py      # instruction diff + reloc equality
      data.py           # data/bss symbol & section diffs
      display.py        # hexdump + side-by-side console rendering
    tests/              # offline pytest suite (no IDA required)
```

## 2. HTTP Contract (client ⇄ IDA server, base `http://127.0.0.1:28000`)

| Endpoint | Query | Response | Used by |
|---|---|---|---|
| `GET /func` | `name=<mangled>` | `200` function record; `404 {"error":"not found"}`; `500 {"error":...}` | `fetch_from_ida()` |
| `GET /funcs` | `names=a,b,c` (comma) | `200 {"results": {name: record-or-null}}` | `fetch_many_from_ida()` |
| `GET /synthetic_obj` | `name=<mangled>` | `200` raw COFF bytes (`application/octet-stream`); `404 {"error":"not found"}` | Native diffing / `objdiff-core` binary stream |
| `GET /data` | `name=<mangled>` | `200` data record (same shape) | `fetch_data_from_ida()` |
| `GET /datas` | `names=a,b,c` | `200 {"results": {...}}` | `fetch_many_data_from_ida()` |
| `GET /health` | — | `200 {"status":"ok"}` | `server_alive()` |
| `GET /refresh` | — | `200 {"status":"refreshed"}`; rebuilds `FUNC_CACHE` | `refresh_ida_cache()` |
| `GET /all_names` | — | `200 {"names":[...]}` | `fetch_all_names_from_ida()` |
| `GET /baseline` | — | `200` full baseline dict | `get_baseline()` (offline export) |

**Function record** (`ida_logic.get_function_bytes` → client `match_core`):

```jsonc
{
  "ea": "0x401000",             // start VA (hex string)
  "size": 37,                   // bytes across all chunks
  "bytes": "558bec83ec40...",   // hex string
  "is_thunk": false,            // true -> client prints [THNK]
  "demangled_name": "Foo()",    // optional
  "switches": { "0x12": ["0x1a","0x2c"] },      // insn-offset -> intra-func targets
  "switch_ranges": [[0, 8]],                    // offsets to strip before byte-diff
  "fixups": { "5": "_printf" },                 // rel-byte-offset -> symbol label
  "fixup_widths": { "5": 4 },                   // per-fixup byte width
  "fixup_classes": { "5": "absolute" },         // absolute/relative/...
  "fixup_addends": { "5": 0 },                  // addends
  "fixup_sym_addrs": { "5": 0x402000 },         // target symbol VA
  "fixup_sym_sizes": { "5": 8 },                // target symbol size
  "fixup_sym_kinds": { "5": "unknown" },        // target symbol kind
  "arch": "x86"                                 // "x86" | "x64"
}
```

## 3. Client Data Contracts

### `coff_parser.load_obj(obj_path, parser="auto") -> Dict[str, Dict]`
Per-symbol record:

```python
{ mangled_name: {
    "bytes": bytearray,                # raw section bytes
    "section_bytes": bytearray,        # whole section (for data section diff)
    "offset": int,                     # start within section
    "size": int,
    "section_kind": str,               # "code" | "data" | "bss"
    "section_name": str,
    "flags": [str],                    # e.g. "CompilerGenerated"
    "demangled_name": str | None,
    "relocs": { rel_off: sym_name },
    "reloc_widths": { rel_off: width },   # 2 or 4
    "arch": "x86" | "x64",
}}
```

`resolve_parser(parser=None) -> "lief" | "pure"` — backend choice.

## 4. match_core.py — public functions

```python
IDA_SERVER_URL = "http://127.0.0.1:28000/func?name="

is_objdiff_py_enabled() -> bool                     # True when OBJDIFF_PY is set ("1", "true", "yes", "on")
get_diff_direction(mappings_config=None, override=None) -> "left_to_right" | "right_to_left"

compare_functions(obj_bytes, base_bytes_hex, obj_relocs, base_fixups,
                  obj_reloc_widths=None, base_switch_ranges=None,
                  reloc_mode="name_address", return_details=False,
                  left_accessor=None, right_accessor=None, arch="x86",
                  diff_direction=None)
    -> (float, int) | (float, int, (diff_score, max_score))   # match_pct, count (routes through objdiff_py when OBJDIFF_PY set)

fetch_from_ida(func_name) -> dict | None
fetch_synthetic_obj_from_ida(func_name) -> bytes | None    # GET /synthetic_obj (raw COFF .obj bytes)
fetch_many_from_ida(names) -> dict | None          # batch /funcs
fetch_data_from_ida(func_name) -> dict | None
fetch_many_data_from_ida(names) -> dict | None
fetch_all_names_from_ida() -> list[str]
server_alive() -> bool                              # GET /health
refresh_ida_cache() -> None                         # GET /refresh

matching_symbols(obj_funcs, all_base_records, mappings_config=None) -> list[(left, right|None)]
find_symbol(left_name, obj_funcs, all_base_records, right_used, fuzzy_literals) -> str | None
apply_symbol_mappings(obj_funcs, all_base_records, mappings_config, left_used, right_used, matches)
compare_for_pairing(left_name, right_name, obj_funcs, all_base_records) -> float

make_left_accessor(obj_funcs) -> callable          # (section_bytes, offset) by name
make_right_accessor(base_records, offline=False) -> callable

match_summary(obj_path, json_out=False, strict=False, parser="auto",
              reloc_mode="name_address", mappings_config=None, baseline=None,
              diff_direction=None) -> int
    # exit 0 ok; strict+below-100% -> 1. JSON schema in §5.
match_focus(obj_path, func_name, parser="auto", reloc_mode="name_address",
            mappings_config=None, baseline=None, diff_direction=None) -> None
    # prints hexdump + instruction diff; sys.exit(1) on errors (uses diff_objects when OBJDIFF_PY set)
```

**Environment Variables:**
- `OBJDIFF_PY`: When set to `"1"`, `"true"`, `"yes"`, `"on"`, activates the native Rust `objdiff_py` diff engine.
- `OBJDIFF_DIFF_DIRECTION`: `"left_to_right"` (default, left=compiled `.obj`, right=IDA) or `"right_to_left"` (objdiff upstream style).

Internal: `_compare_functions_objdiff_py(...)`, `_normalize_insn(...)`, `_insn_has_reloc(...)`, `_disassemble(...)`.

> Fidelity (OBJDIFF_SYNTH_FIDELITY_PLAN.md F3): `_compare_functions_objdiff_py` builds the base/
> right object from IDA bytes that carry image VAs at reloc sites — it patches those sites to the
> fixup addends before writing, and applies the REL32 `addend - 4` / width-2 `0` writer rule on
> **both** sides so the object writer never clobbers the real compiled `.obj` bytes on the left.

## 5. `match_summary(json_out=True)` JSON schema

```jsonc
{
  "obj": "compiled.obj",
  "connected": true,
  "summary": { "match": n, "match_100": n, "match_below": n,
               "thunk": n, "not_found": n, "data": n, "bss": n },
  "object": { "match_percent": 92.5, "size": 123, "unmatched_count": 0 },
  "sections": [ { "name": ".text", "match_percent": 95.0, "size": 100, "kind": "code" } ],
  "functions": [
    { "name": "...", "status": "match|thunk|not_found|data|bss",
      "match_pct": 100.0|null, "count": n, "diff_score": [a,b]|null,
      "section": ".text", "size": n, "demangled_name": "..."|null }
  ]
}
```

## 6. CLI

### `ida-match` (`run_match.py`)
```
usage: ida-match [-h] [--func FUNC] [--json] [--strict] [--parser {auto,lief,pure}]
                 [--no-color] [--reloc-mode {none,nameaddress,datavalue,all}] obj_file
```
`--reloc-mode` maps to `RELOC_MODE_*`: `none`/`name_address`/`data_value`/`all`.

### `ida-watch` (`watch.py`)
```
usage: ida-watch [-h] [--func FUNC] [--no-color] obj_file
```
Poll loop: `(mtime, size)` change → re-run `match_focus`/`match_summary`.
Catches `SystemExit` so a failed match does not kill the watcher.

## 7. engine/ — internal diff API (legacy; unused for code diff when OBJDIFF_PY set)

> **Note**: `engine/diff_code.py`, `engine/align.py`, `engine/arch_x86.py`, `engine/data.py`, and `engine/types.py` are the legacy Python diff engine. When `OBJDIFF_PY` is set, code diffs route through `objdiff_py.diff_objects()`. The Python modules are retained without deletion for fallback, regression testing, and data/BSS comparisons. `engine/display.py` is actively used in both modes for terminal console rendering.

```python
types.py:  DEFAULT_RELOC_WIDTH=4; RELOC_MODE_NONE/NAME_ADDRESS/DATA_VALUE/ALL
           PENALTY_IMM_DIFF=1, PENALTY_REG_DIFF=5, PENALTY_REPLACE=60, PENALTY_INSERT_DELETE=100
           classes: InsnRef, ParsedInsn, InstructionDiffRow, _InsnSource, _DiffContext

arch_x86.py:  scan_instructions(source) -> list[InstructionDiffRow]
              process_instruction(source, ins_ref) -> ParsedInsn
              resolve_branches(rows)
align.py:     patience_diff(a, b) -> list opcodes
              insn_align(left_ops, right_ops)
diff_code.py: diff_code(left_data, left_relocs, left_widths,
                        right_data, right_relocs, right_widths,
                        reloc_mode=..., left_data_accessor=..., right_data_accessor=...,
                        arch=...) -> dict(match_percent, diff_score, max_score, ...)
              reloc_eq(ctx, left_ins, right_ins) -> bool
              symbol_name_matches(a, b) -> bool          # strips _, __imp_, j_
              is_symbol_name_compiler_generated(name) -> bool
              _looks_anonymous(name) -> bool             # sub_/unk_/loc_ bare hex
              _strip_switch_ranges(data, fixups, ranges, reloc_widths=None)
data.py:      diff_data_symbol(left_data, right_data, left_relocs, right_relocs,
                              left_reloc_widths, right_reloc_widths, reloc_mode=...) -> float
              diff_bss_symbol(left_size, right_size) -> float
              diff_data_section(...) / diff_bss_section(...) / diff_generic_section(...)
display.py:   _configure_colors(enabled); _strip_ansi(text)
              print_hexdump_diff(obj_bytes, base_bytes, obj_relocs, base_fixups,
                                 obj_reloc_widths=None)
              diff_function(obj_bytes, base_bytes_hex, obj_relocs, base_fixups,
                            base_switches=None, obj_reloc_widths=None,
                            base_switch_ranges=None, reloc_mode=...,
                            left_accessor=None, right_accessor=None, func_name=None,
                            left_demangled_name=None, right_demangled_name=None,
                            arch="x86")
```

## 8. IDA-side (`ida_logic.py`, `ida_server.py`)

```python
ida_logic:  FUNC_CACHE: dict[str, int]          # name -> EA, rebuilt on miss/refresh
            build_cache() -> None
            get_function_bytes(name) -> dict | None    # §2 record
            get_data_bytes(name) -> dict | None
            get_demangled_name(name) -> str | None
            get_baseline() -> dict
            build_synthetic_obj(name) -> bytes | None  # real COFF .obj bytes for objdiff-core
            synthetic_obj_from_record(rec, name=None) -> bytes | None
            refresh() -> None
            is_compiler_generated(name) -> bool
            _is_thunk(func) -> bool              # single leading direct jmp only
            _get_func_relocs_via_operands(func, chunks)
            _get_func_relocs_via_fixups(func, chunks)
            _collect_func_bytes(func)

            # Note: build_synthetic_obj() constructs a valid COFF .obj file using ObjectBuilder,
            # reusing the extracted record fields: bytes, section_name, section_kind, arch,
            # fixups (targets), fixup_widths (2/4/8), fixup_classes (absolute/relative),
            # fixup_addends, and fixup_sym_kinds (code/data/unknown).
            #
            # Fidelity (OBJDIFF_SYNTH_FIDELITY_PLAN.md F2): reloc-site bytes are patched to the
            # record's fixup_addends (MSVC placeholder addend, not the image VA) before the
            # section is written; add_relocation receives `addend - 4` for "relative" (REL32)
            # and `0` for width-2 relocs so the object writer never clobbers the site.

ida_server: PORT = 28000
            start_server() -> None              # binds, builds cache, accept loop thread
            stop_server() -> None
            load_or_reload_logic() -> None      # mtime hot-reload of ida_logic.py
            handle_client(conn)                 # routes §2 endpoints (/func, /synthetic_obj, etc.)
            accept_loop()
```

## 9. config.py — project config (objdiff-style)

```python
Config:     diff_direction: "left_to_right" | "right_to_left"  # default: left_to_right
load_config(config_path) -> Config                # units, build commands, ignores, diff_direction
unit_for_source(config, source_path, project_dir) -> Unit | None
units_for_obj(config, obj_path, project_dir) -> list[Unit]
build_command_for(config, unit, project_dir) -> list[str]
build_command_for_source(config, source_path, project_dir) -> list[str]
watch_files(config, project_dir) -> list[str]     # sources to watch
symbol_mappings_for(config, unit) -> dict
load_config_mappings(config_path, obj_path) -> dict
```

## 10. Tests (offline, no IDA)

`tests/` — pytest, all headless:
- `test_coff_parser.py`, `test_coff_lief.py` — .obj parsing (synthetic fixtures in `conftest.py`)
- `test_match_core.py` — compare/reloc/symbol logic
- `test_objdiff_py.py` — PyO3 bridge tests (ObjectBuilder + diff_objects against fixtures)
- `test_data.py`, `test_x64.py`, `test_config.py`, `test_ida_server.py`

Run: `python -m pytest ida_matcher/matcher/tests -q`

## 11. Native extension (objdiff_py)

PyO3 native extension module compiled from `vendor/objdiff-py` wrapping `objdiff-core` and `object::write`.

### `ObjectBuilder`
```python
class ObjectBuilder:
    def __init__(self, arch: str) -> None: ...
    def add_section(self, name: str, segment: str, kind: int) -> int: ...
    def write_bytes(self, section_id: int, offset: int, data: bytes) -> None: ...
    def add_symbol(self, section_id: int, name: str, value: int, size: int, kind: int, flags: int) -> int: ...
    def add_relocation(self, section_id: int, offset: int, symbol_id: int, kind: int, size: int, addend: int) -> None: ...
    def finish(self) -> bytes: ...
```

- `arch`: `"x86"` / `"i386"` (COFF i386), `"x86_64"` / `"x64"` (COFF x86_64), `"arm"`, `"arm64"`, `"ppc"`, `"mips"`
- **Fidelity (OBJDIFF_SYNTH_FIDELITY_PLAN.md F1):** for all COFF formats the writer uses
  `Mangling::Coff`, so symbol names are written **verbatim** (no automatic `_` prefix) — matching
  real MSVC symbol-table names as IDA labels them (`?Foo@@YAXXZ`, `_printf`, `__ftol2`).
- **Fidelity (F2/F3):** callers must patch reloc-site section bytes to the MSVC placeholder
  addend and pass `addend - 4` to `add_relocation` for REL32 (`kind` 1/20), `0` for width-2
  relocs; the writer skips zero addends and errors on 16-bit addend writes.
- `kind` in `add_section`: `0` = Text, `1` = Data, `2` = ReadOnlyData, `3` = UninitializedData (BSS)
- `kind` in `add_symbol`: `0` = Unknown, `2` = Text, `3` = Data, `4` = Section, `5` = File, `6` = Label
- `flags` in `add_symbol`: bit `0` = Local (`1`), bit `1` = Weak (`2`), bit `2` = Undefined (`4`), bit `3` = Common (`8`), bit `4` = Absolute (`16`)
- `kind` in `add_relocation`: `0` / `6` = DIR32 / DIR16, `1` / `20` = REL32, `11` = SECREL
- `size` in `add_relocation`: byte width (`1`, `2`, `4`, `8`) or bit width (`8`, `16`, `32`, `64`)

### `diff_objects(left_obj: bytes, right_obj: bytes) -> dict`
Diffs two `.obj` byte streams using `objdiff_core::diff::diff_objs`. Returns a dict:
```jsonc
{
  "left": {
    "symbols": [
      {
        "target_symbol": int | null,
        "match_percent": float | null,
        "diff_score": [int, int] | null // [diff_score, max_score]
      }
    ],
    "sections": [
      {
        "match_percent": float | null
      }
    ]
  },
  "right": {
    "symbols": [...],
    "sections": [...]
  }
}
```

## 12. Build & Packaging Story (Phase 3)

- **Build Backend**: `maturin` (`[build-system] requires = ["maturin>=1.0,<2.0"]`, `build-backend = "maturin"`).
- **Mixed Layout**: Packages `ida_matcher` Python package and compiles `objdiff_py` PyO3 extension from `vendor/objdiff-py/Cargo.toml`.
- **Console Scripts**: Preserved entry points `ida-match` (`ida_matcher.matcher.run_match:main`) and `ida-watch` (`ida_matcher.matcher.watch:main`).
- **Distribution**: ABI3 (`abi3-py39`) prebuilt wheels for Windows, Linux, and macOS (`maturin build --release`). End users install wheels without needing a Rust compiler.
- **CI / Automation**: `.github/workflows/build_wheels.yml` runs pytest matrix on Python 3.9–3.13 and generates multi-platform wheels via `PyO3/maturin-action`.