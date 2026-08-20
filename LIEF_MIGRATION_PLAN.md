# LIEF Migration Plan — COFF Parsing

## 1. Goal

Replace the hand-rolled `coff_parser.py` (pure-`struct`, x86-32 only) with
**LIEF** as the primary `.obj` parser. LIEF gives us library-grade COFF
parsing for free — exact function/data bounds via auxiliary symbols, per-reloc
types across all architectures, COMDAT/weak-external metadata, `/bigobj`
support, and demangled names — which is exactly what "foolproof" matching
needs. The legacy pure-Python parser is kept behind a `--parser` switch as a
zero-dependency fallback.

## 2. Why LIEF (verified against the current API docs)

| Capability | Today (`coff_parser.py`) | LIEF |
|---|---|---|
| Function bounds | sort-symbols + measure gap (fragile) | `AuxiliaryFunctionDefinition.total_size` — exact size |
| Data/BSS symbols | not parsed at all | `Binary.symbols` + section `characteristics` |
| COMDAT sections | not parsed | `Section.comdat_info` (`symbol` + `selection`) |
| Weak externals | not parsed | `Symbol.is_weak_external`, `AuxiliaryWeakExternal` |
| Reloc widths | hand-rolled `IMAGE_REL_I386_*` table | `Relocation.type` enum, arch-prefixed (`I386_`, `AMD64_`, `ARM_`, `ARM64_`, `MIPS_`) |
| Multi-arch | I386 only | `Header.machine` (`PE.MACHINE_TYPES`): I386, AMD64, ARM, ARM64, PPC, MIPS… |
| `/bigobj` | unsupported | `Header.kind == BIGOBJ` |
| Long section names | partial | `Section.coff_string` / `get_section()` transparent resolution |
| Demangled names | none | `Symbol.demangled_name` |
| Malformed-file handling | manual bounds checking | library-level validation |

### 2.1 Verified LIEF API surface (COFF)

```python
import lief

coff = lief.COFF.parse(path)          # or lief.parse(); None if not COFF

# headers
coff.header.machine                    # lief.PE.Header.MACHINE_TYPES
coff.header.kind                       # REGULAR | BIGOBJ
coff.header.nb_sections / nb_symbols / pointerto_symbol_table

# sections
sec = coff.get_section(".text")        # name resolved incl. string-table names
sec.characteristics                    # int  (CNT_CODE 0x20, CNT_INITIALIZED_DATA 0x40, CNT_UNINITIALIZED_DATA 0x80)
sec.characteristics_lists              # list[lief.PE.Section.CHARACTERISTICS]
sec.has_characteristic(lief.PE.Section.CHARACTERISTICS.CNT_CODE)
sec.sizeof_raw_data / pointerto_raw_data / virtual_size
sec.relocations                        # iterator
sec.symbols                            # iterator
sec.comdat_info                        # ComdatInfo | None: .symbol, .kind (COMDAT_SELECTION)

# symbols
for sym in coff.symbols:
    sym.name, sym.demangled_name       # demangled_name = free MSVC demangler
    sym.value                          # section-relative offset (defined) / 0 (external)
    sym.section / sym.section_idx      # 0 = external, -1 = absolute, -2 = debug
    sym.storage_class                  # EXTERNAL, STATIC, WEAK_EXTERNAL, FUNCTION...
    sym.is_function / is_external / is_weak_external / is_undefined
    sym.type / base_type / complex_type
    sym.auxiliary_symbols              # iterator over AuxiliarySymbol

# auxiliary symbols (the foolproof part)
for aux in sym.auxiliary_symbols:
    if aux.type == lief.COFF.AuxiliarySymbol.TYPE.FUNC_DEF:
        aux.total_size                 # EXACT function code size
    elif aux.type == lief.COFF.AuxiliarySymbol.TYPE.WEAK_EXTERNAL:
        aux.sym_idx, aux.characteristics
    elif aux.type == lief.COFF.AuxiliarySymbol.TYPE.SEC_DEF:
        aux.length, aux.selection, aux.checksum

# relocations
for reloc in coff.relocations:         # or sec.relocations
    reloc.type                         # arch-prefixed enum, e.g. TYPE.I386_DIR32
    reloc.symbol / reloc.symbol_idx    # target symbol
    reloc.section                      # section it applies to
```

> **Note on relocation values:** LIEF encodes relocation types with the machine
> prefix (e.g. `I386_DIR32 == 131078`, not the raw COFF `0x0006`). Width lookup
> must key on the `TYPE` enum member, not a raw int table.

## 3. Architecture

### 3.1 Parser interface (unchanged consumer contract)

`match_core` only consumes the dict returned by `load_obj`, so we keep the
same contract and swap the implementation behind it:

```python
# ida_matcher/matcher/coff_parser.py  (rewritten as a thin facade)
def load_obj(path) -> dict:
    return load_obj_lief(path) if _use_lief(path) else load_obj_pure(path)
```

New record shape (superset of today's — old fields kept for compatibility):

```python
{
  mangled_name: {
    "bytes":        bytearray,     # section-relative function bytes
    "offset":       int,           # offset of symbol within section
    "relocs":       {rel_off: sym_name},
    "reloc_widths": {rel_off: 2 | 4 | 8},
    "is_thunk":     bool,          # NEW: obj-side thunk parity
    "is_weak":      bool,          # NEW: weak external
    "section_kind": "code" | "data" | "bss",   # NEW: for data diffing
  }
}
```

### 3.2 Module layout after migration

```
ida_matcher/matcher/
  coff_parser.py        # facade: load_obj() dispatches to lief or pure
  coff_lief.py          # NEW: LIEF-backed extraction (sections/symbols/relocs)
  coff_pure.py          # moved legacy parser (renamed from coff_parser.py body)
  match_core.py         # unchanged consumer; gains data/thunk/weak handling
  tests/
    conftest.py         # keep synthetic .obj builder (validates the pure path)
    test_coff_lief.py   # NEW: LIEF-path tests (see §6)
```

`pyproject.toml`:
```toml
dependencies = ["capstone", "lief"]
```
`lief` stays optional at runtime (import guarded) so `--parser pure` still
runs in a bare environment; the CLI hints to `pip install lief` when missing.

## 4. API mapping (old code → LIEF)

| Current `coff_parser.py` | LIEF replacement |
|---|---|
| `IMAGE_FILE_HEADER` unpack | `coff.header` (`machine`, `nb_sections`, …) |
| `IMAGE_SECTION_HEADER` loop | `coff.sections` / `coff.get_section(name)` |
| `IMAGE_SYMBOL` parse + string table | `coff.symbols`; `sym.name`/`sym.coff_name` |
| sort-code-symbols + gap = bounds | `sym.auxiliary_symbols` → `FUNC_DEF.total_size`; fallback to gap heuristic when aux missing |
| `IMAGE_RELOCATION` + `_reloc_width()` table | `reloc.type` enum → width map keyed on `TYPE` (I386/AMD64/ARM/ARM64) |
| `s["type"] & 0x00F0` function filter | `sym.is_function` or `complex_type == FUNCTION` |
| `__imp_` / `$L` filtering | `sym.name` checks kept; `sym.is_undefined` for externals |
| section flags `0x20` code check | `sec.has_characteristic(CNT_CODE)` |
| — | `sec.has_characteristic(CNT_INITIALIZED_DATA / CNT_UNINITIALIZED_DATA)` → data/BSS extraction |
| — | `sym.is_weak_external` → `[WEAK]` flag |
| — | `sym.demangled_name` → display name (Phase 4) |

## 5. Migration steps

### Step 1 — Drop-in parity (green on the existing 34 tests)
- Add `coff_lief.py` producing **exactly** the current record shape.
- Write `coff_parser.py` facade with `--parser`/`LIEF=0/1` env or
  `load_obj(path, parser="auto")`; `auto` = LIEF when installed & parseable,
  else pure.
- Route the synthetic-obj tests through **both** paths. Since the synthetic
  fixture lacks aux symbols, LIEF must reproduce the gap-heuristic result
  (validation: LIEF's symbol `value`s match the pure parser's offsets).
- Add `pyproject.toml` dependency + runtime-optional import guard.

### Step 2 — Exact bounds via aux symbols (foolproofing)
- `coff_lief.py`: prefer `FUNC_DEF.total_size` for a defined function symbol;
  fall back to gap-heuristic only when aux records are absent.
- Add `Section.comdat_info` handling: a COMDAT section is its own function/
  data unit — bounds come from `comdat_info.symbol` + section `sizeof_raw_data`,
  and `COMDAT_SELECTION` drives weak/alias classification.
- Clamp every byte slice to `len(sec.content)` — truncated objects can never
  over-read or silently mask bytes.

### Step 3 — Data & BSS extraction
- `coff_lief.py`: classify non-code sections by characteristics
  (`CNT_INITIALIZED_DATA` → `data`, `CNT_UNINITIALIZED_DATA` → `bss`,
  `CNT_CODE` → `code`).
- Emit `data`/`bss` records with `section_kind`; `.bss` has empty `bytes`
  (client compares against IDA's zeroed page).
- Keep relocs + widths for data pointers (they reloc too).

### Step 4 — Multi-arch width tables
- Map `Relocation.TYPE` → width for I386 (2/4), AMD64 (4/8, incl.
  `REL32_1..5`), ARM (`MOV32A/T`, `REL32`), ARM64 (`ADDR32/64`,
  `PAGEBASE_REL21`, …). Machine comes from `header.machine`, so the same
  parser now feeds x64 diffing (Phase 5 of the parity plan).

### Step 5 — Weak/flag surface (Phase 4 prep)
- Set `is_weak`, `section_kind`, `is_thunk` on records; `demangled_name`
  collected for display. Keep the record dict backward-compatible.

## 6. Test & verification plan

### 6.1 Automated (headless pytest)
- **Parity**: run the existing `test_coff_parser.py` cases through both
  `load_obj_lief` and `load_obj_pure` and assert identical outputs.
- **Bounds**: synthetic `.obj` with a `FUNC_DEF` aux record → assert exact
  size wins over gap heuristic.
- **Data/BSS**: synthetic multi-section `.obj` (`.text`/`.data`/`.bss`) →
  assert `section_kind` classification and reloc extraction in data.
- **Widths**: per-`TYPE` unit tests for I386/AMD64/ARM/ARM64 width maps.
- **Robustness**: truncated file → `load_obj` returns `{}` (never raises);
  non-COFF input → falls back to pure path / `{}`.
- **Weak/COMDAT**: fixture with a `WEAK_EXTERNAL` aux + COMDAT section →
  `is_weak` set, bounds from `comdat_info`.

### 6.2 Real-object validation (must do before merging)
LIEF's COFF parser has had edge-case reports (e.g. `lief/issues/1091`,
"Unknown format" on some objects). **Gate the merge on parsing the actual
MSVC `.obj` files** the tool is used against (e.g. a `rogan2` build):
- `dumpbin /headers` vs. LIEF section/symbol counts agree.
- Function list and byte offsets match the old parser on a real x86-32 build.
- Reloc offsets/widths match.
- If any real `.obj` fails to parse, keep `--parser pure` as the escape hatch
  and file the repro upstream.

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| LIEF fails to parse some MSVC objects | `auto` parser falls back to `pure`; repro filed upstream (§6.2) |
| Native wheel (no pure-Python install) | dependency optional; `--parser pure` works with no LIEF |
| API churn (LIEF has had 0.x → 0.15/1.x rewrites) | pin `lief>=X` in `pyproject.toml`; isolate all API use in `coff_lief.py` |
| Symbol `value` semantics differ from raw COFF offsets | cross-check `value` vs `section.virtual_address` semantics in §6.2 real-object gate |
| Big `.lib`/archive support not needed (tool takes `.obj`) | out of scope; `lief.ARCHIVE` can be added later |

## 8. Open decisions

1. **Parser selection default**: `auto` (LIEF-if-available) vs explicit
   `--parser lief|pure` flag vs env var `IDA_MATCHER_PARSER`? (Recommend:
   `auto` + `--parser` override.) (Answered: Go with recommended)
2. **Pin strategy**: pin exact `lief==<version>` or floor `lief>=<version>`?
   (Recommend floor, since CI should pick up fixes.)  (Answered: Go with recommended)
3. **Keep the pure parser in-repo** permanently, or remove once LIEF has been
   validated against real builds? (Recommend keep until multi-arch lands.)  (Answered: keep it still as a fallback but always lief being preferrable)
4. **Dependency weight**: accept the ~native-wheel install cost as mandatory,
   or keep it optional and print a hint (recommend optional)?  (Answered: Go with recommended)