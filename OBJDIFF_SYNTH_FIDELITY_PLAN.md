# Plan: MSVC COFF Fidelity for the Synthetic Object (`objdiff-core` round-trip)

> Status: **plan — root causes verified, fix recipe proven in temp scripts, no code in the repo changed yet**
> Parent plan: `OBJDIFF_RUST_MIGRATION.md` (Phases 0–3 done). This doc adds the *fidelity* phase
> that makes the synthetic `.obj` byte-equivalent to a real MSVC `.obj` for `objdiff-core`.

## 1. Context and the problem

The Rust-migration path (`OBJDIFF_RUST_MIGRATION.md`) feeds `objdiff-core` a synthetic COFF
`.obj` built at runtime from the live IDA database via `object::write` (through the `objdiff_py`
PyO3 bridge, `ObjectBuilder`). The idea is correct — a cross-check against the **official
`objdiff-cli`** proved it — but the synthetic object had two fidelity bugs that capped matches
at ~93% and could even make symbol pairing fail.

### 1.1 Cross-check performed (official tooling, no repo code involved)

Reference function: `COnscreenTimerEntry::Process` (167 bytes, 12 relocs, `max_score 5600`).

| Comparison | Tool | Result |
|---|---|---|
| `target.o` (decomp.me reference) vs IDA-synth `.o` **unfixed** | objdiff-cli | 99.01786% — 11 reloc args mismatched showing `+0xb7cb5c` (absolute VAs) |
| `target.o` vs IDA-synth `.o` **fixed** (recipe below) | objdiff-cli | **100.00000%** — all 56 instructions, all 12 relocs, penalty 0/5600 |
| `current.o` (local recompilation) vs `target.o` | objdiff-cli | 94.19643% — real codegen drift |
| `current.o` vs IDA-synth `.o` (fixed) | objdiff-cli | 93.22807% — the same real codegen drift |
| `current.o` vs live IDA bytes (own matcher) | matcher | 92.00% |

Conclusion: after the two fixes, the IDA prep is byte-faithful. The remaining 92–94% gap is
**real codegen difference** in `current.o` (extra `mov ebp,[edi]`, register choice `ecx` vs
`ebp/edx`, `cmp` operand order, branch offsets ±2), not a prep error.

The decomp.me site score (86.44%, scratch `fzdFq`) is an older/different state and is recorded
site-side as obj-vs-obj; it is not reproducible locally because `decomp.me` blocks scraping
(Cloudflare 403) for the full `ctx.cpp`.

### 1.2 Test bed — `E:\repos\gta_sa_test`

All fidelity validation lives in the local scratch/test-bed folder (outside this repo):

```
E:\repos\gta_sa_test\
  _Process_COnscreenTimerEntry__QAEXXZ\          # decomp.me scratch unit used by this plan
    target.o    # reference (expected) MSVC 7.0 obj — 167 B, 12 relocs, max_score 5600
    current.o   # local recompilation (the 92-94% side)
    code.cpp    # decompiled source under test
    ctx.cpp     # game context
    metadata.json
  _CreateRopeForSwatPed_CRopes__SAHABVCVector___Z\   # regression unit (matcher: 100%)
  _InitialiseVehiclePoolConversionTable_CReplay__SAXXZ\  # regression unit (matcher: 100%)
  GetNextFileOnCd__10CStreamingFib\                  # x64 unit
  gta_sa_93.i64 / .id0/.id1/.nam/.til                # the live IDA 9.3 database
  ida_watch.json        # symbol/reloc mappings for the units
  match_unit.py         # focused matcher runner
  build.bat             # MSVC 7.0 build script
  msvc700-master\       # vendored VS .NET 2002 (MSVC 7.0) toolchain
  *.zip                 # decomp.me scratch downloads
```

The F4 golden fixture (`tests/fixtures/process_target.o`) is copied from
`E:\repos\gta_sa_test\_Process_COnscreenTimerEntry__QAEXXZ\target.o`, and its companion
`process_record.json` mirrors the IDA record the live server returns for
`_ZN19COnscreenTimerEntry7ProcessEv`.

## 2. Root cause 1 — spurious `_` prefix on every Text/Data symbol

### 2.1 Mechanism

`object::write::Object::new(Coff, I386, Little)` sets `mangling = Mangling::CoffI386`
(`object-0.36.7/src/write/mod.rs:114`, `Mangling::default` at `mod.rs:1007-1016`).
`Mangling::CoffI386::global_prefix()` returns `Some(b'_')` (`mod.rs:1019-1024`), and `add_symbol`
prepends it to **every** `Text`/`Data`/`Tls` symbol (`mod.rs:385-399`).

Real MSVC only decorates plain C names with `_`. `?`-mangled (C++) and already-underscored
(compiler-helper / `__imp_`) names are stored **verbatim** in the COFF symbol table.

| Symbol (as IDA labels it / real MSVC stores it) | object crate `CoffI386` writes |
|---|---|
| `?Process@COnscreenTimerEntry@@QAEXXZ` | `_?Process@COnscreenTimerEntry@@QAEXXZ` ✗ |
| `_printf` | `__printf` ✗ |
| `__ftol2` | `___ftol2` ✗ |

x86_64 COFF defaults to `Mangling::Coff` (`global_prefix()` = `None`), so **only 32-bit x86** is
affected — but that is the primary target.

### 2.2 Why it breaks objdiff

`objdiff-core` pairs symbols by exact symbol-table name (`matching_symbols`). Left = real
`target.o` has `?Process@...`; right = synthetic has `_?Process@...` → the pair is missed, or
relocs pointing at `_printf` vs `__printf` never match. The temp cross-check had to post-process
the bytes to strip the spurious `_` (`fix_synth_names.py`).

## 3. Root cause 2 — reloc-site bytes carry the VA, not the addend

### 3.1 Mechanism

`objdiff-core` reads **implicit COFF addends from the section data bytes at the relocation site**
(`objdiff-core/src/arch/x86.rs:302-304`, `section.data()[address..address+4]` read as `i32`) —
there is no addend field in a COFF relocation record.

- IDA record `bytes` are the **image bytes** → the reloc site holds the absolute VA
  (e.g. `5ccbb700` = `0xb7cb5c`).
- Real MSVC `.obj` holds a **placeholder addend** at the site: `0` for base-of-symbol refs,
  `0x3d` (=61) for `TheCamera+0x3d`. (Verified byte-by-byte in `target.o`.)
- The `object` crate `coff_adjust_addend` adds `+4` for `IMAGE_REL_I386_REL32`
  (`object-0.36.7/src/write/coff/object.rs:193-199`), and `write_relocation_addend` writes the
  *adjusted* addend into the section data — **but only when `addend != 0`**
  (`object-0.36.7/src/write/mod.rs:600-603`). Zero addends are never written, so the IDA VA bytes
  survive.

Before the fix the synthetic obj showed `+0xb7cb5c`-style `DIFF_ARG_MISMATCH` on every external,
and REL32 sites carried a `+4` bias.

### 3.2 Addend semantics summary (must be exact)

| case | real MSVC site bytes | what to pass to `add_relocation` | patch site to |
|---|---|---|---|
| DIR32 external (`call _printf` via DIR32), addend 0 | `00000000` | `0` | `0` |
| DIR32 data member (`TheCamera+0x3d`), addend 61 | `3d000000` | `61` | `61` |
| REL32 external (`call ?Foo@...`), addend 0 | `00000000` | `0 - 4 = -4` (writer adds +4 → 0, skip) | `0` |
| REL32 nonzero addend A | `A` (LE) | `A - 4` (writer adds +4 → A, writes it) | `A` |
| DIR16 (width 2), any addend | `A` (LE 16-bit) | `0` (writer errors on 16-bit addend writes) | `A` |

Because zero addends are *skipped* by the writer, sites must be **explicitly patched** to the
addend value; the writer's own write only ever needs to match (or be bypassed for width 2).

## 4. The fix (two changes, proven recipe)

### Fix A — verbatim COFF symbol names

In `ObjectBuilder::new` (`vendor/objdiff-py/src/lib.rs`), set `Mangling::Coff` for COFF formats:

```rust
let mut obj = object::write::Object::new(format, architecture, endianness);
if format == object::BinaryFormat::Coff {
    obj.flags = object::FileFlags::Coff { characteristics: object::pe::IMAGE_FILE_LINE_NUMS_STRIPPED };
    // MSVC stores '?'-mangled and already-underscored names verbatim. The
    // default CoffI386 mangling prepends '_' to every Text/Data symbol, which
    // corrupts them (OBJDIFF_SYNTH_FIDELITY_PLAN.md §2).
    obj.set_mangling(object::write::Mangling::Coff);
}
```

Names are then written exactly as given, which matches real MSVC symbol-table names as IDA labels
them (`?Process@...`, `_printf`, `__ftol2`). Requires a wheel rebuild (`pip install -e .`).

### Fix B — addend-correct reloc-site bytes

1. Patch each reloc-site's bytes in the section data to the record's `fixup_addends[off]`
   value (the byte value a real MSVC `.obj` carries there) — **before** `write_bytes`, exactly as
   `build_ida_synth_msvc.py` does (`<i`/`<h`/`<q` for widths 4/2/8). This is mandatory because the
   writer skips zero addends and the IDA bytes carry VAs.
2. Pass `writer_addend = addend - 4` when class is `relative` (REL32), else `addend` — so the
   writer's internal `+4` reproduces the intended value and never writes a bogus nonzero addend.
3. For width-2 relocs pass `writer_addend = 0` (the writer's `write_relocation_addend` has no
   16-bit path and returns an error — `mod.rs:629-634`); the explicit site patch is the only write.

Apply in **both** builders:
- `ida_matcher/matcher/ida_logic.py::synthetic_obj_from_record` (server, base/right side),
- `ida_matcher/matcher/match_core.py::_compare_functions_objdiff_py` (client; the *left* side is
  built from the real compiled `.obj` whose site bytes are already correct — patch only the base/
  right side, but apply `addend-4`/width-2 rule on **both** sides so the writer never clobbers).

## 5. Phase status

| Phase | Scope | Status | Notes |
|---|---|---|---|
| F1 | Verbatim COFF names in `ObjectBuilder` (Rust) + wheel rebuild | ✅ Done | sets `Mangling::Coff` for COFF |
| F2 | Addend-correct reloc sites in `synthetic_obj_from_record` (IDA side) | ✅ Done | patch sites + `addend-4` + width-2 |
| F3 | Addend-correct reloc sites in `_compare_functions_objdiff_py` (client) | ✅ Done | patch base side only, writer rule on both |
| F4 | Golden regression vs real `target.o` + doc sync | ✅ Done | fixture + 100% test + docs |

> Rule for agents executing a phase: after verification passes, flip this table entry to
> `✅ Done`, update `API_MAP.md` with every API/behavior change, and update `CURRENT_STATE.md`.

## 6. Execution spec — Phase F1 (verbatim names, Rust)

**File:** `vendor/objdiff-py/src/lib.rs`, `ObjectBuilder::new` (~line 52).
**Change:** insert `obj.set_mangling(object::write::Mangling::Coff);` inside the existing
`if format == object::BinaryFormat::Coff { ... }` block. No Python signature change.
**Rebuild:** `pip install -e .` from repo root (maturin rebuild of `objdiff_py`).

**Tests to add** (`ida_matcher/matcher/tests/test_objdiff_py.py`):
- `test_object_builder_verbatim_symbol_names` — build `ObjectBuilder("x86")`; add symbols
  `?Foo@@YAXXZ`, `_printf`, `__ftol2` (one Text in-section, two undefined Data); `finish()`; parse
  the bytes with `coff_pure.load_obj_pure` (and/or read the COFF string table directly) and assert
  the exact names are present and **no** `_`-prefixed variants (`_?Foo...`, `__printf`,
  `___ftol2`) exist.
- `test_object_builder_verbatim_x64` — same on `ObjectBuilder("x86_64")` (already Coff, no-op
  guard).

**Definition of Done:**
- [x] `obj.set_mangling(Mangling::Coff)` present for all COFF formats; wheel rebuilt.
- [x] New verbatim-name tests green; full suite (`python -m pytest ida_matcher/matcher/tests -q`) green.
- [x] `API_MAP.md` §11 documents verbatim naming.

## 7. Execution spec — Phase F2 (IDA-side addends)

**File:** `ida_matcher/matcher/ida_logic.py::synthetic_obj_from_record` (~line 531).
**Changes:**
1. Build `data = bytearray(raw_bytes)` and, for every fixup, patch the site:
   `struct.pack_into("<i", data, off, addend)` / `"<h"` / `"<q"` for widths 4/2/8.
2. `b.write_bytes(sec_id, 0, bytes(data))` (patched data).
3. In the relocation loop, compute `writer_addend`:
   - `relative` → `addend - 4`; width-2 relocs → force `0`.
   - otherwise → `addend`.
   Pass `writer_addend` to `add_relocation`. Keep reloc_kind mapping unchanged
   (`1` = REL32, `6` = DIR32, width-2 → kind `1`).

**Tests to add** (`test_objdiff_py.py`):
- `test_synthetic_obj_reloc_site_bytes_zero` — record with `bytes` containing a nonzero VA at a
  DIR32 site (`fixup_addends` `0`) → synthetic obj → assert section bytes at site are `0`.
- `test_synthetic_obj_reloc_site_bytes_addend` — DIR32 site addend `61` → site bytes `3d000000`.
- `test_synthetic_obj_reloc_site_bytes_rel32` — REL32 site (`fixup_classes {"off":"relative"}`, addend `0`)
  → site bytes `0`, NOT `4`.
- Extend `test_synthetic_obj_from_record_pure_and_lief_roundtrip` to include a `relative` fixup.

**Definition of Done:**
- [x] Site bytes match MSVC placeholder addends (0 / 61 / 0) in all three tests.
- [x] Full suite green. `API_MAP.md` §8 note updated.

## 8. Execution spec — Phase F3 (client-side addends)

**File:** `ida_matcher/matcher/match_core.py::_compare_functions_objdiff_py` (~line 142).
**Changes:**
1. Right/base side: build `data = bytearray(bytes(base_bytes))`, patch each fixup site with its
   addend (tuple `[3]` or default `0`), then `write_bytes`.
2. Both sides: `writer_addend = r_addend - 4 if r_cls == "relative" else r_addend`; width-2 →
   force `0`.
3. Left side is built from the real compiled `.obj` bytes — no site patch (already correct), but
   the writer rule above must still apply so the `+4` clobber never happens.

**Tests to add:**
- `test_compare_functions_objdiff_py_rel32_addend` — left bytes with REL32 site `0` +
  reloc relative addend `0`; right bytes with the same shape but a VA at the site + fixup
  relative addend `0` → `compare_functions(..., OBJDIFF_PY=1)` returns `100.0`.
- `test_compare_functions_objdiff_py_dir32_addend` — DIR32 member-addend case (site `61` both
  sides) → `100.0`.

**Definition of Done:**
- [x] New addend tests green; full suite green.
- [x] `API_MAP.md` §4 notes the client-side patch behavior.

## 9. Execution spec — Phase F4 (golden regression + doc sync)

**Fixture:** copy the 167-byte `E:\repos\gta_sa_test\_Process_COnscreenTimerEntry__QAEXXZ\target.o`
to `ida_matcher/matcher/tests/fixtures/process_target.o`; add
`ida_matcher/matcher/tests/fixtures/process_record.json` containing the Process IDA record
(167 bytes hex, `fixups`/`fixup_widths`/`fixup_classes`/`fixup_addends`/`fixup_sym_kinds`,
`section_name ".text"`, `section_kind "code"`, `arch "x86"`, 12 fixups, `max_score 5600`).

**Test:** `test_synthetic_obj_matches_real_msvc_obj` — build synthetic via
`synthetic_obj_from_record(record, "?Process@COnscreenTimerEntry@@QAEXXZ")`, then
`diff_objects(fixture_target_bytes, synthetic)`; assert `match_percent == 100.0` and
`diff_score == [0, 5600]`.

**Doc sync:**
1. `API_MAP.md` — finalize the fidelity contract (§11 verbatim names; §8/§4 addend patching).
2. `CURRENT_STATE.md` §3 — add row `I25` "Synthetic-object COFF fidelity (F1–F3)": verbatim
    names + addend-correct reloc sites; cross-check `target.o` vs IDA-synth = 100.00000%.
3. `OBJDIFF_RUST_MIGRATION.md` §2 row 5 → mark validated; §6 add the fidelity work items as Done.
**Definition of Done:**
- [x] Fixtures `process_target.o` and `process_record.json` present in `ida_matcher/matcher/tests/fixtures/`.
- [x] `test_synthetic_obj_matches_real_msvc_obj` passes with 100.0% and score `[0, 5600]`.
- [x] Full suite green (`pytest ida_matcher/matcher/tests -q`).
- [x] All documentation updated and synchronized.

## 10. Test harness / regression command

```bash
python -m pytest ida_matcher/matcher/tests -q
```

Full-suite count baseline: **158 passed** (pre-F1). Every phase keeps it green (net +N new tests).

Cross-check command (manual, for F4 verification):
```bash
objdiff-cli diff --target <target.o> --base <ida_synth_fixed.o> --format json   # expect 100.00000
```

## 11. Risks / mitigations

| Risk | Mitigation |
|---|---|
| `Mangling::Coff` on I386 produces names real MSVC stores with `_` for plain C | IDA labels already carry MSVC decoration (`_printf`, `?Foo@...`); verbatim = identical to the real symbol table. |
| Wheel rebuild required for F1 breaks the installed `objdiff_py` | Rebuild is `pip install -e .`; prebuilt wheels story already documented (API_MAP §12). |
| Width-2 relocs with nonzero addend error the writer (`write_relocation_addend` has no 16-bit path) | Pass writer addend `0` for width-2 and rely on the explicit site patch (F2/F3 spec). |
| `.obj` fixture too large for tests | `target.o` is 167 bytes; fine to commit under `tests/fixtures/`. |
| Decomp.me site score (86.44%) still not reproducible | It is an older/different state recorded obj-vs-obj; out of scope — local truth is the 100% objdiff-cli cross-check. |

## 12. Out of scope

- Changing `current.o` codegen to match `target.o` (that is the user's recompilation work, not prep).
- `decomp.me` upload / scraping (blocked).
- ARM/PPC/MIPS synthetic objects (only COFF is covered by this fidelity fix; `Mangling::Coff` is a no-op for ELF).
## 13. Detailed Execution Spec for Flash

This section consolidates the exact implementation details required for a subagent (Flash) to execute F1-F4 without judgment calls.

### Exact module/file paths and function/method signatures to modify

- **F1 (Rust):** `vendor/objdiff-py/src/lib.rs`
  - Function: `impl ObjectBuilder { pub fn new(format: &str, architecture: &str, endianness: &str) -> PyResult<Self> }`
- **F2 (IDA Server):** `ida_matcher/matcher/ida_logic.py`
  - Function: `def synthetic_obj_from_record(rec: dict, name: str = None) -> bytes:`
- **F3 (Client Engine):** `ida_matcher/matcher/match_core.py`
  - Function: `def _compare_functions_objdiff_py(left_bytes, base_bytes_hex, obj_relocs, base_fixups, base_switches=None, obj_reloc_widths=None, base_switch_ranges=None, func_name=None, diff_direction="left_to_right"):`
- **F4 (Tests & Docs):** 
  - `ida_matcher/matcher/tests/test_objdiff_py.py`
  - `ida_matcher/matcher/tests/fixtures/process_target.o`
  - `ida_matcher/matcher/tests/fixtures/process_record.json`
  - `API_MAP.md`, `CURRENT_STATE.md`, `OBJDIFF_RUST_MIGRATION.md`, `OBJDIFF_SYNTH_FIDELITY_PLAN.md`

### F1: The Rust change and exact rebuild command

- ARM/PPC/MIPS synthetic objects (only COFF is covered by this fidelity fix; `Mangling::Coff` is a no-op for ELF).

## 13. Detailed Execution Spec for Flash

This section consolidates the exact implementation details required for a subagent (Flash) to execute F1-F4 without judgment calls.

### Exact module/file paths and function/method signatures to modify

- **F1 (Rust):** `vendor/objdiff-py/src/lib.rs`
  - Function: `impl ObjectBuilder { pub fn new(format: &str, architecture: &str, endianness: &str) -> PyResult<Self> }`
- **F2 (IDA Server):** `ida_matcher/matcher/ida_logic.py`
  - Function: `def synthetic_obj_from_record(rec: dict, name: str = None) -> bytes:`
- **F3 (Client Engine):** `ida_matcher/matcher/match_core.py`
  - Function: `def _compare_functions_objdiff_py(left_bytes, base_bytes_hex, obj_relocs, base_fixups, base_switches=None, obj_reloc_widths=None, base_switch_ranges=None, func_name=None, diff_direction="left_to_right"):`

### F1: The Rust change and exact rebuild command

**Code Change in `ObjectBuilder::new`:**
```rust
if format == object::BinaryFormat::Coff {
    obj.flags = object::FileFlags::Coff { characteristics: object::pe::IMAGE_FILE_LINE_NUMS_STRIPPED };
    // MSVC stores '?'-mangled and already-underscored names verbatim. The
    // default CoffI386 mangling prepends '_' to every Text/Data symbol, which
    // corrupts them (OBJDIFF_SYNTH_FIDELITY_PLAN.md §2).
    obj.set_mangling(object::write::Mangling::Coff);
}
```

**Rebuild Command:**
```bash
pip install -e .
```
*(Run from the repo root)*

### F2 & F3: Byte-patching helper signature and writer-addend table

**Byte-Patching Helper to inject in `ida_logic.py` and `match_core.py`:**
```python
import struct

def patch_reloc_site(data: bytearray, offset: int, width: int, addend: int):
    """
    Patch the COFF implicit addend directly into the section bytes at the relocation site.
    """
    if width == 4:
        data[offset:offset+4] = struct.pack("<i", addend)
    elif width == 2:
        data[offset:offset+2] = struct.pack("<h", addend)
    elif width == 8:
        data[offset:offset+8] = struct.pack("<q", addend)
```

**Writer-Addend Table (from §3.2):**
| case | real MSVC site bytes | what to pass to `add_relocation` | patch site to |
|---|---|---|---|
| DIR32 external | `00000000` | `0` | `0` |
| DIR32 data member | `3d000000` | `61` | `61` |
| REL32 external | `00000000` | `addend - 4` (writer adds +4) | `0` |
| REL32 nonzero addend `A` | `A` (LE) | `A - 4` | `A` |
| DIR16 (width 2) | `A` (LE 16-bit) | `0` (writer errors on 16-bit addend writes) | `A` |

**Application Logic:**
```python
# During the fixup loop:
if cls == "relative":
    writer_addend = addend - 4
elif width == 2:
    writer_addend = 0
else:
    writer_addend = addend
```

### Test Cases and Fixtures (F4)

**Fixtures:**
- `ida_matcher/matcher/tests/fixtures/process_target.o`: Use the 167-byte `target.o` from `E:\repos\gta_sa_test\_Process_COnscreenTimerEntry__QAEXXZ\target.o`.
- `ida_matcher/matcher/tests/fixtures/process_record.json`: Contains the IDA record for `_ZN19COnscreenTimerEntry7ProcessEv` with 12 fixups and `max_score 5600`.

**Test Names to Implement:**
1. `test_object_builder_verbatim_symbol_names` (assert names have no `_` prefix)
2. `test_object_builder_verbatim_x64` (same but `x86_64`)
3. `test_synthetic_obj_reloc_site_bytes_zero` (DIR32, addend 0)
4. `test_synthetic_obj_reloc_site_bytes_addend` (DIR32, addend 61)
5. `test_synthetic_obj_reloc_site_bytes_rel32` (REL32, addend 0)
6. `test_synthetic_obj_from_record_pure_and_lief_roundtrip` (extend with `relative` fixup)
7. `test_compare_functions_objdiff_py_rel32_addend`
8. `test_compare_functions_objdiff_py_dir32_addend`
9. `test_synthetic_obj_matches_real_msvc_obj` (golden regression test)

### Definition of Done Checklist

- [x] **F1:** `obj.set_mangling(Mangling::Coff)` implemented and wheel rebuilt.
- [x] **F1:** Verbatim name tests added and passing.
- [x] **F1:** `API_MAP.md` §11 updated.
- [x] **F2:** `patch_reloc_site` and `writer_addend` logic implemented in `ida_logic.py`.
- [x] **F2:** Reloc site bytes tests added and passing.
- [x] **F2:** `API_MAP.md` §8 updated.
- [x] **F3:** `patch_reloc_site` and `writer_addend` logic implemented in `match_core.py`.
- [x] **F3:** Client-side addend tests added and passing.
- [x] **F3:** `API_MAP.md` §4 updated.
- [x] **F4:** Fixtures added.
- [x] **F4:** `test_synthetic_obj_matches_real_msvc_obj` passing (100.0% match).
- [x] **F4:** Full test suite green (`pytest ida_matcher/matcher/tests -q`).
- [x] **F4:** All four docs synced and marked as ✅ Done.
