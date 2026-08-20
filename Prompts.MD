# Prompts for the objdiff-core Rust Migration

Execution prompts for `OBJDIFF_RUST_MIGRATION.md` (the plan) with `API_MAP.md` (the live
interface reference). Two model tiers, one workflow:

- **Gemini Pro** → *architectural plan detailing*. Refines the plan MD, locks signatures,
  schema, and crate layout before any code is written. Never writes implementation code.
- **Gemini Flash** → *implementation*. Executes a fully-detailed phase from the plan MD,
  writes the code, runs tests, and updates the two docs. Never invents scope.

**Universal rules (paste at the top of every prompt):**

```
You are working in the repo at the current working directory. Two files are your contract:
- OBJDIFF_RUST_MIGRATION.md  (the plan; phase specs + status table)
- API_MAP.md                 (the current public interface; must stay in sync)
For the COFF-fidelity work the third contract doc is OBJDIFF_SYNTH_FIDELITY_PLAN.md
(the phased fix plan F1–F4; section 13 is the execution spec).
You must NOT guess or invent requirements. Before any edit, read the relevant plan
section and the relevant API_MAP.md section. After a phase completes, update BOTH docs.
Token rules:
- Never paste full file contents back into chat.
- Make surgical edits; do not rewrite whole files.
- Run `python -m pytest ida_matcher/matcher/tests -q` after every significant change;
  fix failures before continuing.
- Do not delete code unless the plan explicitly says so.
```

---

## 0. Plan Detailing (Gemini Pro — architecture only)

Use before each implementation phase to turn the plan bullet points into a precise spec
that Flash can execute without making judgment calls.

```
You are a Rust/Python systems architect. Your task: detail one phase of
OBJDIFF_RUST_MIGRATION.md so it can be implemented mechanically by another model.

Inputs you MUST read first:
1. OBJDIFF_RUST_MIGRATION.md — the target phase section and the "Decisions" section.
2. API_MAP.md — current APIs the phase touches or replaces.
3. The relevant upstream source under vendor/objdiff (e.g. objdiff-core/src/diff/*.rs)
   so every formula/behavior you specify is real, not guessed.

Produce as your ONLY output an "Execution spec" appended to the plan's phase section
(or a phase-detail MD you name explicitly), containing:
- Exact module/file paths and function signatures to add or modify.
- The PyO3 API surface (class names, method names, argument/return types) for this phase.
- Byte/JSON schema the phase must produce and consume (paste the real struct from
  objdiff-core where one exists).
- Test cases to add, referencing existing tests/conftest.py fixtures by name.
- A "Definition of Done" checklist that maps 1:1 to the phase's work items.

Rules: no implementation code. No prose summaries in chat. Edit the plan file in place.
Mark the phase status row as "⬜ Detailed — ready for Flash" (not Done).
```

---

## 1. Phase 0 — PyO3 bridge spike (Gemini Flash)

```
Execute Phase 0 "Spike the PyO3 bridge" exactly as detailed in OBJDIFF_RUST_MIGRATION.md.

Inputs:
1. Read the Phase 0 spec and status table in OBJDIFF_RUST_MIGRATION.md.
2. Read API_MAP.md §2 (HTTP contract) and §4 (match_core) so you know the current seam.
3. Read tests/conftest.py — the synthetic .obj fixtures are the regression harness.

Instructions:
1. Create vendor/objdiff-py (crate: pyo3, objdiff-core, object) exposing exactly the
   API surface the plan's Execution spec declares.
2. ObjectBuilder: add section / write bytes / add symbol / add relocation / .finish() -> bytes.
3. diff_objects(left_obj: bytes, right_obj: bytes) -> dict, feeding objdiff_core::diff::diff_objs.
4. Add a pytest that (a) builds an .obj with ObjectBuilder and asserts objdiff-core
   (via object::read) consumes it with no errors, and (b) asserts diff_objects' match_percent
   and diff_score equal the Python engine's output on the existing fixtures.
5. Run the full test suite until green.

Documentation step (mandatory):
1. In OBJDIFF_RUST_MIGRATION.md, set Phase 0 status to "✅ Done".
2. In API_MAP.md, add a "Native extension (objdiff_py)" section documenting
   ObjectBuilder and diff_objects signatures exactly as implemented.
```

---

## 2. Phase 1 — IDA-side synthetic object (Gemini Flash)

```
Execute Phase 1 "Convert IDA-side extraction to ObjectBuilder" exactly as detailed in
OBJDIFF_RUST_MIGRATION.md.

Inputs:
1. Read the Phase 1 spec and status table in OBJDIFF_RUST_MIGRATION.md.
2. Read API_MAP.md §2 (HTTP contract), §8 (ida_logic/ida_server), and the objdiff_py section.
3. Read ida_matcher/matcher/ida_logic.py and ida_server.py to see the current extraction
   and the fixup/width/class/addend fields available.

Instructions:
1. In ida_logic.py add build_synthetic_obj(func_name) -> bytes that translates existing
   fixups/fixup_classes/fixup_addends into ObjectBuilder.add_relocation() calls.
   Target: a real COFF .obj that objdiff-core (object::read) parses with no issues.
2. Keep the existing JSON dict path working unchanged for comparison during transition.
3. Add GET /synthetic_obj?name=... to ida_server.py returning raw .obj bytes
   (Content-Type: application/octet-stream) or JSON base64 — follow the plan's choice.
4. Add headless tests: ObjectBuilder output round-trips through the pure COFF reader
   (coff_pure/coff_lief) with the same relocs and widths.
5. Run the full test suite until green.

Documentation step (mandatory):
1. In OBJDIFF_RUST_MIGRATION.md, set Phase 1 status to "✅ Done".
2. In API_MAP.md, update §2 HTTP contract table with /synthetic_obj, and §8 with
   build_synthetic_obj(); note any fields reused from the fixup descriptors.
```

---

## 3. Phase 2 — client engine swap (Gemini Flash)

```
Execute Phase 2 "Swap the client diff engine" exactly as detailed in
OBJDIFF_RUST_MIGRATION.md.

Inputs:
1. Read the Phase 2 spec and status table in OBJDIFF_RUST_MIGRATION.md (including the
   "No deletions" decision and the OBJDIFF_PY flag).
2. Read API_MAP.md §4 (match_core), §7 (engine/), and the objdiff_py section.
3. Read match_core.py and the existing engine tests.

Instructions:
1. Add an OBJDIFF_PY environment flag that routes compare_functions()/match_focus()
   through diff_objects() when set; default behavior unchanged.
2. When the Rust path is active: read the compiled .obj from disk, fetch synthetic bytes
   from the server, call objdiff_py.diff_objects, and pass the result dict to the
   existing console formatter (engine/display.py stays).
3. Add an optional config key for the right-to-left (objdiff-style) diff direction;
   default remains left=compiled .obj, right=IDA.
4. Do NOT delete engine/diff_code.py, align.py, arch_x86.py, data.py, types.py —
   they become the unused legacy path.
5. Add tests covering both flag states; CI runs both. Full suite green.

Documentation step (mandatory):
1. In OBJDIFF_RUST_MIGRATION.md, set Phase 2 status to "✅ Done".
2. In API_MAP.md, update §4 and §7: mark engine/ modules as "legacy (unused when
   OBJDIFF_PY set)", document the flag, and add the right-to-left config key.
```

---

## 4. Phase 3 — install/build story (Gemini Flash)

```
Execute Phase 3 "Install/build story" exactly as detailed in OBJDIFF_RUST_MIGRATION.md.

Inputs:
1. Read the Phase 3 spec and status table in OBJDIFF_RUST_MIGRATION.md.
2. Read pyproject.toml (current build config) and README.md installation section.
3. Read API_MAP.md §6 (CLI) so the doc updates match reality.

Instructions:
1. Switch the build backend to maturin: add [build-system] requires = ["maturin"],
   configure the mixed Rust/Python layout, and keep the existing ida-match/ida-watch
   console scripts working.
2. Document the Rust toolchain requirement (rustup + maturin build) for building the
   IDA plugin in README.md, while shipping prebuilt wheels so end users never run cargo.
3. Add a CI or documented build step that produces per-platform wheels.
4. Run the full test suite green; verify pip install -e . still exposes both CLIs.

Documentation step (mandatory):
1. In OBJDIFF_RUST_MIGRATION.md, set Phase 3 status to "✅ Done".
2. In API_MAP.md, update §6 CLI (no CLI change expected — confirm) and note the build
   backend change. Update README.md install section as specified.
```

---

## 5. Doc-sync sweep (Gemini Flash — run after any phase)

```
Reconcile the docs after a phase completed.

1. Read OBJDIFF_RUST_MIGRATION.md status table and API_MAP.md.
2. Grep the codebase (match_core.py, ida_server.py, ida_logic.py, pyproject.toml,
   engine/) for every public function/endpoint/CLI flag that exists.
3. Update API_MAP.md so every documented item matches the code 1:1 (add missing,
   annotate changed, delete removed).
4. Confirm each finished phase in OBJDIFF_RUST_MIGRATION.md is "✅ Done" and the
   status table matches reality. Report only a list of diffs made — no code dumps.
```

---

## 6. COFF-fidelity plan detailing (Gemini Pro — architecture only)

Use before implementing the F-phases in `OBJDIFF_SYNTH_FIDELITY_PLAN.md`. Reads the plan and
the proven temp-script recipe, and turns it into precise execution specs Flash/Deepseek can
follow mechanically.

```
You are a systems architect for a COFF/objdiff reverse-engineering toolchain. Detail the
COFF-fidelity plan so another model can implement it without judgment calls.

Inputs you MUST read first:
1. OBJDIFF_SYNTH_FIDELITY_PLAN.md — sections 2-3 (root causes), 4 (the fix), 6-9 (execution specs).
2. API_MAP.md §8, §11 — the ObjectBuilder and synthetic_obj_from_record contracts you touch.
3. The temp proof at C:\Users\USER\AppData\Local\Temp\opencode\build_ida_synth_msvc.py
   (exact byte-patch + name-fix recipe that achieved 100.00000% vs the real target.o).
4. The exact upstream lines cited in the plan:
   - object-0.36.7/src/write/mod.rs:385-399 (add_symbol mangling), 600-603 (addend write skip),
     629-634 (no 16-bit addend path), 1007-1024 (Mangling default/global_prefix)
   - object-0.36.7/src/write/coff/object.rs:193-199 (coff_adjust_addend +4)
   - objdiff-core/src/arch/x86.rs:302-304 (implicit addend read from section data)
5. ida_matcher/matcher/ida_logic.py::synthetic_obj_from_record and
   match_core.py::_compare_functions_objdiff_py as they exist TODAY.

Produce as your ONLY output an "Execution spec" appended to the plan (or a phase-detail MD you
name explicitly), containing:
- Exact module/file paths and function/method signatures to modify for F1-F4.
- The Rust change for F1 (set_mangling location) and the exact rebuild command.
- The byte-patching helper signature (widths 2/4/8) and the writer-addend table from §3.2.
- Test cases, referencing the plan's proposed test names and the fixtures to add.
- A "Definition of Done" checklist mapping 1:1 to the plan's F-phase work items.

Rules: no implementation code. No prose summaries in chat. Edit the plan file in place.
Mark each phase status row as "⬜ Detailed — ready for Flash" (not Done).
```

---

## 7. Phase F1 — verbatim COFF symbol names (Gemini Flash/Deepseek)

```
Execute Phase F1 "Verbatim COFF symbol names" exactly as detailed in OBJDIFF_SYNTH_FIDELITY_PLAN.md §13.

Inputs:
1. Read the F1 spec and the phase status table in OBJDIFF_SYNTH_FIDELITY_PLAN.md.
2. Read API_MAP.md §11 (ObjectBuilder) so the doc update matches the implemented change.
3. Read vendor/objdiff-py/src/lib.rs ObjectBuilder::new (the mangling site).

Instructions:
1. Inside the existing `if format == object::BinaryFormat::Coff { ... }` block in
   ObjectBuilder::new, call obj.set_mangling(object::write::Mangling::Coff) with the comment
   from the plan. Do NOT change any Python signature.
2. Rebuild the extension: pip install -e . from the repo root. Confirm import objdiff_py works.
3. Add test_object_builder_verbatim_symbol_names and test_object_builder_verbatim_x64 to
   ida_matcher/matcher/tests/test_objdiff_py.py per the plan §13 (names ?Foo@@YAXXZ, _printf,
   __ftol2 must appear verbatim; no _-prefixed variants).
4. Run python -m pytest ida_matcher/matcher/tests -q until green.

Documentation step (mandatory):
1. In OBJDIFF_SYNTH_FIDELITY_PLAN.md, set F1 status to "✅ Done".
2. In API_MAP.md §11, confirm the verbatim-naming note is present and accurate.
3. Update the F1 checkbox in OBJDIFF_RUST_MIGRATION.md §6.
```

---

## 8. Phase F2 — IDA-side addend-correct reloc sites (Gemini Flash/Deepseek)

```
Execute Phase F2 "Addend-correct reloc sites, IDA side" exactly as detailed in OBJDIFF_SYNTH_FIDELITY_PLAN.md §13.

Inputs:
1. Read the F2 spec (patch sites with fixup_addends; addend-4 for relative; width-2 -> 0).
2. Read API_MAP.md §8 (synthetic_obj_from_record note) and §2 (fixup_addends field).
3. Read ida_matcher/matcher/ida_logic.py::synthetic_obj_from_record.

Instructions:
1. Build data = bytearray(raw_bytes) and patch each fixup site (struct.pack_into "<i"/"<h"/"<q"
   for widths 4/2/8) to the record's fixup_addends value, BEFORE b.write_bytes.
2. In the relocation loop, compute writer_addend = addend - 4 when class=="relative", force 0 for
   width-2 relocs, else addend; pass it to b.add_relocation. Keep reloc_kind mapping unchanged.
3. Add the three site-byte tests from the plan §13 (zero / 61 / REL32-not-4) and extend the
   pure_and_lief_roundtrip test with a "relative" fixup.
4. Run the full suite until green.

Documentation step (mandatory):
1. Set F2 to "✅ Done" in the plan's status table.
2. Confirm the API_MAP.md §8 fidelity note is accurate; update if needed.
3. Update the F2 checkbox in OBJDIFF_RUST_MIGRATION.md §6.
```

---

## 9. Phase F3 — client-side addend-correct reloc sites (Gemini Flash/Deepseek)

```
Execute Phase F3 "Addend-correct reloc sites, client side" exactly as detailed in OBJDIFF_SYNTH_FIDELITY_PLAN.md §13.

Inputs:
1. Read the F3 spec (patch base/right side; writer rule on BOTH sides).
2. Read API_MAP.md §4 note about _compare_functions_objdiff_py.
3. Read ida_matcher/matcher/match_core.py::_compare_functions_objdiff_py.

Instructions:
1. Right/base side: build data = bytearray(bytes(base_bytes)), patch each fixup site with its
   addend (tuple index 3, default 0), then write_bytes the patched data.
2. Both sides: writer_addend = r_addend - 4 when class=="relative", 0 for width-2, else r_addend.
3. Do NOT patch the left side (it is the real compiled .obj; its bytes are already correct).
4. Add test_compare_functions_objdiff_py_rel32_addend and _dir32_addend per the plan §13
   (OBJDIFF_PY=1 -> 100.0).
5. Run the full suite until green.

Documentation step (mandatory):
1. Set F3 to "✅ Done" in the plan's status table.
2. Confirm the API_MAP.md §4 fidelity note is accurate; update if needed.
3. Update the F3 checkbox in OBJDIFF_RUST_MIGRATION.md §6.
```

---

## 10. Phase F4 — golden regression + doc sync (Gemini Flash/Deepseek)

```
Execute Phase F4 "Golden regression vs real target.o + doc sync" exactly as detailed in OBJDIFF_SYNTH_FIDELITY_PLAN.md §13.

Inputs:
1. Read the F4 spec (fixture + diff_objects == 100.0 / [0, 5600] test).
2. Read tests/conftest.py to match fixture conventions.

Instructions:
1. Copy E:\repos\gta_sa_test\_Process_COnscreenTimerEntry__QAEXXZ\target.o (167 bytes) to
   ida_matcher/matcher/tests/fixtures/process_target.o; add process_record.json holding the
   matching IDA record (bytes/fixups/fixup_widths/fixup_classes/fixup_addends/fixup_sym_kinds,
   section .text, arch x86, 12 fixups).
2. Add test_synthetic_obj_matches_real_msvc_obj: build the synthetic obj via
   synthetic_obj_from_record(record, "?Process@COnscreenTimerEntry@@QAEXXZ"), diff_objects against
   the fixture bytes, assert match_percent == 100.0 and diff_score == [0, 5600].
3. Run the full suite until green.
4. Optional: re-run the objdiff-cli cross-check to reproduce 100.00000%.

Documentation step (mandatory):
1. Finalize the fidelity contract in API_MAP.md (§11, §8, §4).
2. CURRENT_STATE.md §3: add row I25 "Synthetic-object COFF fidelity (F1-F3)" incl. the
   100.00000% cross-check result.
3. OBJDIFF_RUST_MIGRATION.md §2 row 5 (already "Validated") + §6 F1-F4 checkboxes to [x].
4. OBJDIFF_SYNTH_FIDELITY_PLAN.md: flip F1-F4 to "✅ Done".
```