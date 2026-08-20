# Objdiff Parity Plan API Map

This document serves as a cross-reference matrix connecting the core `objdiff` features specified in the Parity Plan to their concrete Python implementations in `ida_matcher/matcher/engine/`.

## Phase 1: Instruction-Diff Engine Parity

| objdiff Feature | Rust Source Reference | Python Implementation | Description |
| :--- | :--- | :--- | :--- |
| **Instruction Alignment** | `similar::capture_diff_slices(Algorithm::Patience)` | `engine/align.py` | Implements Patience diff alignment over Capstone instruction IDs, padding shorter sides with empty rows. |
| **Decision Tree & Penalties** | `diff_instruction()` | `engine/diff_code.py` | Assigns diff kinds (`Equal`, `Replace`, `Insert`, `Delete`, `OpMismatch`, `ArgMismatch`) and calculates penalty scores based on opcode/argument equality. |
| **Branch Resolution** | `resolve_branches()` | `engine/arch_x86.py` | Maps instruction addresses to row indices after alignment to determine if local branch destinations match identically across rows. |
| **Argument Equality** | `arg_eq()`, `loose_eq()` | `engine/diff_code.py` | Compares operand arguments (`Value`, `Reloc`, `BranchDest`). Includes rules for `Opaque` string-eq and relaxed/strict modes. |
| **Instruction Parsing** | `scan_instructions()` | `engine/arch_x86.py` | Identifies embedded data vs code and processes inline/internal branch targets. |
| **Scoring Formula** | `diff_score`, `match_percent` | `engine/diff_code.py` | Computes the final running penalty sum and derives a percentage match against the maximum possible score (`left_ops.len() * 100`). |

## Phase 2: Reloc-Comparison Parity

| objdiff Feature | Rust Source Reference | Python Implementation | Description |
| :--- | :--- | :--- | :--- |
| **Relocation Equality** | `reloc_eq()` | `engine/diff_code.py` | The primary gatekeeper for reloc matching. Compares relocation classes, checks relaxed modes, and verifies names/sections. |
| **Symbol Normalization** | `get_normalized_symbol_name()` | `engine/diff_code.py` | Strips hash suffixes (e.g. MSVC `?A0x@@`) and normalizes sequential markers (`$NNNN`/`.NNNN`) to standard baseline values. |
| **Compiler Generated Names** | `is_symbol_name_compiler_generated()` | `engine/diff_code.py` | Detects anonymous pool labels like `@digits`, `_$E<digits>`, and `$LC<digits>` allowing them to match purely on value/content. |
| **Symbol Name Matches** | `symbol_name_matches()` | `engine/diff_code.py` | Invokes normalization logic before performing string comparison of two reloc target names. |
| **Address/Pool Equality** | `address_eq()` | `engine/diff_code.py` | Handles zero-size (pool) targets by checking the fully resolved target address (symbol base + addend) instead of requiring strict name equality. |

> Note: Phase 2.5 (Modularization) is complete. The functions above have been relocated from the monolithic `match_core.py` into smaller, specialized modules under the `ida_matcher/matcher/engine/` package.

## Phase 3 & 4: Scoring and Data/BSS Parity

| objdiff Feature | Rust Source Reference | Python Implementation | Description |
| :--- | :--- | :--- | :--- |
| **Data Symbol Diffing** | `diff_data_symbol()` | `engine/data.py` | Patience diff over raw bytes (mirrors `similar::diff_ratio`) with double-weighting for matching relocations within the byte range. |
| **BSS Symbol Diffing** | `diff_bss_symbol()` | `engine/data.py` | Scores bss symbols based on size equality (100% if equal, 50% otherwise). |
| **Section Aggregation** | `diff_generic_section()`, `diff_data_section()`, `diff_bss_section()` | `engine/data.py` | Averages scores at the section level, applying gating rules (e.g. data section score overrides generic score if all relocs match). |
| **Cross-Symbol Data Access** | `ins_data_literals_eq()` | `engine/diff_code.py` | Resolves cross-symbol equality when `DataValue` matching is required, relying on `data_accessor` passed into `_InsnSource`. |
