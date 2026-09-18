"""
IDA Call Graph Exporter
=======================
Exports the call graph from an IDA database to Markdown (.md) and/or Graphviz DOT (.dot).

Features:
  - Full function listing with addresses, sizes, caller/callee counts
  - Per-function caller and callee details
  - Depth-limited traversal from a target function (subgraph mode)
  - Top-N hotspot ranking by caller count
  - Graphviz DOT export for visualization
  - Filtering by name pattern, size range, or segment

Usage:
  Run in IDA via File > Script File, or from IDAPython console.
  All configuration is in the EXPORT CONFIG section below.
"""

import idaapi
import idc
import idautils
import os
import re
import json
import time
from collections import defaultdict

# ============================================================
# EXPORT CONFIG
# ============================================================

# Output paths (set to None to skip that export)
OUTPUT_DIR = r"D:\repos\ida_live_matching_diff"
MD_OUTPUT = os.path.join(OUTPUT_DIR, "callgraph.md")
DOT_OUTPUT = os.path.join(OUTPUT_DIR, "callgraph.dot")
JSON_OUTPUT = os.path.join(OUTPUT_DIR, "callgraph.json")
CSV_OUTPUT = os.path.join(OUTPUT_DIR, "callgraph_index.csv")

# Mode: "full" = entire database, "subtree" = depth-limited from ROOT_FUNC
MODE = "full"

# Root function for subtree mode (name or address string)
ROOT_FUNC = "?setup@TRIBE_Game@@MAEHXZ"

# Depth limit for subtree mode (0 = unlimited)
MAX_DEPTH = 3

# Top-N callers ranking (0 = disabled)
TOP_N_CALLERS = 20

# Name filter regex (only include matching functions, None = all)
# Example: r"TRIBE_|RGE_" to include only TRIBE_ and RGE_ prefixed functions
NAME_FILTER = None

# Size filter (min/max bytes, None = no limit)
MIN_SIZE = None
MAX_SIZE = None

# Segment filter (list of segment names, None = all code segments)
# Example: [".text", "THIS_COD"]
SEGMENT_FILTER = None

# Include leaf functions (no callees) in output
INCLUDE_LEAVES = True

# Include thunks/jumps in output
INCLUDE_THUNKS = False

# Max callers/callees to show per function in MD (0 = all)
MAX_CALLERS_DISPLAY = 10
MAX_CALLEES_DISPLAY = 10

# Emit address-anchored headings + clickable internal links (recommended for AI agents)
ANCHORED_MD = True


# ============================================================
# CORE: Build the call graph
# ============================================================

class FuncInfo:
    __slots__ = ('ea', 'name', 'size', 'start_ea', 'end_ea',
                 'callees', 'callers', 'is_thunk', 'is_leaf', 'segment')

    def __init__(self, ea):
        self.ea = ea
        self.start_ea = ea
        self.name = idc.get_func_name(ea) or f"sub_{ea:X}"
        func = idaapi.get_func(ea)
        self.size = func.size() if func else 0
        self.end_ea = func.end_ea if func else ea
        self.callees = set()   # set of func_ea
        self.callers = set()   # set of func_ea
        self.is_thunk = False
        self.is_leaf = False
        self.segment = idc.get_segm_name(ea) or "?"


def is_call_insn(ea):
    """Check if instruction at ea is a call."""
    mnem = idc.print_insn_mnem(ea)
    return mnem in ('call', 'CALL', 'bl', 'BL')


def is_thunk_func(func_ea):
    """Check if function is a thunk (tail chunk or jump-only)."""
    flags = idc.get_func_flags(func_ea)
    if flags & idc.FUNC_THUNK:
        return True
    if flags & idc.FUNC_TAIL:
        return True
    return False


def get_segment_of(ea):
    return idc.get_segm_name(ea) or "?"


def build_full_graph():
    """Build the complete call graph for the IDB."""
    graph = {}
    total = len(list(idautils.Functions()))
    print(f"[*] Building call graph for {total} functions...")

    # Phase 1: Collect all function metadata
    for i, func_ea in enumerate(idautils.Functions()):
        if (i + 1) % 1000 == 0:
            print(f"    [{i+1}/{total}] Processing functions...")
        fi = FuncInfo(func_ea)
        fi.is_thunk = is_thunk_func(func_ea)
        graph[func_ea] = fi

    # Phase 2: Enumerate callees via FlowChart + instruction scan
    print("[*] Enumerating callees (FlowChart + insn scan)...")
    for i, (func_ea, fi) in enumerate(graph.items()):
        if (i + 1) % 1000 == 0:
            print(f"    [{i+1}/{len(graph)}] Scanning callees...")
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        try:
            flow = idaapi.FlowChart(func)
        except:
            continue
        for block in flow:
            ea = block.start_ea
            while ea < block.end_ea:
                if is_call_insn(ea):
                    target = idc.get_operand_value(ea, 0)
                    if target in graph:
                        fi.callees.add(target)
                ea = idc.next_head(ea, block.end_ea)

    # Phase 3: Build callers from callees (reverse edges)
    print("[*] Building caller lists...")
    for func_ea, fi in graph.items():
        for callee_ea in fi.callees:
            if callee_ea in graph:
                graph[callee_ea].callers.add(func_ea)

    # Phase 4: Mark leaf functions
    for fi in graph.values():
        fi.is_leaf = len(fi.callees) == 0

    print(f"[*] Graph built: {len(graph)} functions, "
          f"{sum(len(fi.callees) for fi in graph.values())} edges")
    return graph


# ============================================================
# SUBTREE: Depth-limited traversal from a root
# ============================================================

def resolve_func(name_or_addr):
    """Resolve a function name or hex address to an ea."""
    if isinstance(name_or_addr, str) and name_or_addr.startswith("0x"):
        return int(name_or_addr, 16)
    # Try as address first
    try:
        ea = int(name_or_addr, 16)
        if idaapi.get_func(ea):
            return ea
    except:
        pass
    # Try as name
    ea = idc.get_name_ea_simple(name_or_addr)
    if ea != idc.BADADDR and idaapi.get_func(ea):
        return ea
    return None


def build_subtree(graph, root_ea, max_depth):
    """Extract a subgraph around root_ea up to max_depth levels."""
    subtree = {}
    visited = set()

    def traverse(ea, depth):
        if ea in visited or ea not in graph:
            return
        visited.add(ea)
        fi = graph[ea]
        subtree[ea] = fi

        if max_depth > 0 and depth >= max_depth:
            return

        # Follow callees
        for callee in fi.callees:
            traverse(callee, depth + 1)

        # Follow callers (1 level up regardless of depth to show context)
        if depth == 0:
            for caller in fi.callers:
                if caller not in visited and caller in graph:
                    subtree[caller] = graph[caller]

    traverse(root_ea, 0)
    return subtree


# ============================================================
# FILTER
# ============================================================

def apply_filters(graph):
    """Apply configured filters and return filtered graph."""
    filtered = {}
    for ea, fi in graph.items():
        if NAME_FILTER and not re.search(NAME_FILTER, fi.name, re.IGNORECASE):
            continue
        if MIN_SIZE is not None and fi.size < MIN_SIZE:
            continue
        if MAX_SIZE is not None and fi.size > MAX_SIZE:
            continue
        if SEGMENT_FILTER and fi.segment not in SEGMENT_FILTER:
            continue
        if not INCLUDE_LEAVES and fi.is_leaf:
            continue
        if not INCLUDE_THUNKS and fi.is_thunk:
            continue
        filtered[ea] = fi
    return filtered


# ============================================================
# EXPORT: Markdown  (anchored / indexable)
# ============================================================

def md_sanitize(name):
    """Escape characters that break markdown tables / code spans."""
    return (name
            .replace('`', "'")
            .replace('|', '/')
            .replace('[', '(')
            .replace(']', ')')
            .replace('\n', ' '))


def md_anchor(ea):
    """Stable, address-based HTML anchor id for a function."""
    return f"func-{ea:X}"


def md_func_link(ea, graph):
    """Return a markdown link to a function's anchored section."""
    if ea in graph:
        fi = graph[ea]
        return f"[`{md_sanitize(fi.name)}` @ {hex(ea)}](#{md_anchor(ea)})"
    return f"`sub_{ea:X}` @ {hex(ea)}"


def export_markdown(graph, output_path):
    """Export the call graph to a Markdown file with address anchors + index tables."""
    print(f"[*] Writing Markdown to {output_path}")

    sorted_eas = sorted(graph.keys())
    total_funcs = len(graph)
    total_edges = sum(len(fi.callees) for fi in graph.values())

    # Build caller count ranking
    caller_ranking = sorted(graph.items(), key=lambda x: len(x[1].callers), reverse=True)

    # Alphabetical index by name
    name_index = sorted(graph.items(), key=lambda x: md_sanitize(x[1].name).lower())

    with open(output_path, 'w', encoding='utf-8') as f:

        # ---- Header / metadata ----
        f.write("# IDA Call Graph Export\n\n")
        f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}  \n")
        f.write(f"**Total Functions:** {total_funcs}  \n")
        f.write(f"**Total Call Edges:** {total_edges}  \n")
        f.write(f"**Binary:** {idc.get_input_file_path()}  \n\n")

        # ---- AI / human lookup guide ----
        if ANCHORED_MD:
            f.write("## Navigation Guide\n\n")
            f.write("Every function section starts with an HTML anchor keyed by address.\n")
            f.write("To jump to a function: `[#func-<HEXADDR>](#func-<HEXADDR>)`  \n")
            f.write("Example: [jump to TRIBE_Game::setup](#func-43AE90)\n\n")
            f.write("| Section | Purpose |\n")
            f.write("|---------|---------|\n")
            f.write("| [Name Index](#name-index-alphabetical) | Alphabetical lookup by demangled name |\n")
            f.write("| [Address Index](#address-index) | Sorted by address, for offset-based lookups |\n")
            f.write("| [Hotspot Functions](#hotspot-functions) | Most-called functions |\n")
            f.write("| [Function Details](#function-details) | Per-function caller/callee sections |\n\n")

        # ---- Name Index (alphabetical) ----
        f.write("## Name Index (alphabetical)\n\n")
        f.write("| Name | Address | Size | Segment | In | Out |\n")
        f.write("|------|---------|------|---------|----|-----|\n")
        for ea, fi in name_index:
            addr_link = f"[{hex(ea)}](#{md_anchor(ea)})"
            f.write(f"| [{md_sanitize(fi.name)}](#{md_anchor(ea)}) | {addr_link} | "
                   f"{fi.size} | {fi.segment} | {len(fi.callers)} | {len(fi.callees)} |\n")
        f.write("\n")

        # ---- Address Index ----
        f.write("## Address Index\n\n")
        f.write("| Address | Name | Size | Segment | In | Out | Type |\n")
        f.write("|---------|------|------|---------|----|-----|------|\n")
        for ea in sorted_eas:
            fi = graph[ea]
            ftype = "thunk" if fi.is_thunk else ("leaf" if fi.is_leaf else "normal")
            f.write(f"| [{hex(ea)}](#{md_anchor(ea)}) | [{md_sanitize(fi.name)}](#{md_anchor(ea)}) | "
                   f"{fi.size} | {fi.segment} | {len(fi.callers)} | {len(fi.callees)} | {ftype} |\n")
        f.write("\n")

        # ---- Hotspot ranking ----
        if TOP_N_CALLERS > 0:
            f.write("## Hotspot Functions (by caller count)\n\n")
            f.write("| Rank | Function | Address | Size | Callers | Callees |\n")
            f.write("|------|----------|---------|------|---------|--------|\n")
            for rank, (ea, fi) in enumerate(caller_ranking[:TOP_N_CALLERS], 1):
                f.write(f"| {rank} | [{md_sanitize(fi.name)}](#{md_anchor(ea)}) | "
                       f"[{hex(ea)}](#{md_anchor(ea)}) | {fi.size} | "
                       f"{len(fi.callers)} | {len(fi.callees)} |\n")
            f.write("\n")

        # ---- Function Details ----
        f.write("## Function Details\n\n")
        for ea in sorted_eas:
            fi = graph[ea]
            ftype = "thunk" if fi.is_thunk else ("leaf" if fi.is_leaf else "normal")

            # HTML anchor + heading
            f.write(f"<a id=\"{md_anchor(ea)}\"></a>\n")
            f.write(f"### `{md_sanitize(fi.name)}` — `{hex(ea)}` ({fi.size}B)\n\n")
            f.write(f"| Field | Value |\n")
            f.write(f"|-------|-------|\n")
            f.write(f"| Start | `{hex(fi.start_ea)}` |\n")
            f.write(f"| End | `{hex(fi.end_ea)}` |\n")
            f.write(f"| Size | {fi.size} bytes |\n")
            f.write(f"| Segment | {fi.segment} |\n")
            f.write(f"| Type | {ftype} |\n")
            f.write(f"| Callers (in) | {len(fi.callers)} |\n")
            f.write(f"| Callees (out) | {len(fi.callees)} |\n\n")

            if fi.callers:
                f.write("**Callers (who calls this):**\n\n")
                callers_sorted = sorted(fi.callers)
                shown = callers_sorted[:MAX_CALLERS_DISPLAY] if MAX_CALLERS_DISPLAY > 0 else callers_sorted
                f.write("| Caller | Address | Size |\n")
                f.write("|--------|---------|------|\n")
                for caller_ea in shown:
                    if caller_ea in graph:
                        cfi = graph[caller_ea]
                        f.write(f"| [{md_sanitize(cfi.name)}](#{md_anchor(caller_ea)}) | "
                               f"[{hex(caller_ea)}](#{md_anchor(caller_ea)}) | {cfi.size}B |\n")
                    else:
                        f.write(f"| `sub_{caller_ea:X}` | `{hex(caller_ea)}` | — |\n")
                if MAX_CALLERS_DISPLAY > 0 and len(callers_sorted) > MAX_CALLERS_DISPLAY:
                    f.write(f"| *(+ {len(callers_sorted) - MAX_CALLERS_DISPLAY} more)* | | |\n")
                f.write("\n")

            if fi.callees:
                f.write("**Callees (what this calls):**\n\n")
                callees_sorted = sorted(fi.callees)
                shown = callees_sorted[:MAX_CALLEES_DISPLAY] if MAX_CALLEES_DISPLAY > 0 else callees_sorted
                f.write("| Callee | Address | Size |\n")
                f.write("|--------|---------|------|\n")
                for callee_ea in shown:
                    if callee_ea in graph:
                        cfi = graph[callee_ea]
                        f.write(f"| [{md_sanitize(cfi.name)}](#{md_anchor(callee_ea)}) | "
                               f"[{hex(callee_ea)}](#{md_anchor(callee_ea)}) | {cfi.size}B |\n")
                    else:
                        f.write(f"| `sub_{callee_ea:X}` | `{hex(callee_ea)}` | — |\n")
                if MAX_CALLEES_DISPLAY > 0 and len(callees_sorted) > MAX_CALLEES_DISPLAY:
                    f.write(f"| *(+ {len(callees_sorted) - MAX_CALLEES_DISPLAY} more)* | | |\n")
                f.write("\n")

            f.write("---\n\n")

    print(f"[+] Markdown written: {output_path}")


# ============================================================
# EXPORT: Graphviz DOT
# ============================================================

def sanitize_dot_id(name):
    """Escape a string for use as a DOT node ID."""
    return name.replace('\\', '\\\\').replace('"', '\\"').replace('<', '\\<').replace('>', '\\>')


def export_dot(graph, output_path):
    """Export the call graph to Graphviz DOT format."""
    print(f"[*] Writing DOT to {output_path}")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("digraph callgraph {\n")
        f.write("    rankdir=LR;\n")
        f.write("    node [shape=record, fontname=\"Consolas\", fontsize=10];\n")
        f.write("    edge [arrowsize=0.6];\n\n")

        # Color scheme for node types
        f.write("    // Node definitions\n")
        for ea in sorted(graph.keys()):
            fi = graph[ea]
            node_id = f"f_{ea:X}"

            if fi.is_thunk:
                color = "lightyellow"
                style = "dashed"
            elif fi.is_leaf:
                color = "lightcyan"
                style = "solid"
            elif len(fi.callers) > 50:
                color = "tomato"
                style = "bold"
            elif len(fi.callers) > 10:
                color = "orange"
                style = "solid"
            else:
                color = "white"
                style = "solid"

            label = sanitize_dot_id(fi.name)
            # Truncate long names
            if len(label) > 60:
                label = label[:57] + "..."
            f.write(f'    {node_id} [label="{{{label}|{hex(ea)}|{fi.size}B|in:{len(fi.callers)} out:{len(fi.callees)}}}", '
                   f'style={style}, fillcolor={color}];\n')

        # Edge definitions
        f.write("\n    // Edges\n")
        for ea in sorted(graph.keys()):
            fi = graph[ea]
            for callee_ea in sorted(fi.callees):
                if callee_ea in graph:
                    f.write(f"    f_{ea:X} -> f_{callee_ea:X};\n")

        f.write("}\n")

    print(f"[+] DOT written: {output_path}")


# ============================================================
# EXPORT: JSON (intermediate / machine-readable)
# ============================================================

def export_json(graph, output_path):
    """Export the call graph as JSON."""
    print(f"[*] Writing JSON to {output_path}")

    data = {
        "metadata": {
            "binary": idc.get_input_file_path(),
            "generated": time.strftime('%Y-%m-%d %H:%M:%S'),
            "total_functions": len(graph),
            "total_edges": sum(len(fi.callees) for fi in graph.values()),
        },
        "functions": {}
    }

    for ea in sorted(graph.keys()):
        fi = graph[ea]
        data["functions"][hex(ea)] = {
            "name": fi.name,
            "start": hex(fi.start_ea),
            "end": hex(fi.end_ea),
            "size": fi.size,
            "segment": fi.segment,
            "is_thunk": fi.is_thunk,
            "is_leaf": fi.is_leaf,
            "callees": [hex(c) for c in sorted(fi.callees)],
            "callers": [hex(c) for c in sorted(fi.callers)],
            "callee_count": len(fi.callees),
            "caller_count": len(fi.callers),
        }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    print(f"[+] JSON written: {output_path}")


# ============================================================
# EXPORT: CSV (grep-friendly flat index)
# ============================================================

def export_csv(graph, output_path):
    """Export a flat CSV index for grep/awk/AI agent lookups."""
    print(f"[*] Writing CSV to {output_path}")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("address,name,size,segment,callers,callees,type,anchor\n")
        for ea in sorted(graph.keys()):
            fi = graph[ea]
            ftype = "thunk" if fi.is_thunk else ("leaf" if fi.is_leaf else "normal")
            name = md_sanitize(fi.name)
            f.write(f"{hex(ea)},{name},{fi.size},{fi.segment},"
                   f"{len(fi.callers)},{len(fi.callees)},{ftype},{md_anchor(ea)}\n")

    print(f"[+] CSV written: {output_path}")


# ============================================================
# MAIN
# ============================================================

def main():
    t0 = time.time()

    # Build the full graph
    graph = build_full_graph()

    # Apply filters
    if NAME_FILTER or MIN_SIZE or MAX_SIZE or SEGMENT_FILTER or not INCLUDE_LEAVES or not INCLUDE_THUNKS:
        graph = apply_filters(graph)
        print(f"[*] After filtering: {len(graph)} functions")

    # Subtree mode
    if MODE == "subtree":
        root_ea = resolve_func(ROOT_FUNC)
        if root_ea is None:
            print(f"[!] Could not resolve root function: {ROOT_FUNC}")
            return
        print(f"[*] Subtree mode: root = {hex(root_ea)} ({idc.get_func_name(root_ea)}), depth = {MAX_DEPTH}")
        graph = build_subtree(graph, root_ea, MAX_DEPTH)
        print(f"[*] Subtree contains {len(graph)} functions")

    # Export
    if MD_OUTPUT:
        export_markdown(graph, MD_OUTPUT)
    if DOT_OUTPUT:
        export_dot(graph, DOT_OUTPUT)
    if JSON_OUTPUT:
        export_json(graph, JSON_OUTPUT)
    if CSV_OUTPUT:
        export_csv(graph, CSV_OUTPUT)

    elapsed = time.time() - t0
    print(f"\n[*] Done in {elapsed:.1f}s")
    print(f"[*] Output files:")
    if MD_OUTPUT:
        print(f"    Markdown: {MD_OUTPUT}")
    if DOT_OUTPUT:
        print(f"    DOT:      {DOT_OUTPUT}")
        print(f"    To render: dot -Tpng \"{DOT_OUTPUT}\" -o callgraph.png")
        print(f"              dot -Tsvg \"{DOT_OUTPUT}\" -o callgraph.svg")
    if JSON_OUTPUT:
        print(f"    JSON:     {JSON_OUTPUT}")
    if CSV_OUTPUT:
        print(f"    CSV:      {CSV_OUTPUT}")
        print(f"    Grep:     grep \"0x5e7560\" \"{CSV_OUTPUT}\"")


if __name__ == "__main__":
    main()
