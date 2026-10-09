# Vendored into the repo (Phase 7) so the `ida-cli match` bridge is versioned
# rather than living only in ~/.ida-cli/plugins/. Install by copying this file
# to ~/.ida-cli/plugins/ida_matcher_plugin.py (see plugins/README.md).
"""
IDA Matcher Plugin for IDA-CLI
Exposes ida_live_matching_diff (ida-match) functionality as ida-cli subcommands.

Routes all IDA data-fetch operations through ida-cli's instance discovery and
RPC transport (port 28100) instead of the standalone port 28000 server.
The ida_live_matcher_plugin.py / port 28000 server is NO LONGER required.

Installation:
    Place this file in ~/.ida-cli/plugins/ida_matcher_plugin.py
    (Requires: pip install ida_matcher)

Subcommands added:
    ida-cli match <obj>                     Summary match of all functions
    ida-cli match <obj> --func SYM          Side-by-side diff for one function
    ida-cli match <obj> --similar SYM       Rank IDA functions by similarity
    ida-cli match <obj> --baseline bl.json  Offline match (no IDA needed)
    ida-cli match-watch <obj>               [LEGACY] Watch mode - kept for future use
"""

import contextlib
import json
import os
import sys
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
#  Server-side handlers  (registered into ida-cli's RPC, run inside IDA Pro)
# ─────────────────────────────────────────────────────────────────────────────

def register_server(command_registry):
    """
    Called by ida-cli's server.py (inside IDA Pro) to register ida_logic
    handlers as first-class RPC commands.

    Each handler is (func, doc, needs_sync_wrap=True) so that execute_on_main_thread
    is applied automatically — all ida_logic calls need IDA's main thread.
    """
    try:
        from ida_matcher.matcher import ida_logic as _il  # noqa: verify importable at startup
    except ImportError:
        # ida_matcher not installed in IDA's Python environment - skip silently.
        # The user still needs to install it inside IDA's Python; we just don't crash.
        return

    # ── Individual function / data lookups ───────────────────────────────────

    def match_get_func(name):
        from ida_matcher.matcher import ida_logic as il
        result = il.get_function_bytes(name)
        return result if result else {}

    def match_get_funcs(names):
        """Batch code-symbol lookup.  `names` may be a list or comma-joined string."""
        from ida_matcher.matcher import ida_logic as il
        if isinstance(names, str):
            names = [n for n in names.split(",") if n]
        return {"results": {n: il.get_function_bytes(n) for n in names}}

    def match_get_data(name):
        from ida_matcher.matcher import ida_logic as il
        result = il.get_data_bytes(name)
        return result if result else {}

    def match_get_datas(names):
        """Batch data-symbol lookup.  `names` may be a list or comma-joined string."""
        from ida_matcher.matcher import ida_logic as il
        if isinstance(names, str):
            names = [n for n in names.split(",") if n]
        return {"results": {n: il.get_data_bytes(n) for n in names}}

    # ── Cache management ─────────────────────────────────────────────────────

    def match_refresh():
        from ida_matcher.matcher import ida_logic as il
        il.build_cache()
        return {"status": "refreshed"}

    def match_all_names():
        from ida_matcher.matcher import ida_logic as il
        if not il.FUNC_CACHE:
            il.build_cache()
        return {"names": list(il.FUNC_CACHE.keys())}

    # ── Offline baseline export ───────────────────────────────────────────────

    def match_get_baseline():
        from ida_matcher.matcher import ida_logic as il
        return il.get_baseline()

    # Register all handlers.  needs_sync_wrap=True → execute_on_main_thread().
    for _name, _fn, _doc in [
        ("match_get_func",     match_get_func,     "Get function bytes + fixups from IDA (ida-matcher)"),
        ("match_get_funcs",    match_get_funcs,    "Batch-fetch function records from IDA (ida-matcher)"),
        ("match_get_data",     match_get_data,     "Get data-symbol bytes from IDA (ida-matcher)"),
        ("match_get_datas",    match_get_datas,    "Batch-fetch data records from IDA (ida-matcher)"),
        ("match_refresh",      match_refresh,      "Rebuild IDA name→address cache (ida-matcher)"),
        ("match_all_names",    match_all_names,    "List all IDA function names (ida-matcher)"),
        ("match_get_baseline", match_get_baseline, "Export full function baseline from IDA (ida-matcher)"),
    ]:
        command_registry[_name] = (_fn, _doc, True)


# ─────────────────────────────────────────────────────────────────────────────
#  Client-side: monkey-patch match_core to route through ida-cli's RPC
# ─────────────────────────────────────────────────────────────────────────────

@contextlib.contextmanager
def _patch_match_core(client):
    """
    Context manager that temporarily replaces match_core's HTTP-to-port-28000
    fetch functions with wrappers that call through `client` (ida-cli RPC).

    Python resolves module-global names at call time, so patching the module
    attributes is sufficient — match_summary / match_focus pick up the new
    functions automatically.
    """
    try:
        import ida_matcher.matcher.match_core as mc
    except ImportError:
        print(
            "Error: ida_matcher is not installed.\n"
            "Install it with:  pip install ida_matcher\n"
            "or from source:   pip install -e <path/to/ida_live_matching_diff> --no-build-isolation",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Wrapper builders ─────────────────────────────────────────────────────

    def p_server_alive():
        try:
            client.get_status()
            return True
        except Exception:
            return False

    def p_refresh_ida_cache():
        try:
            client.run_command("match_refresh", {})
        except Exception:
            pass

    def p_fetch_from_ida(func_name):
        try:
            r = client.run_command("match_get_func", {"name": func_name})
            return r if r and "bytes" in r else None
        except Exception:
            return None

    def p_fetch_many_from_ida(names):
        if not names:
            return {}
        try:
            r = client.run_command("match_get_funcs", {"names": list(names)})
            return {k: v for k, v in (r.get("results") or {}).items() if v is not None}
        except Exception:
            # Graceful fallback: fetch one-by-one
            out = {}
            for n in names:
                rec = p_fetch_from_ida(n)
                if rec is not None:
                    out[n] = rec
            return out

    def p_fetch_data_from_ida(name):
        try:
            r = client.run_command("match_get_data", {"name": name})
            return r if r and "bytes" in r else None
        except Exception:
            return None

    def p_fetch_many_data_from_ida(names):
        if not names:
            return {}
        try:
            r = client.run_command("match_get_datas", {"names": list(names)})
            return {k: v for k, v in (r.get("results") or {}).items() if v is not None}
        except Exception:
            out = {}
            for n in names:
                rec = p_fetch_data_from_ida(n)
                if rec is not None:
                    out[n] = rec
            return out

    def p_fetch_all_names_from_ida():
        try:
            r = client.run_command("match_all_names", {})
            return r.get("names", [])
        except Exception:
            return []

    # ── Apply patches ────────────────────────────────────────────────────────
    patches = {
        "server_alive":             p_server_alive,
        "refresh_ida_cache":        p_refresh_ida_cache,
        "fetch_from_ida":           p_fetch_from_ida,
        "fetch_many_from_ida":      p_fetch_many_from_ida,
        "fetch_data_from_ida":      p_fetch_data_from_ida,
        "fetch_many_data_from_ida": p_fetch_many_data_from_ida,
        "fetch_all_names_from_ida": p_fetch_all_names_from_ida,
    }

    originals = {k: getattr(mc, k) for k in patches}
    for k, v in patches.items():
        setattr(mc, k, v)
    try:
        yield mc
    finally:
        for k, v in originals.items():
            setattr(mc, k, v)


# ─────────────────────────────────────────────────────────────────────────────
#  Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

_RELOC_MODE_MAP = {
    "none":        "none",
    "nameaddress": "name_address",
    "datavalue":   "data_value",
    "all":         "all",
}


def _configure_colors(args):
    try:
        from ida_matcher.matcher.engine.display import _configure_colors as _cc
        _cc(not getattr(args, "no_color", False))
    except Exception:
        pass


def _load_mappings_config(args, obj_path):
    cfg_path = getattr(args, "config", None)
    if not cfg_path:
        return None
    try:
        from ida_matcher.matcher.config import load_config_mappings, load_config_reloc_mappings
        p = Path(cfg_path)
        return {
            "mappings":       load_config_mappings(p, obj_path),
            "reloc_mappings": load_config_reloc_mappings(p, obj_path),
        }
    except ImportError:
        print("Warning: ida_matcher.matcher.config unavailable; ignoring --config.", file=sys.stderr)
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  CLI command: match
# ─────────────────────────────────────────────────────────────────────────────

def _cmd_match_all(args, all_dir: str):
    """Batch match all .obj files in a directory and write match_report.json."""
    from ida_cli.cli import get_client
    dir_path = Path(all_dir)
    if not dir_path.exists():
        print(f"Error: directory '{dir_path}' not found.", file=sys.stderr)
        sys.exit(1)

    obj_files = sorted(dir_path.glob("*.obj"))
    if not obj_files:
        print(f"No .obj files found in {dir_path}", file=sys.stderr)
        sys.exit(1)

    try:
        from ida_matcher.matcher.match_core import match_summary
    except ImportError:
        print("Error: ida_matcher is not installed.", file=sys.stderr)
        sys.exit(1)

    client = get_client(args.instance)
    reloc_mode = _RELOC_MODE_MAP[getattr(args, "reloc_mode", "nameaddress")]
    parser_backend = getattr(args, "parser", "auto")
    report = {}
    total_pct = 0.0
    n = 0

    print(f"Batch matching {len(obj_files)} .obj files in {dir_path}...")
    with _patch_match_core(client) as mc:
        for obj_path in obj_files:
            print(f"  {obj_path.name}...", end=" ", flush=True)
            try:
                result = mc.match_summary(
                    obj_path,
                    json_out=True,
                    strict=False,
                    parser=parser_backend,
                    reloc_mode=reloc_mode,
                )
                if isinstance(result, dict):
                    pct = result.get("object", {}).get("match_percent", 0.0)
                    print(f"{pct:.1f}%")
                    report[obj_path.name] = result
                    total_pct += pct
                    n += 1
                else:
                    print("(no data)")
                    report[obj_path.name] = {}
            except Exception as e:
                print(f"ERROR: {e}")
                report[obj_path.name] = {"error": str(e)}

    out_path = dir_path / "match_report.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    avg = total_pct / n if n else 0.0
    print(f"\nDone. Average match: {avg:.1f}%  Report: {out_path}")


def cmd_match(args):
    """
    Entry point for `ida-cli match`.

    Modes (driven by flags):
        (default)    Summary match of all functions in <obj>
        --sym SYM    Side-by-side instruction diff for one function
        --similar SYM  Rank every IDA function by match% against SYM
        --baseline   Fully offline match against an exported baseline JSON
        --all [DIR]  Batch match every .obj in DIR, write match_report.json

    NOTE: uses args.sym (not args.func) to avoid collision with ida-cli's
    internal args.func subcommand-dispatch attribute.
    """
    from ida_cli.cli import get_client

    # ── Batch-all mode ────────────────────────────────────────────────────────
    all_dir = getattr(args, "match_all_dir", None)
    if all_dir is not None:
        _cmd_match_all(args, all_dir)
        return

    if not args.obj:
        print("Error: specify a .obj file or use --all <dir> for batch mode.", file=sys.stderr)
        sys.exit(1)
    obj_path = Path(args.obj)
    if not obj_path.exists():
        print(f"Error: {obj_path} not found.", file=sys.stderr)
        sys.exit(1)

    _configure_colors(args)
    reloc_mode = _RELOC_MODE_MAP[getattr(args, "reloc_mode", "nameaddress")]
    parser_backend = getattr(args, "parser", "auto")
    mappings_config = _load_mappings_config(args, obj_path)
    target_sym = getattr(args, "sym", None)   # --sym; not args.func (reserved by ida-cli)

    # ── Offline baseline mode: no IDA connection required ────────────────────
    baseline = None
    if getattr(args, "baseline", None):
        bl_path = Path(args.baseline)
        if not bl_path.exists():
            print(f"Error: baseline file {bl_path} not found.", file=sys.stderr)
            sys.exit(1)
        with open(bl_path) as f:
            baseline = json.load(f)

    if baseline is not None:
        try:
            from ida_matcher.matcher.match_core import (
                match_summary, match_focus, find_similar_code_symbols
            )
        except ImportError:
            print("Error: ida_matcher is not installed.", file=sys.stderr)
            sys.exit(1)
        if not args.json:
            print(f"Running offline match on {obj_path.name}...")
        if getattr(args, "similar", None):
            sys.exit(find_similar_code_symbols(
                obj_path, args.similar, parser=parser_backend, reloc_mode=reloc_mode
            ))
        elif target_sym:
            match_focus(
                obj_path, target_sym,
                parser=parser_backend, reloc_mode=reloc_mode,
                mappings_config=mappings_config, baseline=baseline,
            )
        else:
            sys.exit(match_summary(
                obj_path,
                json_out=args.json, strict=getattr(args, "strict", False),
                parser=parser_backend, reloc_mode=reloc_mode,
                mappings_config=mappings_config, baseline=baseline,
            ))
        return

    # ── Live mode: route through ida-cli instance ─────────────────────────────
    client = get_client(args.instance)

    with _patch_match_core(client) as mc:
        if not args.json:
            print(f"Running match on {obj_path.name}...")
        if getattr(args, "similar", None):
            sys.exit(mc.find_similar_code_symbols(
                obj_path, args.similar,
                parser=parser_backend, reloc_mode=reloc_mode,
            ))
        elif target_sym:
            mc.match_focus(
                obj_path, target_sym,
                parser=parser_backend, reloc_mode=reloc_mode,
                mappings_config=mappings_config,
            )
        else:
            sys.exit(mc.match_summary(
                obj_path,
                json_out=args.json, strict=getattr(args, "strict", False),
                parser=parser_backend, reloc_mode=reloc_mode,
                mappings_config=mappings_config,
            ))


# ─────────────────────────────────────────────────────────────────────────────
#  CLI command: match-watch  [LEGACY – kept for future use, not actively maintained]
# ─────────────────────────────────────────────────────────────────────────────

def cmd_baseline_export(args):
    """Export the full IDA function/data cache to a baseline.json for offline matching."""
    from ida_cli.cli import get_client
    client = get_client(args.instance)
    print(f"Exporting baseline from IDA... (this may take a moment)")
    res = client.run_command("match_get_baseline")
    out_path = Path(args.output)
    out_path.write_text(json.dumps(res, indent=2), encoding="utf-8")
    n_funcs = len(res.get("functions", res) if isinstance(res, dict) else res)
    print(f"Baseline exported to {out_path}  ({n_funcs} entries)")


def cmd_match_watch_legacy(args):
    """
    [LEGACY] Watch a .obj file for changes and re-run match automatically.

    This command is kept for historical reference but is no longer actively
    maintained.  For advanced watch features (config-driven builds, per-unit
    rebuilds, objdiff-style watch patterns) use `ida-watch` from the
    ida_live_matching_diff package directly.
    """
    import time

    obj_path = Path(args.obj)
    if not obj_path.exists():
        print(f"Error: {obj_path} not found.", file=sys.stderr)
        sys.exit(1)

    from ida_cli.cli import get_client
    client = get_client(args.instance)

    reloc_mode = _RELOC_MODE_MAP[getattr(args, "reloc_mode", "nameaddress")]
    target_sym = getattr(args, "sym", None)   # --sym; not args.func (reserved by ida-cli)
    _configure_colors(args)

    print(f"[match-watch LEGACY] Watching {obj_path.name}... (Ctrl+C to stop)")
    print("[match-watch LEGACY] For advanced watch features, use: ida-watch <obj>")

    def _get_stat(path):
        try:
            st = os.stat(path)
            return (st.st_mtime, st.st_size)
        except FileNotFoundError:
            return (0, 0)

    last_stat = (0, 0)

    while True:
        try:
            stat = _get_stat(obj_path)
            if stat != last_stat and stat != (0, 0):
                last_stat = stat
                ts = time.strftime("%H:%M:%S")
                print(f"\n[{ts}] Matching {obj_path.name}...")
                with _patch_match_core(client) as mc:
                    try:
                        if target_sym:
                            mc.match_focus(obj_path, target_sym, reloc_mode=reloc_mode)
                        else:
                            mc.match_summary(obj_path, reloc_mode=reloc_mode)
                    except SystemExit:
                        pass  # match_summary may sys.exit(0) on strict; keep watching
            time.sleep(1)
        except KeyboardInterrupt:
            print("\n[match-watch] Stopped.")
            break


# ─────────────────────────────────────────────────────────────────────────────
#  Plugin registration
# ─────────────────────────────────────────────────────────────────────────────

def register_cli(subparsers, common_parser):
    """Register ida-matcher subcommands into ida-cli."""

    # ── ida-cli match ─────────────────────────────────────────────────────────
    p_match = subparsers.add_parser(
        "match",
        parents=[common_parser],
        help="Match a compiled .obj against the live IDA database",
    )
    p_match.add_argument(
        "obj",
        nargs="?",
        default=None,
        help="Path to the compiled .obj file (required unless --all is used)",
    )
    p_match.add_argument(
        "--sym",
        metavar="SYM",
        dest="sym",
        help="Focus: side-by-side diff for one mangled symbol",
    )
    p_match.add_argument(
        "--similar",
        metavar="SYM",
        help="Similarity search: rank IDA functions by match%% against SYM",
    )
    p_match.add_argument(
        "--baseline",
        metavar="FILE",
        help="Offline match against a baseline.json (no IDA connection needed)",
    )
    p_match.add_argument(
        "--config",
        metavar="FILE",
        help="ida_watch.json config for manual symbol / reloc mappings",
    )
    p_match.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any function is below 100%% (CI gate)",
    )
    p_match.add_argument(
        "--parser",
        choices=["auto", "lief", "pure"],
        default="auto",
        help="COFF .obj parser backend (default: auto)",
    )
    p_match.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
        help="Disable ANSI colours",
    )
    p_match.add_argument(
        "--reloc-mode",
        dest="reloc_mode",
        choices=["none", "nameaddress", "datavalue", "all"],
        default="nameaddress",
        help="Relocation comparison strictness (default: nameaddress)",
    )
    p_match.add_argument(
        "--all",
        metavar="DIR",
        dest="match_all_dir",
        nargs="?",
        const="build/BinaryMatching",
        help="Batch match all .obj in DIR (default: build/BinaryMatching); writes match_report.json",
    )
    p_match.set_defaults(func=cmd_match)

    # ── ida-cli match-watch  [LEGACY] ─────────────────────────────────────────
    p_watch = subparsers.add_parser(
        "match-watch",
        parents=[common_parser],
        help="[LEGACY] Watch a .obj for changes and re-run match automatically",
    )
    p_watch.add_argument("obj", help="Path to the compiled .obj file")
    p_watch.add_argument(
        "--sym",
        metavar="SYM",
        dest="sym",
        help="Focus on one mangled symbol",
    )
    p_watch.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
    )
    p_watch.add_argument(
        "--reloc-mode",
        dest="reloc_mode",
        choices=["none", "nameaddress", "datavalue", "all"],
        default="nameaddress",
    )
    p_watch.set_defaults(func=cmd_match_watch_legacy)

    # ── ida-cli baseline-export  [convenience] ────────────────────────────────
    p_bl = subparsers.add_parser(
        "baseline-export",
        parents=[common_parser],
        help="Export the full IDA function cache to a baseline JSON file (offline matching)",
    )
    p_bl.add_argument(
        "--output", "-o",
        default="baseline.json",
        help="Output file path (default: baseline.json)",
    )
    p_bl.set_defaults(func=cmd_baseline_export)
