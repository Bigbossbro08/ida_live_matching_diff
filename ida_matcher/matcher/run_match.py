"""
ida_matcher.matcher.run_match
~~~~~~~~~~~~~~~~~~~~~~~
Run the matcher once against a pre-compiled .obj file (no watch loop).

Usage:
    ida-match <file.obj> [--func ?name@@YAXXZ] [--json] [--no-color]
"""
import os
import sys
import argparse
from pathlib import Path

from ida_matcher.matcher.match_core import match_summary, match_focus, find_similar_code_symbols
from ida_matcher.matcher.engine.display import _configure_colors
from ida_matcher.matcher.config import load_config_mappings, load_config_reloc_mappings


def main():
    parser = argparse.ArgumentParser(
        prog="ida-match",
        description="Match a compiled .obj file against a live IDA database.",
    )
    parser.add_argument("obj_file", help="Path to the .obj file")
    parser.add_argument("--func", help="Focus on a specific function (mangled name)")
    parser.add_argument("--similar", help="Find similar functions in IDA for this symbol")
    parser.add_argument("--config", help="Path to ida_watch.json config file for manual symbol mappings")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable JSON summary")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when any recognized function is below 100%% (CI gate)")
    parser.add_argument("--parser", choices=["auto", "lief", "pure"], default="auto",
                        help="COFF .obj parser backend (auto = LIEF when available)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--baseline", help="Path to a baseline.json file for offline matching (no IDA server needed)")
    parser.add_argument("--reloc-mode", choices=["none", "nameaddress", "datavalue", "all"], default="nameaddress",
                        help="Relocation comparison mode (default: nameaddress)")
    args = parser.parse_args()

    if not os.path.exists(args.obj_file):
        print(f"Error: {args.obj_file} not found.")
        sys.exit(1)

    _configure_colors(not (args.no_color or os.environ.get("NO_COLOR")))

    # Map CLI arg to match_core constant
    reloc_mode_map = {
        "none": "none",
        "nameaddress": "name_address",
        "datavalue": "data_value",
        "all": "all"
    }
    reloc_mode = reloc_mode_map[args.reloc_mode]

    obj_path = Path(args.obj_file)
    mappings_config = None
    if args.config:
        mappings_config = {"mappings": load_config_mappings(Path(args.config), obj_path),
                           "reloc_mappings": load_config_reloc_mappings(Path(args.config), obj_path)}

    baseline = None
    if args.baseline:
        if not os.path.exists(args.baseline):
            print(f"Error: baseline file {args.baseline} not found.")
            sys.exit(1)
        import json
        with open(args.baseline, "r") as f:
            baseline = json.load(f)
        
    print(f"Running match on {obj_path.name}...")
    if args.similar:
        sys.exit(find_similar_code_symbols(obj_path, args.similar, parser=args.parser, reloc_mode=reloc_mode))
    elif args.func:
        match_focus(obj_path, args.func, parser=args.parser, reloc_mode=reloc_mode, mappings_config=mappings_config, baseline=baseline)
    else:
        sys.exit(match_summary(obj_path, json_out=args.json, strict=args.strict, parser=args.parser, reloc_mode=reloc_mode, mappings_config=mappings_config, baseline=baseline))


if __name__ == "__main__":
    main()