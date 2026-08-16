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

from ida_matcher.matcher import match_summary, match_focus, _configure_colors


def main():
    parser = argparse.ArgumentParser(
        prog="ida-match",
        description="Match a compiled .obj file against a live IDA database.",
    )
    parser.add_argument("obj_file", help="Path to the .obj file")
    parser.add_argument("--func", help="Focus on a specific function (mangled name)")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable JSON summary")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when any recognized function is below 100%% (CI gate)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not os.path.exists(args.obj_file):
        print(f"Error: {args.obj_file} not found.")
        sys.exit(1)

    _configure_colors(not (args.no_color or os.environ.get("NO_COLOR")))

    obj_path = Path(args.obj_file)
    print(f"Running match on {obj_path.name}...")
    if args.func:
        match_focus(obj_path, args.func)
    else:
        sys.exit(match_summary(obj_path, json_out=args.json, strict=args.strict))


if __name__ == "__main__":
    main()