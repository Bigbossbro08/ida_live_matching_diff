"""
tools.matcher.run_match
~~~~~~~~~~~~~~~~~~~~~~~
Build a single .cpp file and run the matcher once (no watch loop).

Usage:
    python -m tools.matcher.run_match <file.cpp> [func_name]
"""
import sys
import os

from tools.compiler import build_obj_for_match, get_obj_path
from tools.matcher import match_summary, match_focus


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m tools.matcher.run_match <file.cpp> [func_name]")
        sys.exit(1)

    cpp_file = sys.argv[1]
    target_func = sys.argv[2] if len(sys.argv) >= 3 else None

    if not os.path.exists(cpp_file):
        print(f"Error: {cpp_file} not found.")
        sys.exit(1)

    print(f"Building {cpp_file} via build.cmd --mode obj...")
    try:
        build_obj_for_match(cpp_file)
    except RuntimeError as exc:
        print(f"Build failed: {exc}")
        sys.exit(1)

    obj_path = get_obj_path(cpp_file)
    if not obj_path.exists():
        print(f"Error: Expected object file {obj_path} was not found.")
        sys.exit(1)

    print(f"Running match on {obj_path.name}...")
    if target_func:
        match_focus(obj_path, target_func)
    else:
        match_summary(obj_path)


if __name__ == "__main__":
    main()
