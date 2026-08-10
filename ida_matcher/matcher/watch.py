"""
ida_matcher.matcher.watch
~~~~~~~~~~~~~~~~~~~
Watch an .obj file for changes and re-run the matcher on every modification.

Usage:
    ida-watch <file.obj> [--func name] [--no-color]
"""
import os
import sys
import argparse
import time
from pathlib import Path

from ida_matcher.matcher import match_summary, match_focus, _configure_colors


def _get_stat(filepath):
    """(mtime, size) tuple so same-second rebuilds still trigger a re-match."""
    try:
        st = os.stat(filepath)
        return (st.st_mtime, st.st_size)
    except FileNotFoundError:
        return (0, 0)


def _match(obj_path, target_func):
    """Run the matcher. Returns True on success, False on a (recoverable) failure."""
    print(f"\n[{time.strftime('%H:%M:%S')}] Matching {obj_path.name}...")
    try:
        if target_func:
            match_focus(obj_path, target_func)
        else:
            match_summary(obj_path)
        return True
    except SystemExit:
        # e.g. function not found / server unreachable - keep watching, do not die
        return False


def main():
    parser = argparse.ArgumentParser(
        prog="ida-watch",
        description="Watch a compiled .obj file and re-match against IDA on every rebuild.",
    )
    parser.add_argument("obj_file", help="Path to the .obj file to watch")
    parser.add_argument("--func", help="Focus on a specific function (mangled name)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not os.path.exists(args.obj_file):
        print(f"Error: {args.obj_file} not found.")
        sys.exit(1)

    _configure_colors(not (args.no_color or os.environ.get("NO_COLOR")))

    obj_path = Path(args.obj_file)
    target_func = args.func

    if target_func:
        print(f"Watching {args.obj_file} for changes, targeting {target_func} (Press Ctrl+C to stop)...")
    else:
        print(f"Watching {args.obj_file} for changes (Press Ctrl+C to stop)...")

    last_stat = _get_stat(args.obj_file)

    # Initial match
    _match(obj_path, target_func)

    try:
        while True:
            time.sleep(1.0)
            current_stat = _get_stat(args.obj_file)
            if current_stat != last_stat:
                last_stat = current_stat
                _match(obj_path, target_func)
    except KeyboardInterrupt:
        print("\nStopped watching.")


if __name__ == "__main__":
    main()
