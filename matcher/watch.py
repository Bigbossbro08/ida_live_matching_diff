"""
tools.matcher.watch
~~~~~~~~~~~~~~~~~~~
Watch a .cpp file for changes and re-run the matcher on every save.

Usage:
    python -m tools.matcher.watch <file.cpp> [func_name]
"""
import sys
import os
import time

from tools.compiler import build_obj_for_match, get_obj_path
from tools.matcher import match_summary, match_focus


def _get_mtime(filepath):
    try:
        return os.path.getmtime(filepath)
    except FileNotFoundError:
        return 0


def _build_and_match(cpp_file, obj_path, target_func):
    """Build the .obj and run the matcher.  Returns True on success."""
    print(f"\n[{time.strftime('%H:%M:%S')}] Building {cpp_file}...")
    try:
        build_obj_for_match(cpp_file)
    except RuntimeError as exc:
        print(f"Build failed: {exc}")
        return False

    if target_func:
        match_focus(obj_path, target_func)
    else:
        match_summary(obj_path)
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m tools.matcher.watch <file.cpp> [func_name]")
        sys.exit(1)

    watch_file = sys.argv[1]
    target_func = sys.argv[2] if len(sys.argv) >= 3 else None

    if not os.path.exists(watch_file):
        print(f"Error: {watch_file} not found.")
        sys.exit(1)

    obj_path = get_obj_path(watch_file)

    if target_func:
        print(f"Watching {watch_file} for changes, targeting {target_func} (Press Ctrl+C to stop)...")
    else:
        print(f"Watching {watch_file} for changes (Press Ctrl+C to stop)...")

    last_mtime = _get_mtime(watch_file)

    # Initial build + match
    _build_and_match(watch_file, obj_path, target_func)

    try:
        while True:
            time.sleep(1.0)
            current_mtime = _get_mtime(watch_file)
            if current_mtime > last_mtime:
                last_mtime = current_mtime
                _build_and_match(watch_file, obj_path, target_func)
    except KeyboardInterrupt:
        print("\nStopped watching.")


if __name__ == "__main__":
    main()
