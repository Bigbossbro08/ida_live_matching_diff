"""
Compatibility shim – all logic has moved to ida_matcher.matcher.match_core.

This file is kept so that any existing scripts that do
``python -m ida_matcher.matcher.match <obj>`` continue to work.
"""
from ida_matcher.matcher.match_core import *   # noqa: F401,F403
from ida_matcher.matcher.match_core import main

if __name__ == "__main__":
    main()