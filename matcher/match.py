"""
Compatibility shim – all logic has moved to tools.matcher.match_core.

This file is kept so that any existing scripts that do
``python tools/matcher/match.py <obj>`` continue to work.
"""
from tools.matcher.match_core import *   # noqa: F401,F403
from tools.matcher.match_core import main

if __name__ == "__main__":
    main()