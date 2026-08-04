import sys
import os
MATCHER_DIR = r"d:\repos\rogan2\tools\matcher"
if MATCHER_DIR not in sys.path:
    sys.path.insert(0, MATCHER_DIR)

import ida_logic
res = ida_logic.get_function_bytes("?inRange@RGE_Action_Move_To@@QAEHXZ")
print("RESULT:", res)
