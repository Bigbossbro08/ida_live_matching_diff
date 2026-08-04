import ida_funcs
import ida_name
import ida_bytes
import idautils
import json
import os

def export_baseline(output_path):
    print("Exporting baseline functions...")
    functions = {}
    
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        name = ida_name.get_name(ea)
        
        # Skip compiler-generated or generic subroutines if desired,
        # but for now we export everything that has a name.
        if name and not name.startswith("sub_"):
            # Get function bytes
            size = func.end_ea - func.start_ea
            # Read bytes using ida_bytes
            try:
                raw_bytes = ida_bytes.get_bytes(func.start_ea, size)
                if raw_bytes:
                    hex_bytes = raw_bytes.hex()
                    functions[name] = {
                        "ea": hex(func.start_ea),
                        "size": size,
                        "bytes": hex_bytes
                    }
            except Exception as e:
                print("Failed to read {}: {}".format(name, e))

    try:
        with open(output_path, "w") as f:
            json.dump(functions, f, indent=2)
        print("Successfully exported {} functions to {}".format(len(functions), output_path))
    except Exception as e:
        print("Failed to write JSON: {}".format(e))

if __name__ == "__main__":
    out_path = r"d:\repos\rogan2\tools\matcher\baseline.json"
    export_baseline(out_path)
