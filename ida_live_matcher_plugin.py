import ida_idaapi
import ida_kernwin
import sys

class LiveMatcherPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "IDA Live Matcher Server"
    help = "Starts the live matching server for decomp workflows"
    wanted_name = "Live Matcher"
    wanted_hotkey = ""

    def init(self):
        try:
            from ida_matcher.matcher import ida_server
            ida_server.start_server()
            return ida_idaapi.PLUGIN_KEEP
        except ImportError:
            print("Live Matcher Plugin: Error - ida_matcher is not installed in IDAs Python environment.")
            return ida_idaapi.PLUGIN_SKIP

    def run(self, arg):
        try:
            from ida_matcher.matcher import ida_server
            if ida_server.SERVER_SOCKET:
                print("Live Matcher is already running.")
            else:
                ida_server.start_server()
        except ImportError:
            print("Live Matcher Plugin: Error - ida_matcher is not installed.")

    def term(self):
        try:
            from ida_matcher.matcher import ida_server
            ida_server.stop_server()
        except Exception:
            pass

def PLUGIN_ENTRY():
    return LiveMatcherPlugin()
