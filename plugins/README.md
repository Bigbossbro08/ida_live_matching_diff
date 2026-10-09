# plugins — ida-cli bridge (versioned)

This directory versions the `ida-cli` plugin that exposes the matcher to
`ida-cli` commands. Previously this file lived only in the user profile
(`~/.ida-cli/plugins/ida_matcher_plugin.py`) and was not tracked anywhere.

## Install

Copy the plugin into ida-cli's user plugin directory:

```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.ida-cli\plugins" | Out-Null
Copy-Item .\plugins\ida_matcher_plugin.py "$env:USERPROFILE\.ida-cli\plugins\ida_matcher_plugin.py" -Force
```

Restart IDA (or reload the ida-cli plugin) afterward.

## What it provides

- **Client CLI**: `ida-cli match <obj> [--sym SYM] [--config ida_watch.json]
  [--strict] [--reloc-mode ...]`, `ida-cli match-watch`, `ida-cli baseline-export`.
- **Server commands** (registered into ida-cli's RPC when `ida_matcher` is
  importable in IDA's Python): `match_get_func`, `match_get_funcs`,
  `match_get_data`, `match_get_datas`, `match_refresh`, `match_all_names`,
  `match_get_baseline`.

## Transport

The plugin monkey-patches `match_core` to route IDA lookups through ida-cli's
RPC. As of Phase 7 the standalone matcher client also resolves its endpoint via
`ida_matcher/matcher/transport.py` (env `IDA_MATCHER_URL` → live ida-cli
instance discovery → legacy `:28000`), so plain `ida-match`/`ida-watch` pick up
the running connector without the plugin. The monkey-patch remains for the
`ida-cli match` path.

## Migrating off port 28000

With the ida-cli connector running, the legacy `ida_server.py` on `:28000` is no
longer required: ida-cli serves the same routes (`/func`, `/funcs`, `/data`,
`/datas`, `/all_names`, `/baseline`, `/refresh`, `/synthetic_obj`). Set
`IDA_MATCHER_URL=http://127.0.0.1:<ida-cli-port>` to pin a specific instance.
