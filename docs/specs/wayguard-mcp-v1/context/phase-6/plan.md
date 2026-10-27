# Phase 6 plan
- New `src/wayguard/mcp_server.py`: low-level MCP `Server` (stdio), `WayguardService` (policy loaded once, gate, sink), five tools, deny-all mode, `serve(root)`.
- `cli.py`: `serve` subcommand, lazy import, root from module-level `default_root`.
- `tests/test_mcp_server.py`: in-memory SDK session tests + one real-subprocess stdout-hygiene test.
- Gate: no dimension above manifest scoring (no new deps, SDK already declared).
