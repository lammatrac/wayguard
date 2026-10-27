# Phase 1 plan

Greenfield. Files (in worktree .worktrees/wayguard-mcp-v1):
- pyproject.toml (hatchling, src layout, `wayguard-mcp = wayguard.cli:main`, dep `mcp>=1.2,<2`, dev group pytest/ruff/mypy), uv.lock, .python-version (3.12)
- src/wayguard/{__init__,__main__,cli,config}.py
- scripts/check_static_safety.py (AC-014, AST-based)
- .github/workflows/ci.yml (ubuntu/macos x 3.11/3.12; uv sync --locked, ruff, mypy --strict, static check, pytest)
- tests/{test_config,test_cli,test_static_safety}.py

Gate re-score: Rev 0, Sec 1, Con 0, Blast 1, Infra 2 (as upfront; ci.yml unrunnable locally), Amb 1. No increase -> proceed.
