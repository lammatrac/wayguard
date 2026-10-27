"""Command-line entry point. Subcommands are added by later phases."""

import argparse
from collections.abc import Sequence

from wayguard import __version__


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="wayguard-mcp",
        description="Read-only, policy-gated SSH diagnostics exposed over MCP (stdio).",
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    parser.add_argument("--version", action="version", version=f"wayguard-mcp {__version__}")
    parser.parse_args(argv)
    parser.print_help()
