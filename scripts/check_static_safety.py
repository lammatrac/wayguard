"""AC-014 / CON-002: fail if src/ uses shell=True, os.system, os.popen, eval or exec.

AST-based, so strings, comments and lookalike names do not trigger it.
Usage: check_static_safety.py DIR [DIR...]
"""

import ast
import sys
from pathlib import Path


def violations(tree: ast.AST) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id in {"eval", "exec"}:
            found.append((node.lineno, f"{fn.id}("))
        elif (
            isinstance(fn, ast.Attribute)
            and fn.attr in {"system", "popen"}
            and isinstance(fn.value, ast.Name)
            and fn.value.id == "os"
        ):
            found.append((node.lineno, f"os.{fn.attr}"))
        for kw in node.keywords:
            if kw.arg == "shell" and not (
                isinstance(kw.value, ast.Constant) and kw.value.value is False
            ):
                found.append((node.lineno, "shell=True"))
    return found


def main(dirs: list[str]) -> int:
    bad = 0
    for d in dirs:
        for f in sorted(Path(d).rglob("*.py")):
            for line, what in violations(ast.parse(f.read_text(), str(f))):
                print(f"{f}:{line}: forbidden {what}")
                bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
