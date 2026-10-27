STATUS: DONE

Verified: pytest 299 passed (x3 runs, stable, ~7 s), ruff check, `mypy --strict src/`, `scripts/check_static_safety.py src` all clean. Timeout tests use 1 s limits and assert the whole tree (incl. a backgrounded grandchild and a TERM-ignoring process) is dead via /proc; no leftover `sleep` processes afterwards. AC-006/007/008/009 and AC-020 line cap (3000 -> 2000) covered with fake ssh stubs only; no network. Negative-minimum policy rejection covered in test_policy.

Browser check: skipped explicitly; no browser-observable surface (library code, no UI/endpoint).

Not verified / notes: real OpenSSH wording (phrases are from knowledge of OpenSSH, exercised via stubs only; phase 7 container e2e should confirm). Secrets split across the truncation boundary are not redacted (best effort). Remote programs exiting 255 can forge a classification phrase (stderr is untrusted).
