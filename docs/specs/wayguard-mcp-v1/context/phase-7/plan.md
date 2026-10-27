# Phase 7 plan
Gate re-score: reversibility 0, security 1, concurrency 0, blast 1, infra 2 (Docker only in e2e/CI), ambiguity 1 -> no dimension higher than manifest (0/1/0/1/2/1). Proceed.

1. `src/wayguard/doctor.py` + `cli.py` wiring: `run_doctor(root, *, ssh_candidates=TRUSTED_SSH_PATHS, out) -> int`. Checks python>=3.11, discover_ssh, root/subdir/policy modes, load_policy, per alias `ssh -G -- alias` (shell=False, child_env, DEVNULL output, 10s timeout) -> "resolvable: yes/no" only. Exit 0 ok / 2 invalid policy / 3 refused policy / 4 other. Tests: tests/test_doctor.py with fake ssh.
2. `tests/test_e2e_docker.py` (marker `e2e`, skipped unless `-m e2e` / docker unavailable), fixtures in `tests/e2e/`; pyproject marker + addopts `-m "not e2e"`; CI job `e2e` ubuntu only.
3. README sync; contracts Phase 7.
