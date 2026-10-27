# Phase 5 plan
Gate re-score: Rev1 Sec1 Con2 Blast1 Infra0 Amb1 = same as manifest (no escalation).
Files: src/wayguard/audit.py (FileAuditSink, tail, prune; separate lock file state/audit.lock so prune's
os.replace cannot orphan appenders), src/wayguard/proposals.py (strict UUID4 id, create/list/get/set_status,
lock state/proposals.lock + O_EXCL), cli.py (audit tail/prune, proposals list/show/dismiss/mark-done),
tests/test_audit.py, tests/test_proposals.py, tests/test_cli_phase5.py, contracts.
