# Phase 4 plan
- src/wayguard/redaction.py (new): `redact(text)`, ordered regex rules, linear-time.
- src/wayguard/ssh_runner.py (new): async `run_action`, `classify`, `_Bounded` stream cap, process-group kill, `ConcurrencyGate`, `format_text_block`.
- src/wayguard/validation.py: add `CONCURRENCY_LIMIT` reason code.
- src/wayguard/policy.py: reject integer `minimum < 0` (extra item from phase 3 review).
- tests: test_redaction.py, test_ssh_runner.py (fake ssh stubs via discover_ssh(_candidates=...)), test_policy.py negative-minimum case.
Gate re-score: Rev0 Sec2 Con1 Blast1 Infra0 Amb1 = unchanged vs manifest; no escalation.
