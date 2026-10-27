# Manifest — wayguard-mcp-v1

- **Spec:** `tasks/context/wayguard-mcp-v1/spec.md`
- **Slug:** `wayguard-mcp-v1`
- **Phase source:** spec §7 "Suggested phase order" (L578-590), used as-is.
- **Dependencies:** strictly sequential (phase N depends on N-1).
- **Rubric legend:** `Rev/Sec/Con/Blast/Infra/Amb` = Reversibility / Security
  surface / Concurrency / Blast radius / New infra-deps / Spec ambiguity, each 0-2.
- **Checkpoint rule:** `checkpoint: yes` if `total >= 6` OR any single dimension = 2.
- **Shared ranges:** Goal/Scope L18-54; Key Decisions L56-86; Constraints L398-423;
  Concurrency and idempotency L425-432; Verification L545-572; Impl notes L574-598.

| Phase | Title | Spec range | Depends on | Rev/Sec/Con/Blast/Infra/Amb | Total | Checkpoint | Status |
|---|---|---|---|---|---|---|---|
| 1 | Scaffold: `pyproject.toml`, `wayguard-mcp` entry point, `uv.lock`, CI, `config` paths and permissions | Scope L33-54; Key Decisions L58-59; REQ-001 L108-122 (layout, modes, atomic writes); CON-002 L403-405; CON-007 L416-417; CON-008 L418-419; AC-014 L498-500; Verification/Automated L547-557; Impl notes layout L576-577 | — | 0/1/0/1/2/1 | 5 | yes | done |
| 2 | Policy schema, validator, denylist and ceilings, plus `init`, `policy validate`, `actions list` | Key Decisions L60-68, L73-78, L85-86; REQ-001 L108-122 (permission refusal); REQ-002 L124-141; REQ-003 L143-162; REQ-004 L164-184; REQ-014 L355-377 (`init`, `policy validate`, `actions list`, exit codes); CON-005 L410-412; CON-009 L420-423; AC-001 L436-448; AC-002 L449-451; AC-015 L501-506 (`doctor` item deferred to phase 7); AC-020 L527-533 (L534 line-cap stub deferred to phase 4); Impl notes L591-596 | 1 | 0/2/0/2/1/1 | 6 | yes | done |
| 3 | Request validation and command construction (highest risk) | Key Decisions L62-63, L77-78; REQ-004 L164-184 (runtime string rules); REQ-005 L186-198; REQ-006 L200-227; REQ-007 L229-237; CON-005 L410-412; AC-003 L452-458; AC-004 L459-466; AC-005 L467-469; Verification test seam L551-552 | 2 | 0/2/0/1/0/1 | 4 | yes | done |
| 4 | SSH runner, limits, classification and redaction | Key Decisions L71-76; REQ-008 L239-256 (timeout, caps, decoding; concurrency gate L251-254 wired in phase 6); REQ-009 L258-276; REQ-010 L278-295; CON-005 L410-412; CON-006 L413-415; CON-009 L420-423; AC-006 L470-472; AC-007 L473-475; AC-008 L476-479; AC-009 L480-482; AC-020 L534; Verification test seam L551-552 | 3 | 0/2/1/1/0/1 | 5 | yes | done |
| 5 | Audit, proposals, and the `audit` and `proposals` CLI | Key Decisions L79-82; REQ-011 L297-314; REQ-012 L316-337; REQ-014 L355-359 (`audit tail/prune`, `proposals list/show/dismiss/mark-done`); CON-006 L413-415; Concurrency and idempotency L425-432; AC-010 L483-486; AC-011 L487-491; AC-021 L535-543 | 4 | 1/1/2/1/0/1 | 6 | yes | done |
| 6 | MCP server tools and `serve` | Key Decisions L58-59 (MCP SDK), L64-65, L69-72, L83-86; REQ-005 L186-198 (tool input schema); REQ-008 L251-254 (busy/cancellation); REQ-013 L339-353; REQ-015 L379-384; REQ-016 L386-396; CON-001 L400-402; CON-003 L406-407; CON-004 L408-409; Concurrency and idempotency L425-432; AC-012 L492-494; AC-013 L495-497; AC-017 L512-514; AC-018 L516-522; AC-019 L523-526 | 5 | 0/2/1/2/1/1 | 7 | yes | done |
| 7 | `doctor`, end-to-end container test, README sync | REQ-007 L237; REQ-014 L364-366 (`doctor`); CON-006 L413-415 (`ssh -G` never printed); AC-015 L505 (`doctor` offline); AC-016 L507-511; Verification L545-572; Impl notes L597-598 | 6 | 0/1/0/1/2/1 | 5 | yes | done |

## Risk notes

- **Phase 1:** Infra=2 — introduces the whole toolchain from nothing: CI pipeline (Linux+macOS matrix), pinned deps and `uv.lock` (CON-007 supply chain); CI platform is not named by the spec (Amb=1).
- **Phase 2:** Sec=2, Blast=2 — the validator and denylist are the fail-closed trust boundary for every later phase; every downstream module consumes the policy model.
- **Phase 3:** Sec=2 — command construction turns agent input into a remote shell command; one quoting or placeholder bug is a remote injection.
- **Phase 4:** Sec=2 — new process-execution boundary (spawns ssh against production hosts, handles untrusted output and secret redaction, signal/kill lifecycle).
- **Phase 5:** Con=2 — new cross-process coordination: `flock` audit appends, `O_EXCL` proposal creation, atomic prune rewrite, and a 200 pending-proposal cap shared by several `serve` processes; `audit prune` deletes user data (Rev=1).
- **Phase 6:** Sec=2, Blast=2, total=7 — newly exposed MCP endpoint taking agent input; integrates every module, deny-all mode and the concurrency gate.
- **Phase 7:** Infra=2 — new Docker `sshd` end-to-end job in CI; `doctor` runs `ssh -G` and must not leak its output.
