# SPEC — WayGuard MCP v1 (policy-controlled SSH diagnostics server)

## 1. Review

- **Status:** Draft
- **Size:** L
- **Risk:** High — this is a security boundary that executes commands on
  production hosts. One injection or fail-open bug breaks the whole contract.
- **Evidence:** Source-only. The repo is greenfield (only `README.md` and
  `LICENSE`), so there are no code anchors yet.
- **Human decisions required:** 0 (Q-001 to Q-008 resolved on 2026-10-27; all
  took the recommended option)

> **Budget exception:** about 4,000 words, over the L target of 3,500. The
> threat-model rules (CON-*) and failure semantics can't be cut without
> dropping enforceable requirements.

### Goal

Build `wayguard-mcp`. It is a user-scoped, stdio-only MCP server and CLI. It
lets AI agents run reviewed, named, read-only SSH diagnostic actions with
validated parameters. It also lets agents propose missing actions, which only a
human can turn into real actions.

### Current → Expected

- **Current:** The README defines the intended v1 interface. No package, code,
  tests or CI exist.
- **Expected:** An installable Python package (`uv tool install .`) that
  provides `wayguard-mcp` with the CLI and the five MCP tools below. It passes
  the S1 §2.8 test matrix on Linux and macOS.

### Scope

- Load and validate the policy, deny by default, and enforce file permissions.
- Five MCP tools: `list_servers`, `list_actions`, `run_action`,
  `propose_action`, `get_policy_status`.
- An OpenSSH runner with hardened options, timeouts, bounded output, error
  classification and redaction.
- An audit log that stores metadata only, plus an inert proposal store.
- CLI commands: `serve`, `init`, `doctor`, `policy validate`, `actions list`,
  `proposals list|show`, `audit tail`.
- A test suite and CI on Linux and macOS.
- **Explicit exclusions:**
  - Arbitrary or raw command execution, and any mutating action.
  - File transfer and port forwarding.
  - An HTTP/SSE transport.
  - Editing SSH config or keys.
  - Approving or editing policy through MCP.
  - A "run once" approval flow.
  - The remote forced-command gateway implementation.
  - A multi-user or central service.

  [S1 §2.1, §1.1]

### Key Decisions

- Python 3.11+ with the official MCP Python SDK over stdio. Packaged with
  `uv`, with a committed lock file. [S1 §2.2]
- Policy is JSON, `version: 1`, and stored in `~/.config/wayguard/`. Unknown
  fields are rejected. [S1 §2.3–2.4]
- Parameter types are `integer`, `enum` and `string` only. Each placeholder
  must be a whole argument. [S1 §2.4]
- A policy change takes effect only after an explicit restart. The server
  never hot-reloads silently. [S1 §1.3]
- `risk` must be `read-only`. Shells and interpreters are rejected as
  executables. [S1 §2.4]

- **Invalid policy at startup (Q-001):** `serve` starts in deny-all mode. See
  REQ-016.
- **Concurrency overflow (Q-002):** A call over `max_concurrent_actions` is
  rejected immediately with `status: "busy"`. Calls are never queued.
- **Hard ceilings (Q-003):** Fixed in code, not policy: timeout ≤ 120 s,
  output ≤ 256 KiB per stream, ≤ 2,000 lines per stream,
  `max_concurrent_actions` ≤ 8. Policy `defaults` must be within these, and
  each action's values must be ≤ the policy `defaults`. See CON-009.
- **Parameters (Q-004):** Every declared parameter is required. There are no
  defaults in v1.
- **Audit retention (Q-005):** A human-run `audit prune --older-than DAYS`
  command. Nothing is deleted automatically.
- **Proposal lifecycle (Q-006):** `pending` → `dismissed` or `done`, changed
  only through the CLI. MCP tools can't change a proposal's status.
- **Enforcement reporting (Q-007):** `get_policy_status.enforcement` is always
  `local-policy-only` in v1.
- **Server description (Q-008):** `servers.*` gets an optional `description`
  (≤ 200 characters). This is a backward-compatible schema addition.

### Open Questions

None.

## 2. Sources & Code Anchors

- **S1:** `README.md` (working tree, uncommitted). §1 contains the normative
  guardrails and §2 the v1 implementation contract. §3 is the manual setup
  guide, used only for the CLI and user-facing behavior.
- **S2:** `~/.claude/CLAUDE.md` contains repository-independent conventions.
  It sets English artifacts. Its "TypeScript over JavaScript" convention
  doesn't apply here, because S1 §2.2 fixes Python.

### Code Anchors

None. The project is greenfield, and at the time of writing it hasn't been
indexed in WayContext.

## 3. Behavior

### REQ-001 — Filesystem layout and permissions

- The configuration root is `~/.config/wayguard/` and contains `policy.json`,
  `audit.jsonl`, `proposals/` and `state/`.
- Directories are created with mode `0700` and files with `0600`.
- Writes are atomic: write a temp file in the same directory, fsync, then
  `os.replace`.
- Execution is refused if any of these is true:
  - The policy is writable by group or other.
  - The policy isn't owned by the current UID.
  - The policy is a symlink that resolves outside the root.
- The policy path is never taken from the CWD, the project, an environment
  variable or MCP input.

  [S1 §2.3]

### REQ-002 — Policy schema validation

Validation rejects the whole policy, not just one entry, in any of these cases:

- Invalid JSON, `version` ≠ 1, any unknown field at any level, or a missing
  required field.
- `defaults.decision` ≠ `"deny"`.
- A server or action ID that doesn't match `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`.
- An `ssh_alias` that is empty, starts with `-`, or contains whitespace,
  control characters or shell metacharacters.
- `risk` ≠ `"read-only"`.
- Timeout, output cap or concurrency values ≤ 0, `defaults` above the CON-009
  ceilings, or an action value above `defaults`.
- A server `description` that is longer than 200 characters or contains
  control characters.
- A non-string `description`, or one with control characters.

[S1 §1.1 #3, §2.4]

### REQ-003 — Executable and argument rules

- `executable` must be an absolute, normalized POSIX path. It can't contain
  `..`, whitespace or control characters.
- The basename can't be on the interpreter denylist. The minimum list is from
  S1: `sh`, `bash`, `zsh`, `dash`, `python*`, `perl*`, `ruby*`, `node*`, `env`,
  `sudo`, `su`, `busybox`. This spec also adds `ksh`, `fish`, `csh`, `tcsh`,
  `php*`, `lua*`, `awk`, `gawk`, `mawk`, `sed`, `find`, `xargs`, `doas`,
  `pkexec`, `ssh`, `scp`, `sftp`, `nohup`, `timeout`, `nice`, `script`,
  `expect`, `vi*`, `less`, `more`, `tee`, `dd`. These either run code or write
  files.
- `args` is a list of strings. An element that is exactly `{name}` is a
  placeholder.
- Any other `{` or `}` in an element is rejected, because embedded
  interpolation isn't allowed.
- A placeholder with no matching entry in `parameters` is rejected.
- A declared parameter that is never used in `args` is rejected.
- Fixed args can't contain NUL, CR or LF.

[S1 §1.1 #2, #6, §2.4]

### REQ-004 — Parameter schemas

| type | Required keys | Validation |
|---|---|---|
| `integer` | `minimum`, `maximum` (both integers, min ≤ max) | JSON integer, not a bool or float; within range |
| `enum` | `values` (1–64 strings, each ≤ 256 chars) | Exact match. Values are validated at policy load with the string rules below. |
| `string` | `max_length` (1–256), `pattern` | `re.fullmatch` against `pattern` |

Every string value, whether an agent input or an enum entry, is rejected if it
does any of these:

- Contains NUL or control characters.
- Starts with `-`.
- Contains a `..` path segment.
- Exceeds `max_length`.

The `-` rule blocks argument injection [S1 §1.1 #5].

Types `raw`, `shell`, `command`, `script` and `args_extra` are rejected.

A path can only come from an `enum` of exact paths. [S1 §2.4]

### REQ-005 — `run_action` request validation

- The input schema is exactly `{server_id, action_id, parameters}`. Additional
  properties are rejected at every level.
- Validation order:
  1. Is the policy valid (REQ-016)?
  2. Does the server exist and is it enabled?
  3. Does the action exist?
  4. Parameters: no missing ones (all declared parameters are required), no
     extra ones, correct type, and
     within constraints.
- The first failure returns `status: "denied"` with a sanitized reason.
  Nothing is executed. [S1 §2.5]

### REQ-006 — Command construction

- The remote command is `shlex.quote(executable)` followed by
  `shlex.quote(arg)` for each argument, joined with single spaces.
- Placeholders are replaced with the validated value as a string. One
  placeholder always produces exactly one argument.
- The local argv is:

  ```text
  [<trusted ssh>, "-T",
   "-o", "BatchMode=yes",
   "-o", "StrictHostKeyChecking=yes",
   "-o", "ForwardAgent=no",
   "-o", "ForwardX11=no",
   "-o", "ClearAllForwardings=yes",
   "-o", "PermitLocalCommand=no",
   "-o", "ControlMaster=no",
   "-o", "ControlPath=none",
   "-o", "RequestTTY=no",
   "-o", "ConnectTimeout=<min(10, timeout)>",
   "--", <ssh_alias>, <remote_command>]
  ```

- The process is started with `shell=False`.
- `ControlMaster` and `ControlPath` are disabled so the call can't reuse a
  user multiplex session that might have forwarding enabled.

[S1 §1.1 #4, §2.4, §2.7]

### REQ-007 — Trusted SSH client discovery

- The client is the first existing regular file from a fixed list:
  `/usr/bin/ssh`, `/usr/local/bin/ssh`, `/opt/homebrew/bin/ssh`.
- `PATH` is never used.
- The child environment is minimal: `HOME`, `USER`, `LOGNAME`,
  `LANG=C.UTF-8`, `PATH=/usr/bin:/bin`, and `SSH_AUTH_SOCK` passed through if
  set.
- `doctor` reports which binary was chosen. [S1 §2.7]

### REQ-008 — Execution limits

- Effective timeout = action `timeout_seconds` or the default, subject to the
  ceiling.
- When the deadline is reached, the server sends SIGTERM, then SIGKILL after
  2 s, and waits for the process (no orphans). The result is
  `status: "timeout"`.
- stdout and stderr are each read up to the effective `max_output_bytes` and
  the CON-009 line ceiling. Anything beyond that is drained and discarded, and
  `truncated_stdout` and `truncated_stderr` are set.
- Output is decoded as UTF-8 with replacement. A truncation marker line is
  appended.
- At most `max_concurrent_actions` calls run at the same time. Any call over
  the limit returns `status: "busy"` immediately and is audited as `denied`
  with reason `concurrency_limit`. It is never queued.
- MCP cancellation kills the child the same way a timeout does.

[S1 §1.1 #14, §2.7]

### REQ-009 — Result classification

`run_action` returns structured content with these fields:

- `status`: one of `ok`, `nonzero_exit`, `timeout`, `denied`, `busy`,
  `host_key_error`, `auth_error`, `unreachable`, `unknown_alias`, `ssh_error`,
  `internal_error`.
- `correlation_id`, `server_id`, `action_id`.
- `exit_code`: an integer, or null.
- `duration_ms`.
- `stdout`, `stderr`: redacted.
- `truncated_stdout`, `truncated_stderr`.
- `stdout_bytes`, `stderr_bytes`: the original byte counts.
- `untrusted_output_notice`.

SSH exit code 255 is classified by matching stable OpenSSH stderr phrases, for
example "Host key verification failed" and "Permission denied (". A 255 that
doesn't match any phrase becomes `ssh_error`. Partial output is never reported
as `ok`. [S1 §1.4, §2.7]

### REQ-010 — Untrusted-output labeling and redaction

- The text content block wraps the remote output in fixed delimiters:
  `--- BEGIN UNTRUSTED REMOTE OUTPUT ---` / `--- END ... ---`.
- A fixed notice comes first: the output is data, not instructions.
- Before output is returned, the following are replaced with
  `[REDACTED:<kind>]`:
  - PEM private-key blocks.
  - `Authorization:` and `Bearer` tokens.
  - `password=`, `passwd=`, `secret=`, `token=`, `api_key=` style key/value
    pairs.
  - AWS access key IDs.
  - Common provider token prefixes (`ghp_`, `glpat-`, `sk-`, `xox[bp]-`).
  - JWT-shaped strings.
  - `Cookie:` and `Set-Cookie:` values.
- Documentation and the notice must not claim that redaction is complete.

[S1 §1.1 #12–13, §1.4]

### REQ-011 — Audit

- `audit.jsonl` gets one append-only JSON line per event (`start` and `end`),
  written under an exclusive file lock with mode `0600`.
- Fields: `ts` (UTC ISO-8601), `event`, `correlation_id`, `server_id`,
  `action_id`, `params` (normalized), `status`, `exit_code`, `duration_ms`,
  `stdout_bytes`, `stderr_bytes`, `truncated`, `timed_out`.
- Normalized `params`: integers and enum values are stored as they are.
  Strings are stored as `{len, sha256_8}`.
- Audit lines never include raw output, the full remote command, the alias's
  resolved host or user, or environment values.
- Denied requests are audited too: one `denied` event that includes the
  reason code.
- Retention: `wayguard-mcp audit prune --older-than DAYS` (DAYS ≥ 1) removes
  lines older than the cutoff by rewriting the file atomically under the lock,
  and prints the number removed. Nothing prunes automatically.

[S1 §1.4]

### REQ-012 — Proposals

- `propose_action` input: `server_id` (string; it may refer to an unknown
  server so that a server can be requested), `goal` (≤ 500 characters),
  `reason` (≤ 1,000), and an optional `suggested_action_summary` (≤ 1,000).
  Additional properties are rejected, as are control characters other than
  `\n`.
- Each proposal is written to `proposals/<id>.json` (`0600`) with: `id`,
  `created_at`, `server_id`, `server_known` (bool), the fields above, and
  `status: "pending"`.
- Lifecycle: `pending` → `dismissed` or `done`. Only the human CLI
  (`proposals dismiss ID`, `proposals mark-done ID`) changes the status, with
  an atomic rewrite that adds `status_changed_at`. Both are terminal states.
  No MCP tool changes a status. `proposals list` shows pending proposals by
  default, and `--all` shows every proposal.
- The number of pending proposals is capped at 200. Beyond that, the call
  returns `denied: proposal_limit`.
- The response returns the ID and tells the human how to review it.
- The tool's description asks for the desired diagnostic result, the expected
  data source and the parameter constraints, not shell text.
- No code path reads a proposal as policy or passes its content to a process.
  [S1 §1.3, §2.5]

### REQ-013 — Listing and status tools

- **`list_servers`:** No input. Returns enabled server IDs, the optional
  `description` (if set) and an action count. It never returns `ssh_alias`, hosts,
  users, identity paths or `ssh -G` output.
- **`list_actions(server_id)`:** Returns each action's ID, description, risk,
  parameter schemas, effective timeout and effective output cap. Unknown or
  disabled servers are denied.
- **`get_policy_status`:** No input. Returns `schema_version`,
  `validation: valid|invalid`, sanitized `errors[]`, `loaded_at`,
  `policy_changed_since_load` (based on mtime/hash), and
  `enforcement`, which is always `local-policy-only` in v1.
  It never returns policy content.

[S1 §2.5]

### REQ-014 — CLI

`wayguard-mcp serve|init|doctor|policy validate|actions list [--server ID]|proposals list|proposals show ID|audit tail [--limit N]`,
plus `audit prune --older-than DAYS`, `proposals dismiss ID` and
`proposals mark-done ID`.

- **`init`:** Creates the layout and writes a sample policy with
  `servers: {}`. It refuses to overwrite an existing policy unless `--force` is
  given, and with `--force` it keeps a timestamped backup.
- **`doctor`:** Checks the Python version, the trusted SSH binary, paths and
  modes, and policy validity. For each alias it runs `ssh -G` and reports only
  "resolvable: yes/no". It never prints the output of `ssh -G`.
- **`policy validate`:** Never connects to a remote host.

Exit codes are distinct per class: success, invalid policy, denied, operational
error, internal error. Proposed values are 0, 2, 3, 4 and 1 respectively, with
argparse usage errors staying at 2.

> Note: S1 requires the classes to be distinct but sets no numbers. The
> implementer may choose the numbers, but they must be documented in the
> README.

[S1 §2.6]

### REQ-015 — Policy lifecycle

- `serve` loads the policy once, at startup.
- Changes on disk aren't applied until a restart. They are reported through
  `policy_changed_since_load`.
- There is no MCP tool that writes or reloads the policy. [S1 §1.3]

### REQ-016 — Deny-all mode

- If policy loading or validation fails at startup, `serve` still starts and
  registers the same five tools.
- In this mode:
  - `get_policy_status` returns `validation: "invalid"` with sanitized errors.
  - `list_servers` returns an empty list.
  - `list_actions` and `run_action` return `denied` with reason
    `policy_invalid`.
  - `propose_action` still works.
- Nothing is executed. [S1 §1.1 #3, §2.5]

## 4. Constraints & Contracts

- **CON-001 — No shell tool, ever:** The only MCP tools are the five in
  REQ-005, REQ-012 and REQ-013. A test asserts the exact set of registered tool
  names. [S1 §1.1 #1, §2.5]
- **CON-002 — No shell constructs in code:** The code never uses
  `shell=True`, `os.system`, `os.popen`, `eval`, `exec`, or string-built local
  commands. This is enforced by a static check in CI. [S1 §2.2, §2.8]
- **CON-003 — Stdout carries protocol only:** In `serve`, all logging goes to
  stderr. A test parses every stdout line as JSON-RPC. [S1 §1.1 #20]
- **CON-004 — No network listener:** The server uses stdio transport only and
  never binds a socket. [S1 §1.1 #19]
- **CON-005 — Fail closed:** Every error path in policy loading, validation or
  the runner results in denial or an error status, never in execution.
  [S1 §1.1 #3]
- **CON-006 — No secret egress:** Tool results, errors, the audit log and
  stderr never contain key material, `~/.ssh/config` content, `SSH_AUTH_SOCK`,
  environment dumps or `ssh -G` output. [S1 §1.1 #12, #17, §2.7]
- **CON-007 — Dependencies:** Pinned version ranges and a committed `uv.lock`.
  Nothing is fetched or installed at runtime. [S1 §2.2]
- **CON-008 — Platforms:** Linux and macOS with Python 3.11+. Windows isn't a
  target. [S1 §2.1]
- **CON-009 — Hard ceilings in code:** timeout ≤ 120 s, output ≤ 256 KiB per
  stream, ≤ 2,000 lines per stream, and `max_concurrent_actions` ≤ 8. These
  are module constants, and no policy field or MCP input can raise them.
  [S1 §1.1 #14, §2.4]

### Concurrency and idempotency

- `run_action` isn't assumed to be idempotent. It's read-only, but it runs
  remotely and each call produces a new audit pair.
- Audit appends are serialized with `fcntl.flock`.
- Proposal writes use unique IDs (UUID4) and atomic create (`O_EXCL`).
- One `serve` process per client is expected. Several processes may share the
  audit log and proposals directory, and the locks cover that case.

## 5. Acceptance Criteria

- **AC-001 — Fail-closed policy (validates REQ-002, REQ-003, REQ-004,
  CON-005):** Each of these produces a validator error and zero SSH spawns:
  - an unknown field at each level;
  - `version: 2`;
  - invalid JSON;
  - a denylisted executable (one fixture per denylist entry);
  - a relative executable;
  - an embedded placeholder (`--lines={lines}`);
  - an unknown placeholder or an unused parameter;
  - `risk: "write"`;
  - a timeout above the ceiling;
  - an alias starting with `-`;
  - a `raw`-type parameter.
- **AC-002 — File permissions (validates REQ-001):** With the policy at mode
  `0644`, owned by another UID, or a symlink that escapes the root, both
  `run_action` and `policy validate` fail with a permission error.
- **AC-003 — Request denial (validates REQ-005):**
  - **Requests:** unknown server, disabled server, unknown action, a missing
    parameter, an extra parameter, a top-level extra field (for example
    `ssh_alias`), a bool passed for an integer, an out-of-range integer, an
    invalid enum, an overlong string, and a string that fails the pattern.
  - **Result:** each returns `status: "denied"`, writes a `denied` audit line,
    and spawns no process.
- **AC-004 — Injection matrix (validates REQ-004, REQ-006):**
  - **Inputs:** for a string parameter with a permissive test pattern, the
    values `a b`, `'`, `"`, `;`, `|`, `$()`, a backtick, `\n`, `\0`, `-rf`,
    `--help`, and `../x`.
  - **Result:** each value is either rejected (`-`-leading, `..`, control
    characters, NUL) or arrives as exactly one remote argument. This is
    verified by golden tests of the serialized remote command, plus a
    round-trip `shlex.split` check.
- **AC-005 — SSH hardening (validates REQ-006, REQ-007):** The argv produced
  for an action matches the REQ-006 golden list exactly. The SSH binary comes
  from the fixed list even when `PATH` contains a fake `ssh` first.
- **AC-006 — Timeout (validates REQ-008):** A fake SSH stub that sleeps
  forever returns `timeout` within timeout + 3 s, and no child process is left
  afterward.
- **AC-007 — Output caps (validates REQ-008):** With a stub that writes 1 MiB
  to stdout and 1 MiB to stderr, each stream is capped independently at the
  limit. Both truncation flags are true and the marker is present.
- **AC-008 — Classification (validates REQ-009):** Stubs that emit the host-key
  failure, auth failure, unreachable and unknown-alias messages with exit 255
  map to their statuses. Exit 1 maps to `nonzero_exit`. In every case
  `exit_code` is reported.
- **AC-009 — Untrusted labeling and redaction (validates REQ-010):** Output
  containing a PEM key, `Authorization: Bearer x`, `password=hunter2`, an AWS
  key ID and a JWT is returned redacted, inside the delimiters, with the notice.
- **AC-010 — Audit hygiene (validates REQ-011, CON-006):** After the
  AC-003, AC-007 and AC-009 runs, `audit.jsonl` contains no output text, no
  string parameter values, no alias host and no remote command, and every line
  has the required fields.
- **AC-011 — Proposals are inert (validates REQ-012):**
  - `propose_action` creates exactly one `0600` file and spawns no process.
  - The policy is unchanged byte-for-byte.
  - The proposed operation still can't be run through `run_action`.
  - Proposal 201 is denied.
- **AC-012 — Tool surface (validates REQ-013, CON-001):** The MCP
  `tools/list` returns exactly the five tool names. `list_servers` and
  `get_policy_status` output contains no alias or hostname from the fixture.
- **AC-013 — Stdout hygiene (validates CON-003):** A `serve` session
  (initialize → list → call → shutdown) produces only valid JSON-RPC on stdout.
  A startup log line appears on stderr.
- **AC-014 — Static safety (validates CON-002):** A CI job greps or lints `src/`
  for `shell=True`, `os.system`, `os.popen`, `eval(` and `exec(`, and fails on
  any hit.
- **AC-015 — CLI (validates REQ-014):**
  - `init` on an empty home creates the layout with the right modes and an
    empty `servers`.
  - `init` again without `--force` fails and leaves the file unchanged.
  - `doctor` and `policy validate` complete with no network access.
  - Exit codes differ per error class.
- **AC-016 — End-to-end (validates S1 §2.9):** Against a disposable
  `sshd` container with a dedicated non-root user:
  - `nginx_error_tail` with `lines=5` returns `ok` with 5 lines.
  - A changed host key returns `host_key_error`.
  - An unknown action is denied, and the agent can only propose it.
- **AC-017 — Policy lifecycle (validates REQ-015):** If the policy is edited
  while `serve` is running, `run_action` keeps using the loaded policy and
  `get_policy_status.policy_changed_since_load` becomes `true`.

- **AC-018 — Deny-all mode (validates REQ-016):** Start `serve` with an
  invalid policy.
  - `get_policy_status` reports `invalid`.
  - `list_servers` returns `[]`.
  - `run_action` returns `denied` with reason `policy_invalid`, and no process
    is spawned.
  - `propose_action` succeeds.
- **AC-019 — Concurrency (validates REQ-008):** With
  `max_concurrent_actions: 1` and a slow SSH stub, a second concurrent
  `run_action` returns `busy` immediately. A `denied` audit line is written
  with reason `concurrency_limit`.
- **AC-020 — Ceilings (validates CON-009, REQ-002):** These policies fail
  validation:
  - `defaults.timeout_seconds: 121`;
  - `defaults.max_output_bytes: 262145`;
  - `max_concurrent_actions: 9`;
  - an action `timeout_seconds` above `defaults`.

  A stub that emits 3,000 short lines is truncated at 2,000.
- **AC-021 — Audit prune and proposal lifecycle (validates REQ-011,
  REQ-012):**
  - `audit prune --older-than 30` removes only lines older than 30 days and
    keeps mode `0600`.
  - `proposals dismiss` and `proposals mark-done` change the status and record
    `status_changed_at`.
  - Changing the status of a proposal that is already `dismissed` or `done`
    fails.
  - No MCP tool can change a proposal's status.

## 6. Verification

### Automated

Proposed, since no tooling exists yet:

- `uv run pytest` for unit tests and stub-SSH tests (a fake `ssh` script
  injected into the trusted-path list through a test-only seam).
- `uv run ruff check` and `uv run mypy --strict src/`.
- The AC-014 static check.
- CI matrix: `ubuntu-latest` and `macos-latest` on Python 3.11 and 3.12.
- The AC-016 end-to-end job runs on Linux only (Docker `sshd`). macOS end-to-end
  is manual.

### Browser / Manual

- No browser checks.
- Manual: register the server in Claude Code (`claude mcp add wayguard --scope
  user -- wayguard-mcp serve`), confirm the tool list with `/mcp`, and run the
  S1 §3.8 prompt against a staging host.
- Verify the Codex, Gemini CLI and Cursor configuration snippets against their
  current documentation (S1 §2.9).

### Regression

None, because the project is greenfield. The README must be updated if any
open-question outcome changes the interface it documents (the CLI, the schema,
or the `get_policy_status` fields).

## 7. Implementation Notes

- **Suggested layout:** `src/wayguard/{config,policy,validation,ssh_runner,redaction,audit,proposals,cli,mcp_server}.py`,
  following the module list in S1 §2.2.
- **Suggested phase order** (each phase is independently testable; for use with
  `spec-phase-runner`):
  1. Scaffold: `pyproject.toml`, the `wayguard-mcp` entry point, `uv.lock`,
     CI, and `config` paths and permissions.
  2. Policy schema, validator, denylist and ceilings, plus `init`,
     `policy validate` and `actions list` (AC-001, AC-002, AC-015, AC-020).
  3. Request validation and command construction (AC-003, AC-004, AC-005).
     **Highest risk.**
  4. SSH runner, limits, classification and redaction (AC-006 to AC-009).
  5. Audit, proposals, and the `audit` and `proposals` CLI (AC-010, AC-011,
     AC-021).
  6. MCP server tools and `serve` (AC-012, AC-013, AC-017 to AC-019).
  7. `doctor`, the end-to-end container test, and a README sync (AC-016).
- Use `jsonschema` (Draft 2020-12, `additionalProperties: false` everywhere)
  for structure. Put semantic rules (REQ-003, REQ-004 and the ceilings) in code,
  so error messages can name the failing path.
- Compile string `pattern` values at policy load and reject invalid regexes.
  Consider limiting pattern length (for example ≤ 256) to reduce ReDoS risk
  from regexes the human writes.
- Codex's example config key in S1 §3.7 is `ssh_guard`, while every other
  client uses `wayguard`. Align it during the README sync.
