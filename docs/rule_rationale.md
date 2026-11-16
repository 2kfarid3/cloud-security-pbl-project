# Rule Rationale

Covers every custom Category 1 Falco rule: what it matches, why that behavior is treated as suspicious (or expectedly benign), what each part of its condition means, its known benign look-alike, and its known bypass/coverage limit. Baseline rules (`category1/falco-values.yaml`, frozen — see `rules/baseline_falco_values.yaml` and its hash in `docs/environment.md`) and improved rules (`rules/improved_falco_values.yaml`) are both covered; the baseline entries restate what Phases 0-2 already found, the improved entries explain the Phase 4 design decisions.

## Baseline rules (unmodified)

### PBL Normal Configuration Read
- **Matches:** `cat` opening `/etc/hostname` or `/www/index.html` inside the `frontend` container.
- **Why labeled normal:** these are exactly the files `normal.sh` reads as routine diagnostics; both are non-sensitive, static, in-image files.
- **Condition parts:** `evt.type in (open, openat, openat2)` — any file-open syscall variant; `proc.name = cat` — specifically the `cat` binary; `fd.name in (...)` — the exact allowlisted paths; `container.name = frontend`.
- **Benign look-alike it does NOT need to distinguish:** none — it only fires on an already-benign allowlist, by design (Informational priority, "this is expected" labeling, not "this is attack-free").
- **Known limit:** allowlist is narrow by construction (confirmed in Phase 3's `normal_config_read_other_file` case: reading `/etc/resolv.conf` produces no alert at all). Absence of this alert must never be read as "suspicious," only as "not on this specific convenience list."

### PBL Normal Temporary File Activity / PBL Normal Curl Health Check
- **Matches:** writes to `/tmp/openmetadata-normal*` (frontend) or to the exact path `/tmp/openmetadata-health-response` (any container).
- **Why labeled normal:** these are the project's own synthetic normal-ops file paths.
- **Known asymmetry (Phase 2 finding):** the Curl Health Check rule has no `container.name` condition, unlike its sibling. Combined with the shared-kernel cross-node visibility described below, a single real event here is independently logged by all 3 Falco pods (raw count 3 for 1 real action) — handled by deduplication in `scripts/parse_falco_events.py`, not a double real event.

### PBL OpenMetadata Environment Discovery
- **Matches:** `env`, or `cat /proc/1/environ`, inside the `backend` container.
- **Why labeled suspicious:** this is literal post-RCE reconnaissance behavior documented in the 2024 OpenMetadata campaign — dumping environment variables is a common way to find embedded credentials/config secrets.
- **Known, confirmed false positive (Phase 3/4, `normal_legit_env_diagnostic`):** a system administrator running `env` for entirely legitimate diagnostic purposes produces the identical syscalls and is therefore flagged identically. This is reported as an accepted limitation, not "fixed" — Falco observes syscalls, not operator intent, and no process-level signal here distinguishes the two without extra context (who issued the command, whether it was interactive, etc.) that this lab's setup does not collect.

### PBL OpenMetadata ServiceAccount Token Access
- **Matches:** `cat` opening a path containing `kubernetes.io/serviceaccount` and ending in `token`, inside `backend`.
- **Why labeled suspicious:** reading the pod's own mounted credential is the concrete Kubernetes-specific credential-access step from the same campaign.
- **Confirmed false negative (Phase 4, `malicious_token_alt_tool`):** any tool other than literally `cat` (e.g. `head`) reads the identical real file with zero alert. Motivated the improved rule below.
- **Known over-match risk (holdout, not yet executed as of this writing):** `fd.name contains ... and fd.name endswith token` is a path-substring match, not an exact path match — `tests/test_matrix.csv`'s held-out `malicious_token_decoy_path` case exists specifically to measure whether a benign file that merely looks like the real path also matches. Not pre-judged here.

### PBL OpenMetadata Payload Execution
- **Matches:** a `sh` process whose arguments contain the literal substring `/tmp/openmetadata-payload.sh`, inside `frontend`.
- **Why labeled suspicious:** write-to-disk-then-execute from a world-writable scratch directory is the local-payload-execution step from the same campaign.
- **Confirmed false negative (Phase 4, `malicious_payload_other_name`):** the identical technique under a different filename is missed entirely.
- **Confirmed partial/coincidental match (Phase 4, `malicious_payload_alt_interpreter`):** swapping the interpreter to `ash` evades the `proc.name = sh` condition on the process that actually runs the payload — but the *outer* `sh -c '...'` wrapper process (from how `kubectl exec` itself invokes the whole block) still contains the path substring in its own command line and still matches. This produces one alert, but it is **not** a real detection of the interpreter swap — see `results/phase4_dev_case_findings.md` for the full reasoning. Treating this as "the rule caught it" would be a methodological error.
- **Known limit:** will also never fire for execution of a /tmp payload that neither matches this filename nor happens to be wrapped in a shell whose own argv restates the path — the realistic general case for an attacker who isn't being run through our specific test harness's invocation style.

## Shared architectural fact behind several of the above

kind's 3 "nodes" are containers on one shared host kernel (confirmed empirically in Phase 2 — see `docs/baseline_analysis.md`, "Cross-node event visibility"). Every Falco pod's `modern_ebpf` probe observes every container's syscalls host-wide; only the Falco pod on the same node as the target container can enrich the event with `container.name`/k8s fields. A rule condition with no such field requirement is therefore independently observed (and alerted) by every Falco pod for one real action. This is not scored as extra true positives — `scripts/parse_falco_events.py`'s `dedup_count` collapses same-container-id events from different hostnames within a short time window before any TP/FP/FN/TN decision is made.

## Improved rules (`rules/improved_falco_values.yaml`, additive, deployed alongside the unmodified baseline)

### PBL Improved Script Execution From Tmp
- **Matches:** any process whose binary is one of Falco's own stock `shell_binaries` macro (`sh`, `bash`, `ash`, `dash`, `ksh`, `csh`, `tcsh`, `zsh`) **and** whose own first argument is a path under `/tmp/` — evaluated on the actually-executing process itself, not an ancestor's command line.
- **Why generalized this way:** fixes both confirmed baseline gaps — a different filename (`malicious_payload_other_name`) and a different interpreter (`malicious_payload_alt_interpreter`) — by keying on "a shell is interpreting a script that lives in `/tmp`," which is what is actually suspicious about the technique, rather than one specific filename+interpreter pair. Keying on the executing process's *own* `proc.args` (not `proc.cmdline` substring matching on a parent) also removes the baseline rule's "coincidental outer-wrapper match" artifact — confirmed in the Phase 4 smoke test (`results/phase4_improved_rules_smoke.md`): this rule's one alert for the `ash` variant is the real `ash` process, not the wrapper.
- **Confirmed, accepted tradeoff (Phase 4 smoke test):** also fires on both of Phase 3's deliberately-designed `hard_normal` /tmp-script cases (`normal_tmp_script_other_name`, `normal_tmp_script_alt_interpreter`) — legitimate scripts placed and executed from `/tmp` are indistinguishable from the attack technique by this syscall pattern alone. This is the core measured instance of the project's research question (narrower rule → false negatives vs. broader rule → false positives), not an oversight.
- **Possible mitigation not implemented here:** an administrative allowlist of known-legitimate `/tmp` script paths/hashes could suppress specific recurring benign cases. Not added, because (a) it would need an operational process for who maintains the allowlist and how entries are approved/expired, which this lab has no stand-in for, and (b) any such allowlist is itself a bypass vector if an attacker can predict or land on an allowlisted path — both the operational basis and the bypass risk would need to be documented per-entry if this were pursued, per the project brief's explicit requirement. Left as a named option for future work rather than implemented speculatively.
- **No `container.name` restriction** (intentionally, to cover both `frontend` and `backend`), so it inherits the same cross-node triplication as `PBL Normal Curl Health Check` — handled by the same deduplication, not a new issue.

### PBL Improved ServiceAccount Token Access Any Tool
- **Matches:** the same file-path condition as the baseline token rule, but on any reading process (`proc.name` unconstrained) instead of only `cat`, and explicitly excludes write-opens (`evt.is_open_write=false`) so it only ever fires on a read of the credential, never on the (irrelevant) directory/file creation events Kubernetes itself generates when mounting the volume.
- **Why generalized this way:** fixes the confirmed `malicious_token_alt_tool` false negative (read via `head`) by removing the single point of evasion (the tool name) while deliberately leaving the file-path condition itself untouched.
- **Inherited, not introduced, limitation:** because the path condition is unchanged from the baseline, this rule inherits the exact same path-substring-matching question the held-out `malicious_token_decoy_path` case is designed to measure. Generalizing the *tool* match was a deliberate, scoped fix; broadening or narrowing the *path* match was deliberately left alone so that holdout case remains a meaningful, unbiased test of the original path logic.

## What Phase 4 did not do, and why

- **No multi-event time correlation.** The project brief explicitly warns against presenting a correlation-based detection as if it were a single Falco condition without implementing and testing the correlation component separately. Nothing here needed multi-event correlation to fix (each confirmed gap was a single-event matching problem), so none was introduced.
- **No ML, scoring model, or anomaly baseline.** Not warranted by the scale or the findings — both confirmed gaps had a direct, explainable single-condition fix.
- **No change to the Environment Discovery rule's false-positive behavior.** Intent cannot be recovered from syscalls alone here; see the baseline entry above. An allowlist could be added in a future iteration with the same operational-basis/bypass-risk documentation requirement noted for the /tmp-execution rule.
