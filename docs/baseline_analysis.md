# Baseline Analysis (Category 1)

Static analysis of the original scenario scripts (`category1/*.sh`), the baseline rules (`category1/falco-values.yaml`), and the committed sample logs (`category1/logs/*.log`), done **before** re-running anything ourselves. This is a pre-registered reading of what *should* happen — Phase 2 will run the scripts for real and confirm or correct these predictions. Nothing here is a final result yet.

Real-world basis: all four scripts simulate post-compromise behavior from the 2024 OpenMetadata RCE campaign on Kubernetes (per `category1/README_EN.md`, citing Microsoft Threat Intelligence's 2024 analysis). No real exploit, malware, or network reverse shell is reproduced — only the file/process side effects an attacker would leave behind.

## Workload facts (confirmed from manifests, not assumed)

- `backend` Deployment (`workload/backend.yaml`): **single container** named `backend` (busybox 1.36.1 running `httpd`). `kubectl exec` without `-c` is unambiguous here.
- `frontend` Deployment (`workload/frontend.yaml`): **two containers** — `frontend` (busybox 1.36.1, `httpd`) and `curl-client` (curlimages/curl 8.11.1, `sleep infinity`, exists only to `exec curl` into the frontend's own loopback service).

## Scenario-by-scenario mapping

### `normal.sh` → baseline rules `PBL Normal Configuration Read`, `PBL Normal Temporary File Activity`, `PBL Normal Curl Health Check`

| Step | Actual command | Rule condition it should hit | Notes |
|---|---|---|---|
| 1 | `cat /etc/hostname`, `cat /www/index.html` (frontend container) | `PBL Normal Configuration Read`: `proc.name=cat`, `fd.name in (/etc/hostname, /www/index.html)`, `container.name=frontend` | 2 separate `open` events → **2 alerts expected**, not 1. `id` and `uname -a` in the same block match no rule (not file opens) — silently unobserved, which is fine, they carry no detection-relevant signal. |
| 1 | `echo pbl-normal-admin >/tmp/openmetadata-normal-session` | `PBL Normal Temporary File Activity`: `fd.name startswith /tmp/openmetadata-normal`, `evt.is_open_write=true`, `container.name=frontend` | 1 alert expected. |
| 2 | `echo created >file`, `echo updated >>file`, then `cat` + `rm` of both `.tmp` and `-session` files | same rule as above | Each shell redirection is its own `open` syscall with `is_open_write=true`, so **2 writes → 2 alerts** for this one logical "update a temp file" step, confirmed in the committed `logs/normal.log` (two near-identical `action=temp_file_write` lines, same file, consecutive microsecond timestamps). The `cat` (read) and `rm` (unlink, not open) are not separately flagged. |
| 3 | `curl -fsS http://127.0.0.1/ >/tmp/openmetadata-health-response` (curl-client container) | `PBL Normal Curl Health Check`: `fd.name = /tmp/openmetadata-health-response`, no `container.name` restriction | 1 alert expected. |

**Design inconsistency worth noting:** the curl-health-check rule is the only one of the three "normal" rules with **no `container.name` filter** — any container writing to that exact path would match. Low practical risk (the filename is specific), but it's an asymmetry versus the other two rules, which do scope to `container.name=frontend`. As Phase 2 showed, this asymmetry is not cosmetic — see "Cross-node event visibility" below.

Expected total for one valid `normal.sh` run, counted as **distinct real actions** (1 session-file write, 2 config reads, 2 temp-file writes, 1 curl-response write): **6**. (An earlier draft of this table said 5; that was an arithmetic slip, corrected after Phase 2's live run.) **Confirmed live in Phase 2:** 3/3 repetitions produced exactly 8 raw alert lines / 6 deduplicated, identically every time — see `results/baseline_summary.md`. The raw/deduped gap is the cross-node duplication described next, not an extra real action.

## Cross-node event visibility (confirmed empirically in Phase 2, applies to every scenario)

kind's three "nodes" are Docker containers on **one shared host kernel**, not separate VMs. Falco's `modern_ebpf` driver hooks kernel-wide tracepoints, so **every Falco DaemonSet pod observes syscalls from every container on the host, regardless of which node it is "scheduled to."** Only the Falco pod running on the *same* node as the target container can enrich the event with Kubernetes/container metadata (it reads that node's local containerd socket); the other two Falco pods see the identical raw syscall (same `container.id`, same nanosecond timestamp) but with `container.name`, `k8s.pod.name`, `k8s.ns.name` all `<NA>`/`null`.

Practical consequence: a rule condition that includes `container.name = ...` (or any k8s-metadata field) will only ever fire on the one correctly-enriched Falco pod — effectively self-deduplicating. A rule condition that does **not** reference any container/k8s field — like `PBL Normal Curl Health Check` — will fire identically on **every** Falco pod that can still evaluate the condition from the raw syscall fields alone, i.e. **once per node** in this 3-node lab, even though only one real action happened.

This is the concrete, measured version of the limitation the project brief already names in the abstract ("host kernel-in paylaşılması" / shared host kernel) — Phase 2 turned that into hard evidence rather than a theoretical caveat. It has a direct methodology consequence for Phase 5: **"observed alerts" must be deduplicated (e.g. by `container.id` + `evt.time`, or simply by requiring the rule condition to carry a k8s-scoping field) before being compared against the expected count for a case, or an unscoped rule's cross-node echoes will be mis-counted as extra true positives.**

### `abnormal_1.sh` (backend) → rule `PBL OpenMetadata Environment Discovery`

```sh
env >/tmp/openmetadata-env-snapshot        # (1) matches: proc.name=env
cat /proc/1/environ >/dev/null             # (2) matches: proc.name=cat, proc.args contains /proc/1/environ
for path in /root/.aws/credentials /root/.ssh/id_rsa /root/.kube/config /etc/shadow; do
  if [ -e "$path" ]; then ls -l "$path" >/dev/null; fi   # (3) NOT matched by any rule
done
```

- Lines (1) and (2) each independently satisfy the rule condition → **2 alerts expected** for one run, confirmed in the committed `logs/abnormal_1.log` (exactly 2 lines, both `scenario=abnormal_1`).
- Line (3) is a **real coverage gap, not a bug**: the credential-path loop only checks file *existence* (`[ -e ]`) and, if present, runs `ls -l` (metadata stat), never reads file *content*. The current rule set has no condition targeting this at all — confirmed by it being absent from the sample log. This matches the brief's own caution that "checking a file exists is not the same as reading its content," but it also means the existence-probing half of the real OpenMetadata recon flow is currently invisible to our detector. Candidate for a deliberately *separate*, lower-priority rule in Phase 4 — not for inflating this rule's scope.
- The `env` command by itself is a very common, legitimate diagnostic action (shown explicitly as a "hard normal" test candidate in the project brief) — this rule has no way today to distinguish a sysadmin running `env` for troubleshooting from this scenario. That ambiguity is a known limitation, not something to paper over with a process-name-only heuristic.

### `abnormal_2.sh` (backend) → rule `PBL OpenMetadata ServiceAccount Token Access`

```sh
cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null
```

- Single `open` matching `proc.name=cat`, `fd.name contains kubernetes.io/serviceaccount`, `fd.name endswith token`, `container.name=backend` → **1 alert expected**, confirmed by the committed `logs/abnormal_2.log` (exactly 1 line). Output correctly redirected to `/dev/null`; the script itself never prints token content, consistent with the project's no-secret-leak rule.

### `abnormal_3.sh` (frontend) → rule `PBL OpenMetadata Payload Execution`

```sh
cat >/tmp/openmetadata-payload.sh <<EOF
#!/bin/sh
id
uname -a
echo reverse-shell-simulation-no-network
EOF
chmod +x /tmp/openmetadata-payload.sh
/bin/sh /tmp/openmetadata-payload.sh
sleep 1
rm -f /tmp/openmetadata-payload.sh
```

- The rule condition is `spawned_process and proc.name=sh and proc.args contains /tmp/openmetadata-payload.sh and container.name=frontend`.
- **Confirmed double-count in the committed `logs/abnormal_3.log`:** two alerts fire for what is conceptually *one* payload execution:
  1. The **outer** `sh -c '<heredoc + chmod + /bin/sh ... + rm>'` process — its own `proc.cmdline` contains the substring `/tmp/openmetadata-payload.sh` (both in the heredoc body and in the actual exec line), so `proc.args contains ...` matches the *wrapper* shell too, even though the wrapper itself isn't "the payload" running.
  2. The **inner** `sh /tmp/openmetadata-payload.sh` process — the actual intended match.
- This is exactly the "outer shell argument coincidence → duplicate alert" risk the project brief flags as something to check before trusting raw alert counts. It means **1 real attack action here legitimately produces 2 alerts under the current rule**, which is why the TA's evaluation unit is explicitly "one case execution," not "one alert." We will **not** rewrite this rule's condition during baseline analysis (baseline stays frozen); an improved rule in Phase 4 could narrow the match (e.g. requiring the parent process to be the heredoc's own exec line, or matching on `proc.pname` instead of a plain substring on `proc.args`) — tracked as a rule-rationale item, not fixed here.
- The payload file's *creation* and `chmod +x` are not flagged by any rule (filename doesn't start with `/tmp/openmetadata-normal`), so there's no FP risk from writing the file itself — only from executing it.

## Cross-cutting observations (apply to all four scenarios)

1. **`scenario=` in the log is a label the rule itself writes, not independent ground truth.** Whether a given run is actually a valid representative of "normal" or "abnormal_N" must be judged from what the script did and what Falco observed, not from trusting the string the rule's `output:` template happened to print — this matters once we start adding new test cases that are not simply re-runs of these four scripts.
2. **Alert count ≠ action count, in both directions.** We saw it inflate a single logical action into 2 alerts (payload execution, temp-file writes) using the *same* rule. The evaluator in Phase 5 must treat one case×repetition as the unit, and must not score "2 alerts" as "2 true positives" for a single attack execution.
3. **None of the four baseline rules reference a `run_id`, test marker, or anything added purely for grading.** They match on process name, container name, and real file paths — which is correct (a rule that recognized "this is a test" would be worthless), but it also means our *new* test cases in Phase 3 must be realistic enough to actually exercise these same conditions, not just be labeled correctly.
4. **Evidence limitation (updated after Phase 2):** the predictions above were originally derived from the scripts' literal shell logic plus one committed historical log sample per scenario (dated `2026-10-10`). Phase 2 then re-ran all four scenarios, 3 repetitions each, against the live cluster with a fresh Falco tail, and every repetition matched these predictions exactly and deterministically (see `results/baseline_summary.md`) — so this is no longer an untested hypothesis for these four specific scripts. It remains a 3-sample measurement of 4 fixed, already-known-to-match cases, not a general false-positive/false-negative rate; that broader claim still needs Phase 3's additional test cases and Phase 5's scored comparison.
