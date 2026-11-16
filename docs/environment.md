# Environment Snapshot

This file records the actual, measured state of the lab environment at the time of testing. It is re-verified at the start of later phases rather than assumed.

## Measurement metadata

- Measured: 2026-11-08 (local time), host timezone KST (UTC+9)
- Repo HEAD at measurement time: `270bf2df9ae1eddfb26e8dc88cb92326c54a99a8` ("Add Kubernetes security PBL labs")
- Upstream testbed: https://github.com/cclab-inu/Practical-Cloud-Security-PBL (origin remote — read-only reference, never pushed to)
- Working directory: `/home/farid/Practical-Cloud-Security-PBL`

## Host

- OS: Ubuntu 24.04.5 LTS
- Kernel: `7.0.0-42-generic` (x86_64)
- Memory: 15 GiB total, ~10 GiB available at measurement time
- Disk (`/`): 150G total, 43G available (71% used)
- `fs.inotify.max_user_instances`: raised at runtime from the distro default (128) to 1024 during this session — see [Phase 0 finding](#phase-0-finding-falco-crashloopbackoff-from-inotify-exhaustion) below. This is a runtime-only `sysctl -w`; it is **not** persisted via `/etc/sysctl.d` (that write was blocked by the session's own tool policy), so it resets on host reboot and must be re-applied if Falco crash-loops again after a restart.

## Tooling versions

| Tool | Version |
|---|---|
| Docker | 29.1.3 (build 29.1.3-0ubuntu3~24.04.2) |
| kind | 0.24.0 |
| kubectl client | v1.37.2 |
| kubectl server (API) | v1.31.0 |
| Helm | v3.22.1+gd6c1a0e |
| Cilium chart | 1.16.3 (app version 1.16.3) |
| Falco chart | 9.2.2 (app version 0.45.2) |
| Falco driver | `modern_ebpf` (no kernel module build needed) |

**Known version skew:** `kubectl version` itself warns that the client (1.37) and API server (1.31) differ by more than the officially supported ±1 minor version. No functional failures were observed from this during Phase 0 checks (all `kubectl` commands used here succeeded), but this is a documented constraint of the current setup, not a "latest and greatest" claim — do not silently upgrade/downgrade components to "fix" this without checking whether it actually breaks a specific command first.

## Cluster topology

- kind cluster: `pbl-security`, kubectl context: `kind-pbl-security`
- Nodes (all Ready, kernel `7.0.0-42-generic`, containerd 1.7.18):
  - `pbl-security-control-plane` — control plane + one Falco pod
  - `pbl-security-worker` — `frontend` (2 containers: `frontend`, `curl-client`), `backend`, one Falco pod
  - `pbl-security-worker2` — `db`, one Falco pod
- Namespaces: `pbl-security` (app workloads), `falco` (monitoring), `kube-system` (infra)
- Helm releases: `cilium` (kube-system, revision 2, deployed), `falco` (falco namespace, revision 1, deployed)

Pod names, IPs, and node placement are not stable across restarts/rollouts — use the label selectors in the manifests under `workload/` and `category1/`, not the specific names recorded here.

## Falco readiness and event source

- Event source: `modern_ebpf` (confirmed from the `falco-driver-loader` init container log).
- Container metadata enrichment: confirmed working — sampled alerts carry `container.id`, `container.name`, `container.image.repository/tag`, `k8s.pod.name`, `k8s.ns.name`.
- Custom rules file: `category1/falco-values.yaml` → `pbl_rules.yaml`, mounted as the `falco-rules` ConfigMap. All 6 custom rules (`PBL Normal Configuration Read`, `PBL Normal Temporary File Activity`, `PBL Normal Curl Health Check`, `PBL OpenMetadata Environment Discovery`, `PBL OpenMetadata ServiceAccount Token Access`, `PBL OpenMetadata Payload Execution`) are confirmed loaded in the running engine (`falco -L` output lists them by name) and actively evaluated.
- Non-blocking schema warning: `pbl_rules.yaml | schema validation: failed for <root>[0][priority]: Failed to match against any enum values.` Root-caused in this session (see below) — not fixed here, since the baseline rules file is left untouched per project convention; tracked for Phase 1/4 (improved rules can fix the casing).

## Phase 0 finding: Falco CrashLoopBackOff from inotify exhaustion

**Symptom:** at the start of Phase 0, 2 of 3 Falco pods (`pbl-security-worker`, `pbl-security-worker2`) were `0/2 CrashLoopBackOff` (21 restarts, ~15h old pods). Only the control-plane Falco pod was `2/2 Running`. Docker containers for all 3 kind nodes showed `Up 41 minutes` against a 16h creation time, indicating the host had rebooted roughly 40 minutes before this session started.

**Root cause (evidence-based):** `kubectl logs -c falco` on a crashing pod showed `Error: could not initialize inotify handler` right after rule loading, immediately before the container exited. Checking the kernel tunable on the host (shared by all kind node-containers, since they run in the host's initial user namespace) showed `fs.inotify.max_user_instances = 128`, the Ubuntu default. With kubelet, containerd, the desktop session, and repeated Falco restarts all competing for the same host-wide limit, two of the three Falco pods could not obtain an inotify instance after the reboot.

**Fix applied:** `sudo sysctl -w fs.inotify.max_user_instances=1024` on the host, then `kubectl -n falco delete pod <crashlooping pods>` so the DaemonSet recreated them under the new limit. Both pods came back `2/2 Running` within ~40 seconds and no longer show the inotify error in their logs.

**Verification:** `kubectl -n falco get pods` now shows all 3 Falco pods `2/2 Running`; `kubectl -n falco logs <new pod> -c falco` no longer contains the inotify error; a background alert (`Redirect STDOUT/STDIN to Network Connection in Container`, a stock Falco rule, unrelated to our scenarios) was observed firing normally, confirming the engine is evaluating live syscall events, not just started and idle.

**Caveat:** the fix is runtime-only (see Host section above) and will need to be reapplied after any future host reboot until it is persisted (e.g. via a `/etc/sysctl.d/99-falco-inotify.conf` entry).

## Phase 4 update: Helm release revisions and active rule hashes

As of Phase 4, the `falco` Helm release is at **revision 3** (revision 1: initial `install.sh` install; revision 2: first Phase 4 upgrade attempt, which accidentally dropped `--set` flags not captured in any values file — see `results/phase4_improved_rules_smoke.md` for the bug and its fix; revision 3: corrected upgrade with the original flags restored, confirmed via `helm get values falco -n falco`).

Active rule-file hashes as mounted inside a Falco pod at revision 3 (`sha256sum` of the raw rule-only YAML content, i.e. the value under each `customRules` key — not the local Helm values wrapper file, which has different bytes due to indentation/comments and is hashed separately in `rules/`):
- `/etc/falco/rules.d/pbl_rules.yaml` (baseline, unmodified): `7876a67970d04efa7f524f78529d37486141fad3abeeeec48f3e34b4912c03bf`
- `/etc/falco/rules.d/pbl_rules_improved.yaml` (Phase 4 addition): `5ffdd97c5b523348b5e65d5cd39e49f3ec3cf672dbac6425d948b638032c3360`

Local Helm values file hashes (`rules/baseline_falco_values.yaml` matches `category1/falco-values.yaml` byte-for-byte, confirmed in Phase 4): `60e72ff536f60552d2defb220a99e9ea23da4973bb0e9ff0fc19c48579e65977` (baseline values file) and `e1c584b9a03efe8e7cfe3dda37c1f0c544b054becd34fb5027e282366f618aba` (improved values file).
