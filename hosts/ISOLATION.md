# ISOLATION.md — separating each host's keys and secrets from the aggregator (review #3, finding 1)

**Problem.** The aggregator (think) reaches each role host over SSH as the same OS user that owns that host's signing
key and, on the entropy host, the held entropy `E`. It can also pass an arbitrary role/probe to `attest_host.py`. So
"each host signs its own statement" was true, but "a dishonest aggregator cannot fabricate a host's facts" was not.

**Model.** On every role host:

| element | before | after |
|---|---|---|
| OS identity holding keys + secrets | `willy` / `root` (interactive user) | dedicated **`beacon`** user, no password, `~beacon/` mode 700 |
| what the aggregator's SSH key can do | full shell as that user | login **only as `beacon`**, with `restrict,command="/usr/local/bin/beacon-cmd"` — no shell, no pty, no forwarding, no scp |
| role / host / probe | supplied by the caller | **fixed** in `/etc/beacon/host.json` on the host |
| phase / seq / binding | trusted | validated locally: phase ∈ {commit,reveal,failure}, seq monotonic per phase (`~beacon/state.json`), binding = 64 hex |
| device access (p550 `/dev/ptp0`, k3 `/dev/ptp1`) | `sudo` / root | group membership (`ptp` / `clock`), no sudo |
| aggregator reading `E` or a private key | possible via shell | impossible: no shell, files owned by `beacon` 0600 |

The aggregator therefore gets exactly one capability per host: *ask this host to attest phase P for seq N bound to B*
(or, on the entropy host, commit / reveal-prepare / abandon-prepare / finalize / pending). It cannot choose the probe,
the role, the key, or read the secret.

**What this does and does not close.** It closes fabrication of host facts by the aggregator. It does not make the
hosts independent of the *operator*: the same person administers all machines. A hostile *operator* can still do
anything; a hostile or compromised *aggregator process/host* cannot. That is the honest boundary and it is stated in
`PROTOCOL.md`.

**Residual assumptions.** sshd honours `restrict` + forced command (documented OpenSSH behaviour); `beacon-cmd` has no
path to a shell; probes run as `beacon` cannot escalate. The operator's own admin access is out of scope.

**Rollout.** `setup_host.sh <role>` on each host (needs root once): creates the user, moves keys/secrets, installs
`beacon-cmd` and `host.json`, installs think's public key with the forced command, grants device group access, and
verifies think can attest and cannot open a shell. Keys do not change, so `KEYS.json` does not change.

## Operational rule learned on 2026-09-12 (the guard bit its author)

`beacon-cmd` enforces a **monotonic sequence per phase** and never lowers it. A test run on a production host with a
sacrificial `seq 997` therefore blocked the real `seq 20` until an operator reset `/home/beacon/state.json` as root.
Rule: **never exercise a production host's forced command with a sequence above the live chain.** Use `seq 0` only
before the chain exists on that host, or a separate test host configuration. Resetting the state file is an operator
action and should be recorded here when it happens (it happened once: protectli, 2026-09-12 02:49 UTC, 997 → 19).
