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


## Hardening after independent verification (2026-09-12, checkpoint c7daba7)

- `setup_host.sh` now creates `beacon` with `/bin/sh`. OpenSSH runs forced commands through the login shell; `nologin`
  broke `beacon-cmd` on first deployment and the live hosts had been fixed by hand. Confinement is the
  `restrict,command=` key, not the shell.
- **Commit is recoverable.** If anything fails after the entropy host has generated `E` but before the pulse is durably
  written, the aggregator immediately abandons and finalizes that seq (`unpublished:<reason>`); `pulse.py
  abort-unpublished` does the same idempotently for any secret whose seq never entered the chain, and the cycle runs it
  before every commit.
- **`E` is removed at finalize**, for abandonments and reveals alike: the secret file is overwritten with zeros and
  fsynced, then replaced by a record without `E`. This is a **best-effort logical overwrite** — on SSDs and journaled
  filesystems it is not guaranteed physical destruction, and the custody claim says so.
- Every host statement carries a signed `execution` self-report: OS user, uid, whether it ran via the forced command,
  the `SSH_ORIGINAL_COMMAND` it saw, and the SHA-256 of `/usr/local/bin/beacon-cmd` and `/etc/beacon/host.json`. Self-
  reported — but signed with a key only the confined user holds — so it is consistent, checkable evidence of the
  confinement that pulse data alone previously could not show.


## Review #4 (2026-09-12): recovery, durability, enforcement

- **Recovery is derived from the published chain.** `pulse.py recover` runs first in every cycle: aborts secrets whose
  seq never entered the chain; finalizes a leftover `.revealing`/`.abandoning` whose resolving pulse is already
  published; and, if the head is an unresolved commit (a previous cycle died), the cycle **resumes** it — reveal within
  the window, signed failure after — instead of attempting a new commit and stalling.
- **The held secret is crash-durable** before the signed commitment leaves the entropy host: full write to a temp file,
  `fsync`, atomic rename, directory `fsync`, read-back check.
- **Rollback covers the SSH call itself**: a timeout or malformed reply after the host may have created a secret
  triggers the same idempotent abandonment; `recover` retries anything that slips through.
- **Execution self-reports are enforced from seq 26** (`schema.ENFORCE_EXECUTION_FROM_SEQ`), by the aggregator at mint
  and by the verifier: `user == beacon`, `via_forced_command`, `beacon_cmd_sha256` among the published values, and
  `host_config_sha256` equal to the per-host value in `hosts/EXPECTED.json`. Pulses 0020–0025 are isolated but predate the
  field or its enforcement and are not retroactively required to carry it.

## Cadence trigger edge (2026-09-13)

The time host now initiates one thing: p550's `beacon` user holds an outbound SSH key (`~beacon/.ssh/cadence_ed25519`)
that is authorised on think as
`restrict,from="192.168.68.43,192.168.68.44",command="/usr/bin/python3 /home/willy/qrng-beacon/beacon-trigger.py"`.
Through it, `hosts/beacon-cadence.py` delivers a **signed cadence trigger** at each scheduled instant; `beacon-trigger.py`
verifies it against `keys/KEYS.json` (p550's active `time_attester` key), requires it to be fresh (≤ 120 s), writes it to
`trigger/pending.json` and starts `qrng-beacon.service`. That is the whole capability: no shell, no file access, no
other unit. think's host key is pinned in `~beacon/.ssh/known_hosts` on p550.

What a compromised p550 `beacon` user gains from this edge: it could already forge p550's time statements; it can now
also start a cycle at an instant of its choosing. That is bounded (one cycle per hour on think, `.cycle-hour`) and
visible (every commit carries the trigger it was started from, `verify.py` checks the instant is a round boundary and
that the target round follows from it). The aggregator's keys, the entropy host and the other attest hosts are unchanged.
