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

## Cadence trigger edge (2026-09-13 13:00Z–15:00Z; superseded the same day by the UDP delivery described in the next section — kept as history)

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

## Aggregator on k3 (2026-09-13, from pulse 0096) — what changed in the trust picture

- The aggregator is the `aggregator` user on k3 (`~aggregator/beacon/aggregator.key`, the log's checkpoint key, a repo-scoped
  deploy key). Its SSH key is authorised on every role host's `beacon` user with the same `restrict,command="beacon-cmd"` line
  think's key has; think's line stays (think is the cold standby) but think's **aggregator signing key is retired** in
  `keys/KEYS.json`, so think cannot mint a pulse the verifier accepts without a public KEYS.json change.
- k3 now hosts **two roles in two confined users**: `beacon` (the `time_witness` signer, reached over loopback SSH through the
  forced command exactly as before) and `aggregator`. A host-level compromise of k3 gains both; a compromise of the aggregator
  user alone still cannot read the witness key or fabricate its statements. CLAIMS.md says so next to the witness claim.
- The p550 → think SSH edge for the cadence trigger (previous section) is **gone**. The time host now sends its signed trigger
  as a UDP datagram to the aggregator; there is no login, no forced command, no session. The aggregator accepts a datagram only
  if it is a `cadence-trigger` statement for the instant it is itself waiting on, signed by p550's active `time_attester` key;
  everything else is dropped and logged. A forged or replayed datagram cannot start, stop or steer a cycle — the cycle starts on
  the aggregator's own clock and the target follows from the instant, not from the datagram.
- Multiplexed SSH connections (`ControlMaster`) are opened ~40 s before the hour by the same forced-command calls a cycle makes
  (`noop`/`pending`; nothing is signed) so the calls after the instant cost ~0.1 s.

## Machine-to-machine service instead of SSH (2026-09-13, `hosts/agentd.py`)

Bill: *"machine to machine communication… not ssh."* Every role host now runs **`beacon-agentd`** as the same confined
`beacon` user, listening on TCP 5520 on the LAN. It answers exactly the operations the forced command answered, with
the same argument validation and the **same per-phase monotonic sequence file** (`~beacon/state.json`), so the two paths
cannot be played against each other. What changed is the transport and the authentication:

| element | SSH forced command (0018–…) | beacon-agentd |
|---|---|---|
| who may ask | holder of a key in `~beacon/.ssh/authorized_keys` | holder of an **aggregator Ed25519 key pinned in `/etc/beacon/agentd.json`** (the keys `keys/KEYS.json` lists) |
| how a request is authenticated | SSH session (key exchange + user auth), then `SSH_ORIGINAL_COMMAND` | **per message**: an Ed25519-signed statement `{to, op, args, from, ts, nonce, epk}`; refused unless addressed to this host, signed by a pinned key, within ±30 s and with an unseen nonce |
| what runs | sshd → login shell → `beacon-cmd` → host script | `beacon-agentd` → host script (same script, same user, `BEACON_VIA=agentd`) |
| attack surface | sshd, the shell, the forced-command parser | one Python process that parses a length-prefixed JSON message and verifies a signature; no shell, no file access, no other operation |
| secrets on the wire | inside the SSH channel | responses that carry a secret (`reveal-prepare`: E) are **sealed to the requester's ephemeral X25519 key** carried in the signed request (HKDF-SHA256 → ChaCha20-Poly1305, AAD = the request); everything else is a host-signed statement, public by design |
| cost per call (k3 → host) | 0.4–2.0 s cold, 0.07–0.2 s multiplexed | **7–9 ms** to reach the allow-list; the host script's own run time on top |
| self-report in the statement | `execution.via_forced_command: true`, `beacon_cmd_sha256` | `execution.via: "agentd"`, `agentd_sha256`, `request_nonce`; `schema.execution_ok` accepts either against `hosts/EXPECTED.json` |

Residual assumptions: the pinned aggregator keys are the only keys that can make a host sign; the LAN is not trusted
(nothing in the protocol relies on it); the host scripts run as `beacon` and cannot escalate; replay is bounded by the
nonce cache and the ±30 s window, and by the monotonic sequence for anything that signs. Verified 2026-09-13 from k3:
an unpinned key, a request addressed to another host, a stale timestamp, a replayed nonce and garbage are all refused;
a `noop` reaches the allow-list and is refused there. The SSH forced-command lines stay installed during the transition
and are removed once the aggregator has run on the daemon for a day.
