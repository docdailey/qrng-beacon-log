#!/bin/bash
# setup_host.sh — run as root ON a role host. Creates the `beacon` user, moves keys/secrets, installs the forced command.
#   setup_host.sh attest  <role> <host> <refid> <ptp-device-group> "<probe command...>"
#   setup_host.sh entropy <host>
set -e
KIND=$1; shift
FROM_HOME=${FROM_HOME:-/home/willy}; [ -d "$FROM_HOME/beacon" ] || FROM_HOME=/root
AGG_PUB=${AGG_PUB:?think public key required in AGG_PUB}
# The shell MUST be a real (minimal) shell: OpenSSH runs forced commands through the login shell, so nologin/false
# breaks beacon-cmd. Confinement comes from restrict,command="..." in authorized_keys, not from the shell.
id beacon >/dev/null 2>&1 || useradd -r -m -d /home/beacon -s /bin/sh beacon
usermod -s /bin/sh beacon
install -d -m 700 -o beacon -g beacon /home/beacon /home/beacon/beacon /home/beacon/.ssh /etc/beacon
# move keys, pending secrets and scripts from the interactive user to beacon (keys do not change)
for f in "$FROM_HOME"/beacon/*.key "$FROM_HOME"/beacon/*.pub "$FROM_HOME"/beacon/*.py; do [ -e "$f" ] && install -m 600 -o beacon -g beacon "$f" /home/beacon/beacon/; done
[ -d "$FROM_HOME/beacon/pending" ] && { install -d -m 700 -o beacon -g beacon /home/beacon/beacon/pending; cp -p "$FROM_HOME"/beacon/pending/* /home/beacon/beacon/pending/ 2>/dev/null || true; chown -R beacon:beacon /home/beacon/beacon/pending; }
install -m 755 -o root -g root "$(dirname "$0")/beacon-cmd" /usr/local/bin/beacon-cmd
if [ "$KIND" = attest ]; then
  ROLE=$1 HOST=$2 REFID=$3 GRP=$4; shift 4; PROBE="$*"
  python3 - "$ROLE" "$HOST" "$REFID" "$PROBE" <<'PY'
import json,sys,shlex; role,host,refid,probe=sys.argv[1:5]
json.dump({"kind":"attest","role":role,"host":host,"refid":refid,"probe":shlex.split(probe)},open("/etc/beacon/host.json","w"),indent=1)
PY
  [ -n "$GRP" ] && getent group "$GRP" >/dev/null && usermod -aG "$GRP" beacon
else
  HOST=$1; python3 -c "import json;json.dump({'kind':'entropy','role':'entropy_signer','host':'$HOST'},open('/etc/beacon/host.json','w'),indent=1)"
fi
chmod 644 /etc/beacon/host.json
echo "restrict,command=\"/usr/local/bin/beacon-cmd\" $AGG_PUB" > /home/beacon/.ssh/authorized_keys
chown beacon:beacon /home/beacon/.ssh/authorized_keys; chmod 600 /home/beacon/.ssh/authorized_keys
# shred the interactive user's copies of private keys and secrets AFTER the move (they are now beacon's)
for f in "$FROM_HOME"/beacon/*.key; do [ -e "$f" ] && shred -u "$f" 2>/dev/null || rm -f "$f"; done
rm -rf "$FROM_HOME"/beacon/pending
echo "OK: beacon user ready on $(hostname); config: $(cat /etc/beacon/host.json | tr -d '\n ')"
