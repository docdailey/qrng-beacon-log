#!/usr/bin/env python3
"""attest_host.py — runs ON a measurement host (p550, k3, f9t). Runs the host's OWN probe and signs
the result as a statement bound to a specific pulse. The aggregator cannot alter the measurement
without breaking the host's signature.

  attest_host.py <role> <host> <seq> <phase> <binding> <chain_hash> -- <probe command...>
"""
import sys, os, json, subprocess, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attest_lib as A

def main():
    a = sys.argv[1:]; i = a.index("--")
    role, host, seq, phase, binding, chain_hash = a[:6]; probe = a[i + 1:]
    r = subprocess.run(probe, capture_output=True, text=True, timeout=120)
    if r.returncode != 0: sys.stderr.write(r.stderr); sys.exit(2)
    measurement = json.loads(r.stdout)
    probe_script = next((p for p in probe if p.endswith(".py")), None)
    tools = A.tool_binding(__file__, os.path.join(os.path.dirname(os.path.abspath(__file__)), "attest_lib.py"),
                           *( [os.path.expanduser(probe_script)] if probe_script and os.path.exists(os.path.expanduser(probe_script)) else [] ))
    st = A.base_statement(role, host, seq, phase, binding, chain_hash, tools)
    st.update({"probe_command": " ".join(probe), "measurement": measurement,
               "measurement_sha256": hashlib.sha256(A.canon(A.normalize(measurement))).hexdigest()})
    print(json.dumps(A.sign_statement(role, st)))

if __name__ == "__main__":
    main()
