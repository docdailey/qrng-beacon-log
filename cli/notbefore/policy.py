"""policy.py — one verification result type for every verifier in the package (review, project recommendation 1).

    VERIFIED   every required piece of evidence is present and passes
    DEGRADED   nothing failed, but evidence a preregistered result needs is missing (tokens, registration, unsigned contract,
               result not re-executed, anchors not re-checked); a DEGRADED artifact is a dry run and stays DEGRADED however
               it is bundled or re-checked
    INVALID    at least one check failed

`say()` records a check (PASS/FAIL, or an explicit INFO/WARN/WAIT level that never changes the verdict); `degrade()` records
missing-but-required evidence; `facts` carries authenticated values (signed anchor times, checkpoint roots) so that no caller
reads an unsigned copy. Human-readable lines are a rendering of this object, not the policy boundary. Exit codes: 0 / 2 / 1."""
EXIT = {"VERIFIED": 0, "DEGRADED": 2, "INVALID": 1}

class Verification:
    def __init__(self):
        self.lines = []; self.ok = True; self.degraded = []; self.facts = {}; self.verbose = []
    def say(self, ok, msg, level=None):
        tag = level or ("PASS" if ok else "FAIL")
        if tag == "FAIL": self.ok = False
        self.lines.append(f"[{tag}] {msg}")
    def degrade(self, why):
        self.degraded.append(why); self.lines.append(f"[DEGRADED] {why}")
    @property
    def verdict(self): return "INVALID" if not self.ok else ("DEGRADED" if self.degraded else "VERIFIED")
    @property
    def exit_code(self): return EXIT[self.verdict]
    def status(self):
        return {"verification": self.verdict, "ok": self.ok, "degraded": list(self.degraded), "lines": list(self.lines)}
