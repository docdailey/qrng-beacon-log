"""Read the public log as DATA. Nothing from the log is ever executed: the verifier and keys are vendored in this package."""
import os, subprocess, tempfile, json, shutil
from . import DEFAULT_REPO

SIDE = ("", ".tsa.json", ".freetsa.tsr", ".digicert.tsr")

class LogError(Exception): pass

def _git(*a, cwd=None, check=True):
    r = subprocess.run(["git", *a], cwd=cwd, capture_output=True, text=True)
    if check and r.returncode: raise LogError(f"git {' '.join(a)}: {(r.stderr or r.stdout).strip()[:300]}")
    return r

class LogSource:
    """Either a remote clone kept in a cache directory (default) or a local directory (--log-dir)."""
    def __init__(self, repo=DEFAULT_REPO, log_dir=None, cache=None, ref=None, offline=False):
        self.repo, self.offline = repo, offline
        self.tmp = tempfile.mkdtemp(prefix="notbefore-")
        if log_dir:
            self.dir = os.path.abspath(log_dir); self.mode = "dir"
            self.is_git = _git("rev-parse", "--is-inside-work-tree", cwd=self.dir, check=False).returncode == 0
            self.ref = ref                      # None -> working tree
        else:
            self.dir = cache or os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "notbefore", "qrng-beacon-log")
            self.mode = "cache"; self.is_git = True
            if not os.path.isdir(os.path.join(self.dir, ".git")):
                if offline: raise LogError(f"no cached clone at {self.dir} and --offline given")
                os.makedirs(os.path.dirname(self.dir), exist_ok=True); _git("clone", "--quiet", repo, self.dir)
            elif not offline:
                _git("fetch", "--quiet", "--prune", "origin", cwd=self.dir)
            self.ref = ref or "origin/main"
        self.log_git_sha = self._sha()

    def _sha(self):
        if not self.is_git: return "unknown (not a git checkout)"
        return _git("rev-parse", self.ref or "HEAD", cwd=self.dir).stdout.strip()

    def close(self): shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- files
    def _read(self, relpath):
        """Bytes of a file at the pinned ref (or the working tree for a plain --log-dir). None if absent."""
        if self.mode == "dir" and self.ref is None:
            p = os.path.join(self.dir, relpath); return open(p, "rb").read() if os.path.exists(p) else None
        r = _git("show", f"{self.ref}:{relpath}", cwd=self.dir, check=False)
        return r.stdout.encode("utf-8", "surrogateescape") if r.returncode == 0 else None

    def _read_bytes(self, relpath):
        # binary-safe variant for .tsr (git show via text mode would mangle bytes)
        if self.mode == "dir" and self.ref is None:
            p = os.path.join(self.dir, relpath); return open(p, "rb").read() if os.path.exists(p) else None
        r = subprocess.run(["git", "show", f"{self.ref}:{relpath}"], cwd=self.dir, capture_output=True)
        return r.stdout if r.returncode == 0 else None

    def has_pulse(self, seq): return self._read_bytes(f"chain/pulse-{seq:04d}.json") is not None

    def materialize(self, seq):
        """Write chain/pulse-NNNN.json and its TSA sidecars into the temp dir; return the pulse path (or None)."""
        out = os.path.join(self.tmp, "chain"); os.makedirs(out, exist_ok=True)
        base = f"chain/pulse-{seq:04d}.json"; main = None
        for s in SIDE:
            b = self._read_bytes(base + s)
            if b is None:
                if s == "": return None
                continue
            p = os.path.join(out, os.path.basename(base + s)); open(p, "wb").write(b)
            if s == "": main = p
        return main

    def pulse(self, seq):
        b = self._read_bytes(f"chain/pulse-{seq:04d}.json"); return json.loads(b) if b else None

    # ---- anchors branch
    def anchors_available(self):
        if not self.is_git: return os.path.isdir(os.path.join(self.dir, "anchors"))
        have = lambda: _git("rev-parse", "--verify", "--quiet", "origin/anchors", cwd=self.dir, check=False).returncode == 0
        if not have() and not self.offline: _git("fetch", "-q", "origin", "anchors", cwd=self.dir, check=False)   # a plain clone may not have the branch yet
        return have() or os.path.isdir(os.path.join(self.dir, "anchors"))

    def anchor(self, seq):
        """(record dict, statement bytes) for a pulse from origin/anchors (or an anchors/ worktree), or (None, None)."""
        rec = stmt = None
        if self.is_git:
            r = subprocess.run(["git", "show", f"origin/anchors:pulse-{seq:04d}.anchor.json"], cwd=self.dir, capture_output=True)
            s = subprocess.run(["git", "show", f"origin/anchors:pulse-{seq:04d}.stmt.json"], cwd=self.dir, capture_output=True)
            if r.returncode == 0 and s.returncode == 0: rec, stmt = json.loads(r.stdout), s.stdout
        if rec is None:
            d = os.path.join(self.dir, "anchors")
            rp, sp = os.path.join(d, f"pulse-{seq:04d}.anchor.json"), os.path.join(d, f"pulse-{seq:04d}.stmt.json")
            if os.path.exists(rp) and os.path.exists(sp): rec, stmt = json.load(open(rp)), open(sp, "rb").read()
        return rec, stmt
