// notbefore.net/decisions — the NotBefore decision log (DECISION-LOG.md, NOTBEFORE.md §7.12).
// A public, write-once, append-only RFC 6962 log of Ed25519-signed decision statements, checkpointed as c2sp signed
// notes under the origin "notbefore.net/decisions". Storage: D1 (binding DB). Signing key: secret DECISIONS_SIGNING_KEY
// (PKCS8 PEM of the Ed25519 key whose public half is keys/decisions.pub in the repository — clients verify against
// THAT, never against anything this Worker says about itself).
//
// Write-once rule: (key_id, decision_id) is a namespace. The first valid statement appended for it gets
// seq_in_namespace 1 and is the authoritative preregistration; later ones are amendments (2, 3, ...). A statement whose
// contract_sha256 is already in the log is returned as-is (idempotent). Nothing is ever updated or deleted.
//
// Byte formats match tlog.py exactly: leaf = canonical JSON (sorted keys, no spaces); leaf hash = SHA256(0x00 || leaf);
// node = SHA256(0x01 || l || r); checkpoint = "origin\nsize\nroot_b64\n\n— origin base64(keyid4 || sig64)\n",
// keyid = SHA256(origin || "\n" || 0x01 || pubkey)[:4]; signature over the three-line text.

const ORIGIN = "notbefore.net/decisions";
const DECISION_SPEC = "notbefore/decision/1", LEAF_SPEC = "notbefore/decision-leaf/1";
const ID_RE = /^[A-Za-z0-9._:\/=@+-]{1,256}$/, HEX64 = /^[0-9a-f]{64}$/, HEX16 = /^[0-9a-f]{16}$/;
const MAX_BODY = 160 * 1024, MAX_TOKEN = 32 * 1024, MAX_CONTRACT = 64 * 1024, PAGE = 500;
const enc = new TextEncoder(), dec = new TextDecoder();

// ---------------------------------------------------------------- bytes
const b64 = (u8) => btoa(String.fromCharCode(...u8));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const cat = (...parts) => { const n = parts.reduce((a, p) => a + p.length, 0), out = new Uint8Array(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const sha256 = async (u8) => new Uint8Array(await crypto.subtle.digest("SHA-256", u8));
function canon(o) {                                   // RFC 8785-compatible for the value space we use: strings, ints, bools, objects, arrays
  if (o === null || typeof o !== "object") return JSON.stringify(o);
  if (Array.isArray(o)) return "[" + o.map(canon).join(",") + "]";
  return "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + canon(o[k])).join(",") + "}";
}
const utcnow = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

// ---------------------------------------------------------------- RFC 6962 over precomputed leaf hashes
const leafHash = async (leafBytes) => sha256(cat(new Uint8Array([0]), leafBytes));
const nodeHash = async (l, r) => sha256(cat(new Uint8Array([1]), l, r));
function k2(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }              // largest power of two strictly below n (n >= 2)
async function mth(H) {                                                          // H: array of leaf hashes
  if (H.length === 0) return sha256(new Uint8Array(0));
  if (H.length === 1) return H[0];
  const k = k2(H.length); return nodeHash(await mth(H.slice(0, k)), await mth(H.slice(k)));
}
async function inclusionPath(m, H) {                                             // PATH(m, D[0:n])
  const n = H.length; if (n <= 1) return [];
  const k = k2(n);
  if (m < k) return [...(await inclusionPath(m, H.slice(0, k))), await mth(H.slice(k))];
  return [...(await inclusionPath(m - k, H.slice(k))), await mth(H.slice(0, k))];
}
async function consistencyProof(m, H) { const n = H.length; if (m === 0 || m > n) throw new Error("bad m"); if (m === n) return []; return subproof(m, H, true); }
async function subproof(m, D, b) {
  const n = D.length; if (m === n) return b ? [] : [await mth(D)];
  const k = k2(n);
  if (m <= k) return [...(await subproof(m, D.slice(0, k), b)), await mth(D.slice(k))];
  return [...(await subproof(m - k, D.slice(k), false)), await mth(D.slice(0, k))];
}

// ---------------------------------------------------------------- keys + notes
let KEY = null;
async function signingKey(env) {
  if (KEY) return KEY;
  const pem = env.DECISIONS_SIGNING_KEY; if (!pem) throw new Error("DECISIONS_SIGNING_KEY not configured");
  const der = unb64(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
  const priv = await crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", priv);                       // public half from the JWK 'x'
  const pub = unb64(jwk.x.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - (jwk.x.length % 4)) % 4));
  const keyId = (await sha256(cat(enc.encode(ORIGIN + "\n"), new Uint8Array([1]), pub))).slice(0, 4);
  KEY = { priv, pub, keyId }; return KEY;
}
async function signNote(env, size, root) {
  const k = await signingKey(env);
  const text = `${ORIGIN}\n${size}\n${b64(root)}\n`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, k.priv, enc.encode(text)));
  return text + "\n— " + ORIGIN + " " + b64(cat(k.keyId, sig)) + "\n";
}
async function verifyStatement(st, sigB64) {
  if (!st || st.spec !== DECISION_SPEC) return "not a " + DECISION_SPEC + " statement";
  if (!ID_RE.test(st.decision_id || "")) return "decision_id must match ^[A-Za-z0-9._:/=@+-]{1,256}$";
  if (!HEX64.test(st.contract_sha256 || "")) return "contract_sha256 must be 64 hex";
  if (!HEX16.test(st.key_id || "")) return "key_id must be 16 hex";
  if (Object.keys(st).length !== 7) return "statement has unexpected shape";
  if (typeof st.contract_spec !== "string" || !/^notbefore\/contract\/\d{1,3}$/.test(st.contract_spec)) return "contract_spec must be notbefore/contract/<n>";
  if (typeof st.created_utc !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(st.created_utc)) return "created_utc must be YYYY-MM-DDTHH:MM:SSZ";
  let pub; try { pub = unb64(st.public_key_b64); } catch { return "public_key_b64 is not base64"; }
  if (pub.length !== 32) return "public key must be 32 bytes";
  if (hex(await sha256(pub)).slice(0, 16) !== st.key_id) return "key_id is not SHA256(public_key)[:16]";
  let sig; try { sig = unb64(sigB64 || ""); } catch { return "signature_b64 is not base64"; }
  if (sig.length !== 64) return "signature must be 64 bytes";
  const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, enc.encode(canon(st)));
  return ok ? null : "Ed25519 signature does not verify over the canonical statement";
}

// ---------------------------------------------------------------- storage
async function leafHashes(db) {
  const { results } = await db.prepare("SELECT leaf_hash FROM entries ORDER BY idx").all();
  return results.map((r) => unhex(r.leaf_hash));
}
async function latestCheckpoint(env, db) {
  const H = await leafHashes(db); const size = H.length;
  const row = await db.prepare("SELECT note FROM checkpoints WHERE size = ?").bind(size).first();
  if (row) return { note: row.note, size, H };
  const root = await mth(H); const note = await signNote(env, size, root);           // sign on demand, store once
  await db.prepare("INSERT OR IGNORE INTO checkpoints(size, root_hex, note, created_utc) VALUES (?,?,?,?)").bind(size, hex(root), note, utcnow()).run();
  return { note, size, H };
}
async function appendEntry(env, db, st, sigB64, tokens, contract) {
  const existing = await db.prepare("SELECT idx, seq_in_ns, received_utc, leaf FROM entries WHERE key_id = ? AND decision_id = ? AND contract_sha256 = ?").bind(st.key_id, st.decision_id, st.contract_sha256).first();
  if (existing) return { ...existing, existed: true };                            // idempotent WITHIN the signer's namespace (R7): another key claiming the same hash gets its own entry
  for (let attempt = 0; attempt < 4; attempt++) {
    const n = (await db.prepare("SELECT COUNT(*) AS c FROM entries").first()).c;
    const k = (await db.prepare("SELECT COUNT(*) AS c FROM entries WHERE key_id = ? AND decision_id = ?").bind(st.key_id, st.decision_id).first()).c + 1;
    const received = utcnow();
    const tsaSha = {}; for (const [name, bytes] of Object.entries(tokens)) tsaSha[name] = hex(await sha256(bytes));
    const leaf = { spec: LEAF_SPEC, index: n, received_utc: received, seq_in_namespace: k, statement: st, signature_b64: sigB64, tsa_sha256: tsaSha, contract_disclosed: contract !== null };
    const leafText = canon(leaf); const lh = hex(await leafHash(enc.encode(leafText)));
    try {
      await db.prepare("INSERT INTO entries(idx, key_id, decision_id, seq_in_ns, contract_sha256, leaf, leaf_hash, received_utc, tsa_freetsa, tsa_digicert, contract) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
        .bind(n, st.key_id, st.decision_id, k, st.contract_sha256, leafText, lh, received, tokens.freetsa || null, tokens.digicert || null, contract ? canon(contract) : null).run();
      return { idx: n, seq_in_ns: k, received_utc: received, leaf: leafText, existed: false };
    } catch (e) {                                                                // UNIQUE(idx) or UNIQUE(ns, seq) raced: recompute and retry
      if (!/UNIQUE|constraint/i.test(String(e.message || e))) throw e;
      const again = await db.prepare("SELECT idx, seq_in_ns, received_utc, leaf FROM entries WHERE key_id = ? AND decision_id = ? AND contract_sha256 = ?").bind(st.key_id, st.decision_id, st.contract_sha256).first();
      if (again) return { ...again, existed: true };
    }
  }
  throw new Error("append raced too many times");
}

// ---------------------------------------------------------------- HTTP
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store" };
const json = (o, status = 200) => new Response(JSON.stringify(o, null, 1) + "\n", { status, headers: { ...CORS, "Content-Type": "application/json; charset=utf-8" } });
const text = (s, status = 200, ctype = "text/plain; charset=utf-8") => new Response(s, { status, headers: { ...CORS, "Content-Type": ctype } });
const bad = (msg, status = 400) => json({ error: msg }, status);

async function handle(req, env) {
  const url = new URL(req.url); const p = url.pathname.replace(/\/+$/, "") || "/";
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  const db = env.DB; if (!db) return bad("decision log storage not configured", 503);
  let m;
  if (p === "/decisions" && req.method === "GET") {
    const { note, size } = await latestCheckpoint(env, db); const k = await signingKey(env);
    return json({ origin: ORIGIN, spec: DECISION_SPEC, leaf_spec: LEAF_SPEC, size, checkpoint: note, verifier_key: `${ORIGIN}+${hex(k.keyId)}+${b64(cat(new Uint8Array([1]), k.pub))}`,
      rule: "write-once: the first valid statement for (key_id, decision_id) is the authoritative preregistration; later ones are amendments (seq_in_namespace > 1)",
      endpoints: ["GET /decisions/checkpoint", "GET /decisions/checkpoint/<size>", "GET /decisions/entry/<index>[/contract|/tsa/<name>]", "GET /decisions/proof/<index>?size=", "GET /decisions/consistency?old=&new=", "GET /decisions/lookup?key_id=&decision_id=", "GET /decisions/leaves?from=&to=", "POST /decisions/submit"],
      mirror: "https://github.com/docdailey/qrng-beacon-log/tree/main/decisions", spec_url: "https://github.com/docdailey/qrng-beacon-log/blob/main/DECISION-LOG.md" });
  }
  if (p === "/decisions/checkpoint" && req.method === "GET") return text((await latestCheckpoint(env, db)).note);
  if ((m = p.match(/^\/decisions\/checkpoint\/(\d+)$/)) && req.method === "GET") {
    const row = await db.prepare("SELECT note FROM checkpoints WHERE size = ?").bind(+m[1]).first(); return row ? text(row.note) : bad("no checkpoint stored at that size", 404);
  }
  if ((m = p.match(/^\/decisions\/entry\/(\d+)$/)) && req.method === "GET") {
    const row = await db.prepare("SELECT leaf FROM entries WHERE idx = ?").bind(+m[1]).first(); return row ? text(row.leaf, 200, "application/json; charset=utf-8") : bad("no such entry", 404);
  }
  if ((m = p.match(/^\/decisions\/entry\/(\d+)\/contract$/)) && req.method === "GET") {
    const row = await db.prepare("SELECT contract FROM entries WHERE idx = ?").bind(+m[1]).first(); return row && row.contract ? text(row.contract, 200, "application/json; charset=utf-8") : bad("no disclosed contract for that entry", 404);
  }
  if ((m = p.match(/^\/decisions\/entry\/(\d+)\/tsa\/(freetsa|digicert)$/)) && req.method === "GET") {
    const row = await db.prepare(`SELECT tsa_${m[2]} AS t FROM entries WHERE idx = ?`).bind(+m[1]).first();
    return row && row.t ? new Response(row.t, { headers: { ...CORS, "Content-Type": "application/timestamp-reply" } }) : bad("no such token", 404);
  }
  if ((m = p.match(/^\/decisions\/proof\/(\d+)$/)) && req.method === "GET") {
    const H = await leafHashes(db); const idx = +m[1]; const size = url.searchParams.has("size") ? +url.searchParams.get("size") : H.length;
    if (!(size >= 1 && size <= H.length) || !(idx >= 0 && idx < size)) return bad("index/size out of range");
    const sub = H.slice(0, size); return json({ index: idx, size, root_b64: b64(await mth(sub)), proof: (await inclusionPath(idx, sub)).map(b64) });
  }
  if (p === "/decisions/consistency" && req.method === "GET") {
    const H = await leafHashes(db); const a = +url.searchParams.get("old"), b = +url.searchParams.get("new");
    if (!(a >= 1 && a <= b && b <= H.length)) return bad("need 1 <= old <= new <= size");
    return json({ old: a, new: b, old_root_b64: b64(await mth(H.slice(0, a))), new_root_b64: b64(await mth(H.slice(0, b))), proof: (await consistencyProof(a, H.slice(0, b))).map(b64) });
  }
  if (p === "/decisions/leaves" && req.method === "GET") {
    const from = +(url.searchParams.get("from") || 0), to = Math.min(+(url.searchParams.get("to") || from + PAGE), from + PAGE);
    const { results } = await db.prepare("SELECT idx, leaf FROM entries WHERE idx >= ? AND idx < ? ORDER BY idx").bind(from, to).all();
    const size = (await db.prepare("SELECT COUNT(*) AS c FROM entries").first()).c;
    return json({ from, to, size, leaves: results.map((r) => r.leaf) });
  }
  if (p === "/decisions/lookup" && req.method === "GET") {
    const key_id = url.searchParams.get("key_id") || "", decision_id = url.searchParams.get("decision_id") || "";
    if (!HEX16.test(key_id) || !ID_RE.test(decision_id)) return bad("key_id (16 hex) and decision_id required");
    const { results } = await db.prepare("SELECT idx, seq_in_ns, contract_sha256, received_utc, leaf FROM entries WHERE key_id = ? AND decision_id = ? ORDER BY seq_in_ns").bind(key_id, decision_id).all();
    const { note, size, H } = await latestCheckpoint(env, db);
    const entries = results.map((r) => ({ index: r.idx, seq_in_namespace: r.seq_in_ns, contract_sha256: r.contract_sha256, received_utc: r.received_utc }));
    const out = { key_id, decision_id, size, checkpoint: note, entries, authoritative: null };
    if (results.length) { const f = results[0]; out.authoritative = { index: f.idx, leaf: f.leaf, proof: (await inclusionPath(f.idx, H)).map(b64) }; }
    return json(out);
  }
  if (p === "/decisions/submit" && req.method === "POST") {
    if (+(req.headers.get("content-length") || 0) > MAX_BODY) return bad("body too large", 413);
    const raw = await req.text();                                                    // the header is advisory: measure what arrived (R8)
    if (enc.encode(raw).length > MAX_BODY) return bad("body too large", 413);
    let body; try { body = JSON.parse(raw); } catch { return bad("body must be JSON"); }
    const st = body.statement, err = await verifyStatement(st, body.signature_b64); if (err) return bad(err);
    const tokens = {};
    for (const name of ["freetsa", "digicert"]) {
      const v = body.tsa_tokens && body.tsa_tokens[name]; if (v == null) continue;
      let t; try { t = unb64(v); } catch { return bad(`tsa_tokens.${name} is not base64`); }
      if (t.length > MAX_TOKEN || t[0] !== 0x30) return bad(`tsa_tokens.${name} is not a DER token`); tokens[name] = t;
    }
    let contract = null;
    if (body.contract !== undefined) {
      if (typeof body.contract !== "object" || body.contract === null) return bad("contract must be an object");
      const ctext = canon(body.contract); if (enc.encode(ctext).length > MAX_CONTRACT) return bad("contract too large");   // UTF-8 bytes, not UTF-16 code units (R8)
      if (hex(await sha256(enc.encode(ctext))) !== st.contract_sha256) return bad("disclosed contract does not hash to statement.contract_sha256");
      contract = body.contract;
    }
    const e = await appendEntry(env, db, st, body.signature_b64, tokens, contract);
    const { note, size, H } = await latestCheckpoint(env, db);
    return json({ index: e.idx, seq_in_namespace: e.seq_in_ns, authoritative: e.seq_in_ns === 1, existing: !!e.existed, received_utc: e.received_utc, leaf: e.leaf, size, checkpoint: note, proof: (await inclusionPath(e.idx, H)).map(b64) }, e.existed ? 200 : 201);
  }
  return bad("not found", 404);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.hostname === "www.notbefore.net") {                                    // one canonical host: www -> apex, path and query kept
      url.hostname = "notbefore.net"; return Response.redirect(url.toString(), 301);
    }
    if (url.pathname === "/decisions" || url.pathname.startsWith("/decisions/")) {
      try { return await handle(req, env); } catch (e) { return json({ error: "internal: " + (e.message || String(e)) }, 500); }
    }
    return env.ASSETS.fetch(req);                                                // everything else: the static repository
  },
};
export const _test = { canon, mth, inclusionPath, consistencyProof, leafHash, verifyStatement, signNote, signingKey };
