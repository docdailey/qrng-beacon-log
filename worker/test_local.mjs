// Local conformance test for worker/decisions.js against tlog.py's vectors and a Python-signed statement.
// Run: node worker/test_local.mjs <pkcs8 pem path> <vectors json>   (the vectors file is produced by the Python side)
import { readFileSync } from "node:fs";
import { _test as W } from "./decisions.js";
const [pemPath, vecPath] = process.argv.slice(2);
const V = JSON.parse(readFileSync(vecPath, "utf8"));
const enc = new TextEncoder();
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (h) => Uint8Array.from((h.match(/../g) || []).map((x) => parseInt(x, 16)));
let fails = 0; const ok = (c, m) => { console.log((c ? "[PASS] " : "[FAIL] ") + m); if (!c) fails++; };
// RFC 6962 vectors (CT test vectors, same as tlog.py selftest)
const H = []; for (const l of V.ct_leaves_hex) H.push(await W.leafHash(unhex(l)));
for (let n = 1; n <= H.length; n++) ok(hex(await W.mth(H.slice(0, n))) === V.ct_roots_hex[n - 1], `MTH(${n}) matches CT vector`);
for (const [m, n, proof] of V.ct_consistency) ok(JSON.stringify((await W.consistencyProof(m, H.slice(0, n))).map(hex)) === JSON.stringify(proof), `consistency ${m}->${n}`);
for (const [m, n, path] of V.ct_inclusion) ok(JSON.stringify((await W.inclusionPath(m, H.slice(0, n))).map(hex)) === JSON.stringify(path), `inclusion path ${m} of ${n}`);
// canonical JSON agrees with Python json.dumps(sort_keys, separators, ensure_ascii=False)
ok(W.canon(V.canon_obj) === V.canon_str, "canon() byte-identical to Python canonical JSON");
// a statement signed by the Python identity module verifies here
ok((await W.verifyStatement(V.statement, V.signature_b64)) === null, "Python-signed statement verifies in the Worker");
const tampered = { ...V.statement, decision_id: V.statement.decision_id + "x" };
ok((await W.verifyStatement(tampered, V.signature_b64)) !== null, "tampered statement is rejected");
// a note signed here verifies with tlog.py's key id + format (checked back in Python)
const env = { DECISIONS_SIGNING_KEY: readFileSync(pemPath, "utf8") };
const note = await W.signNote(env, 3, unhex(V.ct_roots_hex[2]));
const k = await W.signingKey(env);
console.log(JSON.stringify({ note, key_id_hex: hex(k.keyId), pub_b64: Buffer.from(k.pub).toString("base64") }));
process.exit(fails ? 1 : 0);
