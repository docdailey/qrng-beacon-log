-- notbefore.net/decisions — D1 schema. Append-only by construction: nothing here is ever UPDATEd or DELETEd.
CREATE TABLE IF NOT EXISTS entries (
  idx INTEGER PRIMARY KEY,                    -- 0-based RFC 6962 leaf index, assigned in arrival order
  key_id TEXT NOT NULL,                       -- SHA256(consumer pubkey)[:16]
  decision_id TEXT NOT NULL,
  seq_in_ns INTEGER NOT NULL,                 -- 1 = the authoritative preregistration for (key_id, decision_id); >1 = amendments
  contract_sha256 TEXT NOT NULL,              -- unique per NAMESPACE (below), not globally: a hash is not a claim on anyone else's namespace (R7)
  leaf TEXT NOT NULL,                         -- canonical leaf JSON exactly as hashed
  leaf_hash TEXT NOT NULL,                    -- hex SHA256(0x00 || leaf)
  received_utc TEXT NOT NULL,
  tsa_freetsa BLOB, tsa_digicert BLOB,        -- the consumer's RFC 3161 tokens over the contract bytes, if supplied
  contract TEXT,                              -- the contract itself, if the consumer chose to disclose it at submission
  UNIQUE (key_id, decision_id, seq_in_ns),
  UNIQUE (key_id, decision_id, contract_sha256)   -- idempotent retry within the signer's namespace
);
CREATE INDEX IF NOT EXISTS entries_ns ON entries (key_id, decision_id);
CREATE TABLE IF NOT EXISTS checkpoints (
  size INTEGER PRIMARY KEY,
  root_hex TEXT NOT NULL,
  note TEXT NOT NULL,                         -- the signed note served for this size (log signature only; witnesses cosign in the git mirror)
  created_utc TEXT NOT NULL
);
