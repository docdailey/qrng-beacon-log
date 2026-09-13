-- migrate-001 (2026-09-13, R7): drop the GLOBAL uniqueness of contract_sha256; make it unique per (key_id, decision_id).
-- SQLite cannot drop a column constraint in place: rebuild the table, copy rows in index order, keep every leaf byte identical.
CREATE TABLE IF NOT EXISTS entries_new (
  idx INTEGER PRIMARY KEY, key_id TEXT NOT NULL, decision_id TEXT NOT NULL, seq_in_ns INTEGER NOT NULL,
  contract_sha256 TEXT NOT NULL, leaf TEXT NOT NULL, leaf_hash TEXT NOT NULL, received_utc TEXT NOT NULL,
  tsa_freetsa BLOB, tsa_digicert BLOB, contract TEXT,
  UNIQUE (key_id, decision_id, seq_in_ns),
  UNIQUE (key_id, decision_id, contract_sha256)
);
INSERT INTO entries_new (idx, key_id, decision_id, seq_in_ns, contract_sha256, leaf, leaf_hash, received_utc, tsa_freetsa, tsa_digicert, contract)
  SELECT idx, key_id, decision_id, seq_in_ns, contract_sha256, leaf, leaf_hash, received_utc, tsa_freetsa, tsa_digicert, contract FROM entries ORDER BY idx;
DROP TABLE entries;
ALTER TABLE entries_new RENAME TO entries;
CREATE INDEX IF NOT EXISTS entries_ns ON entries (key_id, decision_id);
