//! Append-only SQLite custody ledger with a SHA-256 hash chain.
//!
//! Each row's `entry_hash` chains to the previous row. Rows can also carry
//! an Ed25519 operator signature over their `entry_hash` (see
//! [`Ledger::append_signed`] and [`Ledger::verify_chain_signed`]):
//! the hash chain alone is a checksum log — anyone with write access to
//! the database can rewrite rows and recompute the hashes — while a
//! signature can only be made by whoever holds the operator's signing
//! seed. Signed verification therefore catches a chain rewrite that the
//! hash-only check misses. Rows written before signing existed, or
//! without a signing key, have `signature = NULL` and still pass the
//! hash-only [`Ledger::verify_chain`].
//!
//! The chain tip (the last row's `entry_hash`, see [`Ledger::chain_tip`])
//! should be recorded in a second location at acquisition time; see
//! `SECURITY.md` for the anchoring procedure.

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand_core::RngCore;
use rusqlite::{params, Connection, OptionalExtension};

use arcana_core::{sha256_bytes, unix_now, ArcanaError};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone)]
pub struct CustodyEvent {
    pub id: i64,
    pub ts: i64,
    pub operator: String,
    pub action: String,
    pub path: String,
    pub sha256: String,
    pub prev_hash: String,
    pub entry_hash: String,
    /// Hex Ed25519 signature of `entry_hash`, or `None` for unsigned
    /// (legacy) rows.
    pub signature: Option<String>,
}

// ---------------------------------------------------------------------------
// Operator signing keys (Ed25519).
// ---------------------------------------------------------------------------
// The signing seed (32 bytes, hex) is SECRET: keep it offline, never in
// the case directory, never in git. Load it for acquisition only, via
// ARCANA_SIGNING_KEY. The verifying key (32 bytes, hex) is PUBLIC:
// record it with the case and anchor it with the chain tip (see
// `Ledger::chain_tip` and SECURITY.md). Signing is per-row, over the
// UTF-8 bytes of the entry_hash hex string.

/// Generates a fresh random Ed25519 operator keypair.
/// Returns `(signing_seed_bytes, verifying_key_bytes)` — both 32 bytes.
/// The seed is secret; the verifying key is public and shareable.
pub fn generate_operator_keypair() -> ([u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying = signing_key.verifying_key().to_bytes();
    (seed, verifying)
}

/// Builds a signing key from a 64-hex-character seed (e.g. ARCANA_SIGNING_KEY).
pub fn signing_key_from_seed_hex(seed_hex: &str) -> Result<SigningKey, ArcanaError> {
    let bytes = hex::decode(seed_hex)
        .map_err(|e| ArcanaError::InvalidSigningKey(format!("seed is not hex: {e}")))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| {
        ArcanaError::InvalidSigningKey("seed must be exactly 32 bytes (64 hex chars)".into())
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Builds a verifying key from a 64-hex-character public key.
pub fn verifying_key_from_hex(key_hex: &str) -> Result<VerifyingKey, ArcanaError> {
    let bytes = hex::decode(key_hex)
        .map_err(|e| ArcanaError::InvalidSigningKey(format!("verifying key is not hex: {e}")))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        ArcanaError::InvalidSigningKey(
            "verifying key must be exactly 32 bytes (64 hex chars)".into(),
        )
    })?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| ArcanaError::InvalidSigningKey(format!("invalid verifying key: {e}")))
}

/// Signs one entry_hash with the operator key. Returns the 64-byte signature as hex.
pub fn sign_entry_hash(signing_key: &SigningKey, entry_hash: &str) -> String {
    let signature: Signature = signing_key.sign(entry_hash.as_bytes());
    hex::encode(signature.to_bytes())
}

/// Verifies one entry_hash signature. Returns false (never panics) on bad
/// hex, wrong length, or a signature made by a different key / for a
/// different hash.
pub fn verify_entry_signature(
    verifying_key: &VerifyingKey,
    entry_hash: &str,
    signature_hex: &str,
) -> bool {
    let Ok(bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(arr) = <[u8; 64]>::try_from(bytes) else {
        return false;
    };
    let signature = Signature::from_bytes(&arr);
    verifying_key
        .verify(entry_hash.as_bytes(), &signature)
        .is_ok()
}

pub struct Ledger {
    conn: Connection,
}

impl Ledger {
    pub fn open(path: &Path) -> Result<Self, ArcanaError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path).map_err(|e| ArcanaError::Ledger(e.to_string()))?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS custody_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                operator TEXT NOT NULL,
                action TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE,
                signature TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_custody_sha ON custody_events(sha256);
            ",
        )
        .map_err(|e| ArcanaError::Ledger(e.to_string()))?;
        // Ledgers created before signing existed have no `signature`
        // column; add it so old rows keep verifying (as NULL) and new
        // rows can be signed.
        let has_signature: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('custody_events') WHERE name = 'signature'")
            .and_then(|mut stmt| stmt.exists([]))
            .map_err(|e| ArcanaError::Ledger(e.to_string()))?;
        if !has_signature {
            conn.execute(
                "ALTER TABLE custody_events ADD COLUMN signature TEXT",
                [],
            )
            .map_err(|e| ArcanaError::Ledger(e.to_string()))?;
        }
        Ok(Self { conn })
    }

    /// Starts a write transaction. Pair with [`Ledger::commit`] on
    /// success or [`Ledger::rollback`] on failure, so a run's ledger
    /// rows commit together or not at all.
    pub fn begin(&self) -> Result<(), ArcanaError> {
        self.conn
            .execute("BEGIN IMMEDIATE", [])
            .map(|_| ())
            .map_err(|e| ArcanaError::Ledger(e.to_string()))
    }

    pub fn commit(&self) -> Result<(), ArcanaError> {
        self.conn
            .execute("COMMIT", [])
            .map(|_| ())
            .map_err(|e| ArcanaError::Ledger(e.to_string()))
    }

    pub fn rollback(&self) -> Result<(), ArcanaError> {
        self.conn
            .execute("ROLLBACK", [])
            .map(|_| ())
            .map_err(|e| ArcanaError::Ledger(e.to_string()))
    }

    fn tip_hash(&self) -> Result<String, ArcanaError> {
        let hash: Option<String> = self
            .conn
            .query_row(
                "SELECT entry_hash FROM custody_events ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ArcanaError::Ledger(e.to_string()))?;
        Ok(hash.unwrap_or_else(|| GENESIS.to_string()))
    }

    /// Returns the chain tip — the entry_hash of the most recent custody
    /// row. Record this value (with the operator's verifying key) in a
    /// second location at acquisition time; see SECURITY.md. Errors on an
    /// empty ledger.
    pub fn chain_tip(&self) -> Result<String, ArcanaError> {
        self.conn
            .query_row(
                "SELECT entry_hash FROM custody_events ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| ArcanaError::Ledger(e.to_string()))
    }

    /// Appends an unsigned (legacy) row. Kept for backward
    /// compatibility; see [`Ledger::append_signed`].
    pub fn append(
        &self,
        operator: &str,
        action: &str,
        path: &str,
        sha256: &str,
    ) -> Result<CustodyEvent, ArcanaError> {
        self.append_signed(operator, action, path, sha256, None)
    }

    /// Appends a custody row, signing its entry_hash when a signing key
    /// is given. With `signing_key = None` the row is stored unsigned
    /// (signature NULL).
    pub fn append_signed(
        &self,
        operator: &str,
        action: &str,
        path: &str,
        sha256: &str,
        signing_key: Option<&SigningKey>,
    ) -> Result<CustodyEvent, ArcanaError> {
        let ts = unix_now() as i64;
        let prev = self.tip_hash()?;
        let material = format!("{ts}|{operator}|{action}|{path}|{sha256}|{prev}");
        let entry_hash = sha256_bytes(material.as_bytes());
        let signature: Option<String> = signing_key.map(|k| sign_entry_hash(k, &entry_hash));

        self.conn
            .execute(
                "INSERT INTO custody_events
                 (ts, operator, action, path, sha256, prev_hash, entry_hash, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![ts, operator, action, path, sha256, prev, entry_hash, signature],
            )
            .map_err(|e| ArcanaError::Ledger(e.to_string()))?;

        let id = self.conn.last_insert_rowid();
        Ok(CustodyEvent {
            id,
            ts,
            operator: operator.to_string(),
            action: action.to_string(),
            path: path.to_string(),
            sha256: sha256.to_string(),
            prev_hash: prev,
            entry_hash,
            signature,
        })
    }

    pub fn verify_chain(&self) -> Result<(usize, bool), ArcanaError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, ts, operator, action, path, sha256, prev_hash, entry_hash, signature
                 FROM custody_events ORDER BY id ASC",
            )
            .map_err(|e| ArcanaError::Ledger(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(CustodyEvent {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    operator: row.get(2)?,
                    action: row.get(3)?,
                    path: row.get(4)?,
                    sha256: row.get(5)?,
                    prev_hash: row.get(6)?,
                    entry_hash: row.get(7)?,
                    signature: row.get(8)?,
                })
            })
            .map_err(|e| ArcanaError::Ledger(e.to_string()))?;

        let mut prev = GENESIS.to_string();
        let mut count = 0usize;
        for row in rows {
            let ev = row.map_err(|e| ArcanaError::Ledger(e.to_string()))?;
            if ev.prev_hash != prev {
                return Ok((count, false));
            }
            let material = format!(
                "{}|{}|{}|{}|{}|{}",
                ev.ts, ev.operator, ev.action, ev.path, ev.sha256, ev.prev_hash
            );
            if sha256_bytes(material.as_bytes()) != ev.entry_hash {
                return Ok((count, false));
            }
            prev = ev.entry_hash;
            count += 1;
        }
        Ok((count, true))
    }

    /// Verifies the hash chain exactly like [`Ledger::verify_chain`],
    /// and then requires every row to carry a signature that verifies
    /// against its entry_hash under the operator's verifying key.
    /// - A row with no signature fails as `SignatureMissing`.
    /// - A row whose signature was made for a different entry_hash, or
    ///   by a different key, fails as `SignatureInvalid`.
    /// - A rewritten chain (hashes recomputed by an attacker without the
    ///   signing key) passes the hash checks but fails here at the first
    ///   rewritten row.
    /// Legacy unsigned ledgers fail this check by design — use the
    /// hash-only `verify_chain` for those, and re-acquire signed rows
    /// going forward. A corrupt row (unreadable column) is a `Ledger`
    /// error, never a panic.
    pub fn verify_chain_signed(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Result<usize, ArcanaError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, ts, operator, action, path, sha256, prev_hash, entry_hash, signature
                 FROM custody_events ORDER BY id ASC",
            )
            .map_err(|e| ArcanaError::Ledger(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(CustodyEvent {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    operator: row.get(2)?,
                    action: row.get(3)?,
                    path: row.get(4)?,
                    sha256: row.get(5)?,
                    prev_hash: row.get(6)?,
                    entry_hash: row.get(7)?,
                    signature: row.get(8)?,
                })
            })
            .map_err(|e| ArcanaError::Ledger(e.to_string()))?;

        let mut prev = GENESIS.to_string();
        let mut count = 0usize;
        for row in rows {
            let ev = row.map_err(|e| ArcanaError::Ledger(e.to_string()))?;
            if ev.prev_hash != prev {
                return Err(ArcanaError::LedgerTampered {
                    row_id: ev.id,
                    expected: prev,
                    actual: ev.prev_hash.clone(),
                });
            }
            let material = format!(
                "{}|{}|{}|{}|{}|{}",
                ev.ts, ev.operator, ev.action, ev.path, ev.sha256, ev.prev_hash
            );
            if sha256_bytes(material.as_bytes()) != ev.entry_hash {
                return Err(ArcanaError::LedgerTampered {
                    row_id: ev.id,
                    expected: sha256_bytes(material.as_bytes()),
                    actual: ev.entry_hash.clone(),
                });
            }
            let Some(signature) = ev.signature else {
                return Err(ArcanaError::SignatureMissing { row_id: ev.id });
            };
            if !verify_entry_signature(verifying_key, &ev.entry_hash, &signature) {
                return Err(ArcanaError::SignatureInvalid { row_id: ev.id });
            }
            prev = ev.entry_hash;
            count += 1;
        }
        Ok(count)
    }

    pub fn events(&self) -> Result<Vec<CustodyEvent>, ArcanaError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, ts, operator, action, path, sha256, prev_hash, entry_hash, signature
                 FROM custody_events ORDER BY id ASC",
            )
            .map_err(|e| ArcanaError::Ledger(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(CustodyEvent {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    operator: row.get(2)?,
                    action: row.get(3)?,
                    path: row.get(4)?,
                    sha256: row.get(5)?,
                    prev_hash: row.get(6)?,
                    entry_hash: row.get(7)?,
                    signature: row.get(8)?,
                })
            })
            .map_err(|e| ArcanaError::Ledger(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| ArcanaError::Ledger(e.to_string()))?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn test_keypair() -> (SigningKey, String) {
        let (seed, verifying_bytes) = generate_operator_keypair();
        let signing_key = SigningKey::from_bytes(&seed);
        (signing_key, hex::encode(verifying_bytes))
    }

    // A fresh on-disk ledger per call: tests run in parallel in one
    // process, so a single shared file would mix their rows together.
    static LEDGER_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn memory_ledger() -> (Ledger, std::path::PathBuf) {
        let n = LEDGER_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = env::temp_dir().join(format!(
            "arcana-ledger-{}-{}.sqlite",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_file(&dir);
        (Ledger::open(&dir).unwrap(), dir)
    }

    #[test]
    fn hash_chain_verifies() {
        let (ledger, _path) = memory_ledger();
        ledger.append("op", "ingest", "a.txt", "aa").unwrap();
        ledger.append("op", "seal", "a.txt", "aa").unwrap();
        let (n, ok) = ledger.verify_chain().unwrap();
        assert_eq!(n, 2);
        assert!(ok);
    }

    #[test]
    fn keypair_generation_is_random_and_consistent() {
        let (seed_a, verifying_a) = generate_operator_keypair();
        let (seed_b, verifying_b) = generate_operator_keypair();
        assert_ne!(seed_a, seed_b);
        assert_ne!(verifying_a, verifying_b);
        let signing_key = SigningKey::from_bytes(&seed_a);
        assert_eq!(signing_key.verifying_key().to_bytes(), verifying_a);
        let restored = signing_key_from_seed_hex(&hex::encode(seed_a)).unwrap();
        assert_eq!(restored.verifying_key().to_bytes(), verifying_a);
    }

    #[test]
    fn seed_and_verifying_key_hex_validation() {
        assert!(signing_key_from_seed_hex("not-hex").is_err());
        assert!(signing_key_from_seed_hex(&"aa".repeat(16)).is_err()); // 16 bytes, not 32
        assert!(signing_key_from_seed_hex(&"aa".repeat(32)).is_ok());
        assert!(verifying_key_from_hex("zz").is_err());
        assert!(verifying_key_from_hex(&"00".repeat(16)).is_err()); // 16 bytes, not 32
        let (_, verifying_hex) = test_keypair();
        assert!(verifying_key_from_hex(&verifying_hex).is_ok());
    }

    #[test]
    fn sign_and_verify_entry_hash() {
        let (signing_key, verifying_hex) = test_keypair();
        let verifying_key = verifying_key_from_hex(&verifying_hex).unwrap();
        let entry_hash = "ab".repeat(32);
        let signature = sign_entry_hash(&signing_key, &entry_hash);
        assert_eq!(signature.len(), 128, "64-byte signature as hex");
        assert!(verify_entry_signature(&verifying_key, &entry_hash, &signature));

        let (_, other_verifying_hex) = test_keypair();
        let other_key = verifying_key_from_hex(&other_verifying_hex).unwrap();
        assert!(!verify_entry_signature(&other_key, &entry_hash, &signature));
        assert!(!verify_entry_signature(
            &verifying_key,
            &"cd".repeat(32),
            &signature
        ));
        let mut tampered = signature.clone();
        tampered.replace_range(0..1, if &signature[0..1] == "a" { "b" } else { "a" });
        assert!(!verify_entry_signature(&verifying_key, &entry_hash, &tampered));
        assert!(!verify_entry_signature(&verifying_key, &entry_hash, "not-hex"));
        assert!(!verify_entry_signature(&verifying_key, &entry_hash, "aa"));
    }

    #[test]
    fn signed_rows_verify_with_key() {
        let (signing_key, verifying_hex) = test_keypair();
        let verifying_key = verifying_key_from_hex(&verifying_hex).unwrap();
        let (ledger, _path) = memory_ledger();
        ledger
            .append_signed("op", "SEAL_ARCN", "a.arcn", "aa", Some(&signing_key))
            .unwrap();
        ledger
            .append_signed("op", "SEAL_ARCN", "b.arcn", "bb", Some(&signing_key))
            .unwrap();
        assert_eq!(ledger.verify_chain_signed(&verifying_key).unwrap(), 2);
        // Hash-only verification still passes too.
        assert_eq!(ledger.verify_chain().unwrap(), (2, true));
        // The chain tip is the last row's entry_hash.
        let tip = ledger.chain_tip().unwrap();
        let last_hash = ledger.events().unwrap().pop().unwrap().entry_hash;
        assert_eq!(tip, last_hash);
    }

    #[test]
    fn unsigned_row_fails_signed_verification_but_passes_hash_only() {
        let (_, verifying_hex) = test_keypair();
        let verifying_key = verifying_key_from_hex(&verifying_hex).unwrap();
        let (ledger, _path) = memory_ledger();
        ledger.append("op", "SEAL_ARCN", "a.arcn", "aa").unwrap();
        assert_eq!(ledger.verify_chain().unwrap(), (1, true));
        let err = ledger.verify_chain_signed(&verifying_key).unwrap_err();
        assert!(
            matches!(err, ArcanaError::SignatureMissing { row_id: 1 }),
            "unsigned row must fail as SignatureMissing at row 1, got {err:?}"
        );
    }

    #[test]
    fn chain_rewrite_without_signing_key_is_caught() {
        // The attack signing is meant to stop: an attacker with DB write
        // access rewrites a row and recomputes the hash chain so the
        // hash-only check passes.
        let (signing_key, verifying_hex) = test_keypair();
        let verifying_key = verifying_key_from_hex(&verifying_hex).unwrap();
        let (ledger, path) = memory_ledger();
        ledger
            .append_signed("op", "SEAL_ARCN", "a.arcn", "aa", Some(&signing_key))
            .unwrap();
        ledger
            .append_signed("op", "SEAL_ARCN", "b.arcn", "bb", Some(&signing_key))
            .unwrap();
        assert_eq!(ledger.verify_chain_signed(&verifying_key).unwrap(), 2);

        // Rewrite row 1's artifact hash and recompute its entry_hash and
        // row 2's prev_hash + entry_hash, exactly as the hash chain
        // requires. (Done through a second connection to the same file.)
        let conn = Connection::open(&path).unwrap();
        let (ts, operator, action, path_col, prev_hash): (i64, String, String, String, String) =
            conn.query_row(
                "SELECT ts, operator, action, path, prev_hash FROM custody_events WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        let forged_sha = sha256_bytes(b"forged-evidence");
        let forged_entry = sha256_bytes(
            format!("{ts}|{operator}|{action}|{path_col}|{forged_sha}|{prev_hash}").as_bytes(),
        );
        conn.execute(
            "UPDATE custody_events SET sha256 = ?1, entry_hash = ?2 WHERE id = 1",
            [&forged_sha, &forged_entry],
        )
        .unwrap();
        let (ts2, operator2, action2, path2, sha2): (i64, String, String, String, String) =
            conn.query_row(
                "SELECT ts, operator, action, path, sha256 FROM custody_events WHERE id = 2",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        let forged_entry2 = sha256_bytes(
            format!("{ts2}|{operator2}|{action2}|{path2}|{sha2}|{forged_entry}").as_bytes(),
        );
        conn.execute(
            "UPDATE custody_events SET prev_hash = ?1, entry_hash = ?2 WHERE id = 2",
            [&forged_entry, &forged_entry2],
        )
        .unwrap();
        drop(conn);

        // Hash-only verification is fooled by the recomputed chain — that
        // is the known weakness. Signed verification must catch it at
        // row 1, whose signature was made for the original entry_hash.
        assert_eq!(ledger.verify_chain().unwrap(), (2, true));
        let err = ledger.verify_chain_signed(&verifying_key).unwrap_err();
        assert!(
            matches!(err, ArcanaError::SignatureInvalid { row_id: 1 }),
            "rewritten chain must fail as SignatureInvalid at row 1, got {err:?}"
        );
    }

    #[test]
    fn tampered_signed_row_is_caught_by_both_checks() {
        let (signing_key, verifying_hex) = test_keypair();
        let verifying_key = verifying_key_from_hex(&verifying_hex).unwrap();
        let (ledger, path) = memory_ledger();
        ledger
            .append_signed("op", "SEAL_ARCN", "a.arcn", "aa", Some(&signing_key))
            .unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute("UPDATE custody_events SET sha256 = '00' WHERE id = 1", [])
            .unwrap();
        drop(conn);
        assert_eq!(ledger.verify_chain().unwrap().1, false);
        assert!(ledger.verify_chain_signed(&verifying_key).is_err());
    }

    #[test]
    fn old_schema_without_signature_column_migrates() {
        let (signing_key, verifying_hex) = test_keypair();
        let verifying_key = verifying_key_from_hex(&verifying_hex).unwrap();
        let dir = env::temp_dir().join(format!("arcana-migrate-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        // A ledger as created by the pre-signing code: no signature column.
        {
            let conn = Connection::open(&dir).unwrap();
            conn.execute(
                "CREATE TABLE custody_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL, operator TEXT NOT NULL, action TEXT NOT NULL,
                    path TEXT NOT NULL, sha256 TEXT NOT NULL,
                    prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE
                )",
                [],
            )
            .unwrap();
        }
        let ledger = Ledger::open(&dir).unwrap();
        ledger
            .append_signed("op", "SEAL_ARCN", "a.arcn", "aa", Some(&signing_key))
            .unwrap();
        // The open migrated the table, and the signed row verifies.
        assert_eq!(ledger.verify_chain_signed(&verifying_key).unwrap(), 1);
        let sig: Option<String> = {
            let conn = Connection::open(&dir).unwrap();
            conn.query_row(
                "SELECT signature FROM custody_events WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert!(sig.map(|s| s.len() == 128).unwrap_or(false));
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn empty_ledger_tip_errors_cleanly() {
        let (ledger, _path) = memory_ledger();
        assert!(ledger.chain_tip().is_err());
    }

    #[test]
    fn transaction_rolls_back_on_error() {
        let (ledger, _path) = memory_ledger();
        ledger.append("op", "case-open", "src", "aa").unwrap();
        ledger.begin().unwrap();
        ledger.append("op", "SEAL_ARCN", "a.arcn", "aa").unwrap();
        ledger.rollback().unwrap();
        // The rolled-back row is gone; the pre-transaction row remains.
        assert_eq!(ledger.verify_chain().unwrap(), (1, true));
    }
}
