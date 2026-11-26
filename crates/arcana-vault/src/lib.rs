//! AES-256-GCM vault with stretched passphrase derivation.
//!
//! On-disk blob layout:
//! `ARCN | version(1) | salt(16) | nonce(12) | ciphertext+tag`
//!
//! Two key-derivation versions exist, told apart by the version byte:
//!
//! * **v0x02 (current default)** — Argon2id, 64 MiB memory, 3 iterations,
//!   4 lanes, 32-byte key, Argon2 version 0x13. Identical parameters to
//!   the master bundle's v0x02 (`derive_vault_key` in the bundle's
//!   `src/lib.rs`) and to Python Recon's `derive_key_v2`, so v0x02 blobs
//!   are mutually readable across all three.
//! * **v0x01 (legacy)** — 100,000 rounds of SHA-256 over
//!   `passphrase || salt || "arcana-vault-kdf-v1"`, then
//!   `SHA-256(acc || salt || round_le32)` per round. This is the repo's
//!   own v1 KDF, kept readable for blobs sealed before the Argon2id
//!   migration. It is NOT the same KDF as the master bundle's v0x01
//!   (same version byte, different derivation), so bundle v0x01 blobs
//!   do not open here and repo v1 blobs do not open there. Nothing in
//!   this repo seals v0x01 any more.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use arcana_core::{ArcanaError, VAULT_MAGIC, VAULT_VERSION_V1, VAULT_VERSION_V2};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN;
const STRETCH_ROUNDS: u32 = 100_000;

/// Argon2id parameters for v0x02 — must match the master bundle and
/// Python Recon exactly: 64 MiB memory, 3 iterations, 4 lanes, 32-byte
/// key, Argon2 version 0x13.
pub const ARGON2_MEMORY_KIB: u32 = 65536;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 4;

pub struct VaultKey {
    bytes: [u8; 32],
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl VaultKey {
    /// Legacy v0x01 derivation: 100,000 rounds of SHA-256 (repo KDF,
    /// domain `arcana-vault-kdf-v1`). Kept so old blobs still open.
    pub fn derive(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Self, ArcanaError> {
        if passphrase.len() < 12 {
            return Err(ArcanaError::Vault(
                "passphrase must be at least 12 characters".into(),
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        hasher.update(salt);
        hasher.update(b"arcana-vault-kdf-v1");
        let mut acc: [u8; 32] = hasher.finalize().into();
        for round in 0..STRETCH_ROUNDS {
            let mut h = Sha256::new();
            h.update(acc);
            h.update(salt);
            h.update(round.to_le_bytes());
            acc = h.finalize().into();
        }
        Ok(Self { bytes: acc })
    }

    /// Current v0x02 derivation: Argon2id (64 MiB / 3 iter / 4 lanes,
    /// V0x13). The derived key is wiped from RAM when the `VaultKey`
    /// drops, same as the legacy path.
    pub fn derive_v2(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Self, ArcanaError> {
        if passphrase.len() < 12 {
            return Err(ArcanaError::Vault(
                "passphrase must be at least 12 characters".into(),
            ));
        }
        let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(32))
            .map_err(|e| ArcanaError::Vault(e.to_string()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| ArcanaError::Vault(e.to_string()))?;
        Ok(Self { bytes: key })
    }
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn seal_with_key(
    plaintext: &[u8],
    passphrase: &str,
    version: u8,
) -> Result<Vec<u8>, ArcanaError> {
    let salt = generate_salt();
    let key = match version {
        VAULT_VERSION_V1 => VaultKey::derive(passphrase, &salt)?,
        VAULT_VERSION_V2 => VaultKey::derive_v2(passphrase, &salt)?,
        other => {
            return Err(ArcanaError::Vault(format!(
                "unsupported version {other}"
            )))
        }
    };

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| ArcanaError::Vault("encryption failed".into()))?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(VAULT_MAGIC);
    out.push(version);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Seals with the current default: ARCN v0x02 (Argon2id).
pub fn seal(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, ArcanaError> {
    seal_with_key(plaintext, passphrase, VAULT_VERSION_V2)
}

/// Seals with the legacy v0x01 KDF. Only for reproducing old blobs in
/// tests; nothing in the program seals v0x01 any more.
pub fn seal_v1(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, ArcanaError> {
    seal_with_key(plaintext, passphrase, VAULT_VERSION_V1)
}

/// Seals with an explicit version byte (1 or 2).
pub fn seal_version(
    plaintext: &[u8],
    passphrase: &str,
    version: u8,
) -> Result<Vec<u8>, ArcanaError> {
    seal_with_key(plaintext, passphrase, version)
}

/// Unseals an ARCN blob of either version: v0x01 opens with the legacy
/// SHA-256 KDF, v0x02 with Argon2id. Any other version byte, bad magic,
/// truncation, wrong passphrase, or tampered byte is an error.
pub fn unseal(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, ArcanaError> {
    if blob.len() < HEADER_LEN + 16 {
        return Err(ArcanaError::Vault("blob too short".into()));
    }
    if &blob[..4] != VAULT_MAGIC {
        return Err(ArcanaError::Vault("bad magic".into()));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&blob[5..21]);
    let nonce_bytes = &blob[21..33];
    let ciphertext = &blob[33..];

    let key = match blob[4] {
        VAULT_VERSION_V1 => VaultKey::derive(passphrase, &salt)?,
        VAULT_VERSION_V2 => VaultKey::derive_v2(passphrase, &salt)?,
        other => {
            return Err(ArcanaError::Vault(format!(
                "unsupported version {other}"
            )))
        }
    };
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.bytes));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| ArcanaError::Auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let secret = b"chain-of-custody evidence";
        let blob = seal(secret, "correct horse battery staple extra").unwrap();
        assert_eq!(blob[4], VAULT_VERSION_V2, "new seals must be v0x02");
        let plain = unseal(&blob, "correct horse battery staple extra").unwrap();
        assert_eq!(plain, secret);
    }

    #[test]
    fn v1_legacy_roundtrip() {
        let secret = b"legacy blob, sealed the old way";
        let blob = seal_v1(secret, "correct horse battery staple extra").unwrap();
        assert_eq!(blob[4], VAULT_VERSION_V1, "legacy seals must be v0x01");
        let plain = unseal(&blob, "correct horse battery staple extra").unwrap();
        assert_eq!(plain, secret);
    }

    #[test]
    fn wrong_password_fails() {
        let blob = seal(b"x", "correct horse battery staple extra").unwrap();
        assert!(unseal(&blob, "wrong password xxx").is_err());
    }

    #[test]
    fn short_passphrase_rejected() {
        assert!(seal(b"x", "short").is_err());
        assert!(seal_v1(b"x", "short").is_err());
        assert!(VaultKey::derive_v2("short", &[0u8; SALT_LEN]).is_err());
    }

    #[test]
    fn unsupported_version_is_rejected() {
        assert!(seal_version(b"x", "correct horse battery staple extra", 0x03).is_err());
        let mut blob = seal(b"x", "correct horse battery staple extra").unwrap();
        blob[4] = 0x03;
        assert!(unseal(&blob, "correct horse battery staple extra").is_err());
    }

    #[test]
    fn tampered_v2_blob_is_rejected() {
        let mut blob = seal(b"do not alter me", "correct horse battery staple extra").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01; // flip one bit in the GCM tag
        assert!(unseal(&blob, "correct horse battery staple extra").is_err());
    }

    #[test]
    fn truncated_blob_is_rejected() {
        let blob = seal(b"do not alter me", "correct horse battery staple extra").unwrap();
        assert!(unseal(&blob[..20], "correct horse battery staple extra").is_err());
        assert!(unseal(&[], "correct horse battery staple extra").is_err());
    }

    #[test]
    fn two_seals_of_same_plaintext_differ() {
        let a = seal(b"same words", "correct horse battery staple extra").unwrap();
        let b = seal(b"same words", "correct horse battery staple extra").unwrap();
        assert_ne!(a, b);
        assert_eq!(unseal(&a, "correct horse battery staple extra").unwrap(), b"same words");
        assert_eq!(unseal(&b, "correct horse battery staple extra").unwrap(), b"same words");
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Same vectors as recon/tests/test_vault.py, so the Python recon engine and
    // this crate are checked against each other on every CI run.
    #[test]
    fn kdf_matches_python_vector() {
        let salt: [u8; SALT_LEN] = core::array::from_fn(|i| i as u8);
        let key = VaultKey::derive("correct horse battery staple extra", &salt).unwrap();
        assert_eq!(
            key.bytes.to_vec(),
            from_hex("af8f2e7bf7f40bde9c81e87d042524a09521cb74dafddad97d5f6e8ba628301b")
        );
    }

    // Fixed-salt Argon2id vector, shared with the master bundle (file 15)
    // and with recon/tests/test_vault.py: passphrase
    // "synthetic-test-passphrase-123", salt bytes 0..15, Argon2id 64 MiB /
    // 3 iter / 4 lanes / V0x13. Proves the three implementations agree.
    #[test]
    fn argon2id_kdf_matches_bundle_vector() {
        let salt: [u8; SALT_LEN] = core::array::from_fn(|i| i as u8);
        let key = VaultKey::derive_v2("synthetic-test-passphrase-123", &salt).unwrap();
        assert_eq!(
            key.bytes.to_vec(),
            from_hex("f9e2c6bd35f0058799c8b731f0c42e2cc3049ac67ea2a5ede896db188e73b50d")
        );
    }

    #[test]
    fn v1_and_v2_derive_different_keys() {
        let salt: [u8; SALT_LEN] = core::array::from_fn(|i| i as u8);
        let k1 = VaultKey::derive("correct horse battery staple extra", &salt).unwrap();
        let k2 = VaultKey::derive_v2("correct horse battery staple extra", &salt).unwrap();
        assert_ne!(k1.bytes, k2.bytes);
    }

    #[test]
    fn unseals_blob_sealed_by_python() {
        let blob = from_hex(
            "4152434e01e78798961be15be292a5015c03be1f69ef8f27bb0e8eb1a13b5d6b7c613fbd69c17f0442ba547e8346e23fd099b9fde0aa49cb356bd47d5dca502d72841313a52adf98e8ad51c2",
        );
        let plain = unseal(&blob, "correct horse battery staple extra").unwrap();
        assert_eq!(plain, b"arcana-recon interop vector");
    }

    // v0x02 blob sealed by Python Recon (recon/tests/test_vault.py):
    // same passphrase, plaintext "arcana-recon interop vector v2".
    // Proves the Argon2id path is byte-compatible in both directions.
    #[test]
    fn unseals_v2_blob_sealed_by_python() {
        let blob = from_hex(
            "4152434e0248f952a9e5564af4712a1aa944a43a7598300cb926e106b78a0163e3005bbbe1507275a78ddc9dc5eb2d8c751373bd4739e8c33a91599a5f2b3cbc21eae4793ea8ac15941e4aeb085948",
        );
        let plain = unseal(&blob, "correct horse battery staple extra").unwrap();
        assert_eq!(plain, b"arcana-recon interop vector v2");
    }
}
