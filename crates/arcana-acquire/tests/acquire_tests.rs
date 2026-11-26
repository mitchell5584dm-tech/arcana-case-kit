//! Integration tests for the arcana-acquire CLI (Phase 1 §1B port).
//!
//! These drive the built binary, not library functions: nested folders,
//! duplicate basenames, symlink/FIFO skips logged in the ledger, keygen +
//! signed acquire/verify, legacy v1, tamper detection, and rollback on a
//! hard error mid-run. All data is synthetic; passphrases and signing
//! keys are throwaway values passed to the child process only — no test
//! here touches the test process's own environment.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_arcana-acquire");
const PW: &str = "test-passphrase-2026-11-25";

static SEQ: AtomicU64 = AtomicU64::new(0);

fn scratch(name: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "arcana-acquire-tests-{}-{}-{}",
        name,
        std::process::id(),
        n
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn sha256_hex(data: &[u8]) -> String {
    arcana_core::sha256_bytes(data)
}

fn run(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

fn run_ok(args: &[&str], envs: &[(&str, &str)]) -> String {
    let out = run(args, envs);
    assert!(
        out.status.success(),
        "command {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn acquire(source: &Path, case: &Path, extra: &[&str]) -> String {
    let mut args: Vec<&str> = vec![
        "acquire",
        "--path",
        source.to_str().unwrap(),
        "--out",
        case.to_str().unwrap(),
        "--operator",
        "tester",
    ];
    args.extend_from_slice(extra);
    run_ok(&args, &[("ARCANA_VAULT_PASSWORD", PW)])
}

fn vault_files(case: &Path) -> Vec<PathBuf> {
    let vault = case.join("vault");
    if !vault.is_dir() {
        return Vec::new();
    }
    fs::read_dir(&vault)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect()
}

fn ledger_rows(case: &Path) -> Vec<(i64, String, String)> {
    // (id, action, path) for every row, in order.
    let conn = rusqlite::Connection::open(case.join("custody.sqlite")).unwrap();
    let mut stmt = conn
        .prepare("SELECT id, action, path FROM custody_events ORDER BY id ASC")
        .unwrap();
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap();
    rows.map(|r| r.unwrap()).collect()
}

fn keygen() -> (String, String) {
    // Returns (verifying_key_hex, seed_hex).
    let out = run_ok(&["keygen"], &[]);
    let mut verifying = String::new();
    let mut seed = String::new();
    for line in out.lines() {
        if let Some(v) = line.strip_prefix("Verifying key (public — record this with the case): ") {
            verifying = v.trim().to_string();
        }
        if let Some(s) = line.strip_prefix("Signing seed (SECRET — store offline, never share): ") {
            seed = s.trim().to_string();
        }
    }
    assert_eq!(verifying.len(), 64, "verifying key must be 64 hex chars");
    assert_eq!(seed.len(), 64, "seed must be 64 hex chars");
    assert_ne!(verifying, seed);
    (verifying, seed)
}

#[test]
fn nested_folders_are_sealed() {
    let base = scratch("nested");
    let source = base.join("source");
    let case = base.join("case");
    fs::create_dir_all(source.join("sub/deep")).unwrap();
    fs::write(source.join("top.txt"), b"top").unwrap();
    fs::write(source.join("sub/mid.txt"), b"mid").unwrap();
    fs::write(source.join("sub/deep/bottom.txt"), b"bottom").unwrap();

    let stdout = acquire(&source, &case, &[]);
    assert!(stdout.contains("acquired 3 file(s)"), "{stdout}");
    assert_eq!(vault_files(&case).len(), 3);
    // Manifest keeps the relative paths, so nothing collides.
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(case.join("manifest.json")).unwrap()).unwrap();
    let rels: Vec<&str> = manifest["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["relative_path"].as_str().unwrap())
        .collect();
    assert!(rels.contains(&"top.txt"));
    assert!(rels.contains(&"sub/mid.txt"));
    assert!(rels.contains(&"sub/deep/bottom.txt"));
    let out = run(
        &["verify", "--case", case.to_str().unwrap()],
        &[("ARCANA_VAULT_PASSWORD", PW)],
    );
    assert!(out.status.success(), "verify failed: {}", String::from_utf8_lossy(&out.stderr));
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn duplicate_basenames_in_different_folders_do_not_collide() {
    let base = scratch("dupnames");
    let source = base.join("source");
    let case = base.join("case");
    fs::create_dir_all(source.join("a")).unwrap();
    fs::create_dir_all(source.join("b")).unwrap();
    fs::write(source.join("a/same.txt"), b"from folder a").unwrap();
    fs::write(source.join("b/same.txt"), b"from folder b").unwrap();

    acquire(&source, &case, &[]);
    // Vault files are named by content digest, so the two same-named
    // files can never overwrite each other.
    assert_eq!(vault_files(&case).len(), 2);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(case.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["evidence"].as_array().unwrap().len(), 2);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn symlinks_and_special_files_are_skipped_and_logged() {
    let base = scratch("skips");
    let source = base.join("source");
    let case = base.join("case");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("real.txt"), b"real").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(source.join("real.txt"), source.join("link-inside.txt")).unwrap();
        symlink("/etc/hostname", source.join("link-outside.txt")).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(source.join("pipe"))
            .status()
            .expect("mkfifo available");
        assert!(status.success());
    }

    let stdout = acquire(&source, &case, &[]);
    assert!(stdout.contains("acquired 1 file(s)"), "{stdout}");
    assert!(stdout.contains("[SKIP]"), "{stdout}");
    assert_eq!(vault_files(&case).len(), 1);
    // The skips are in the ledger too: 1 case-open + 1 sealed +
    // 1 manifest-write + 3 SKIP rows.
    let rows = ledger_rows(&case);
    let skips: Vec<_> = rows.iter().filter(|(_, a, _)| a.starts_with("SKIP:")).collect();
    assert_eq!(skips.len(), 3, "rows: {rows:?}");
    assert!(skips.iter().all(|(_, a, _)| a.contains("symlink") || a.contains("special file")));
    let out = run(&["verify", "--case", case.to_str().unwrap()], &[]);
    assert!(out.status.success());
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn empty_source_seals_nothing_and_still_verifies() {
    let base = scratch("empty");
    let source = base.join("source");
    let case = base.join("case");
    fs::create_dir_all(&source).unwrap();
    let stdout = acquire(&source, &case, &[]);
    assert!(stdout.contains("acquired 0 file(s)"), "{stdout}");
    let out = run(&["verify", "--case", case.to_str().unwrap()], &[]);
    assert!(out.status.success());
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn keygen_produces_fresh_keypairs() {
    let (v1, s1) = keygen();
    let (v2, s2) = keygen();
    assert_ne!(v1, v2);
    assert_ne!(s1, s2);
}

#[test]
fn signed_acquire_and_signed_verify() {
    let (verifying, seed) = keygen();
    let base = scratch("signed");
    let source = base.join("source");
    let case = base.join("case");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("one.txt"), b"synthetic evidence one").unwrap();
    fs::write(source.join("two.txt"), b"synthetic evidence two").unwrap();

    let envs = [
        ("ARCANA_VAULT_PASSWORD", PW),
        ("ARCANA_SIGNING_KEY", seed.as_str()),
    ];
    let stdout = run_ok(
        &[
            "acquire",
            "--path",
            source.to_str().unwrap(),
            "--out",
            case.to_str().unwrap(),
            "--operator",
            "tester",
        ],
        &envs,
    );
    assert!(stdout.contains("[SIGNED]"), "{stdout}");
    assert!(stdout.contains("[ANCHOR] Chain tip"), "{stdout}");
    assert!(stdout.contains(&verifying), "{stdout}");

    // Signed verify with the right key passes.
    let out = run(
        &[
            "verify",
            "--case",
            case.to_str().unwrap(),
            "--verifying-key",
            &verifying,
        ],
        &[],
    );
    assert!(out.status.success(), "signed verify failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("[ANCHOR] Chain tip"));

    // Signed verify with a different key fails.
    let (other_verifying, _) = keygen();
    let out = run(
        &[
            "verify",
            "--case",
            case.to_str().unwrap(),
            "--verifying-key",
            &other_verifying,
        ],
        &[],
    );
    assert!(!out.status.success(), "wrong key must fail signed verify");

    // Hash-only verify still passes (unsigned-compatible path).
    let out = run(&["verify", "--case", case.to_str().unwrap()], &[]);
    assert!(out.status.success());

    // Every ledger row carries a 128-hex-char signature.
    let conn = rusqlite::Connection::open(case.join("custody.sqlite")).unwrap();
    let signed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM custody_events WHERE signature IS NOT NULL AND length(signature) = 128",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(signed >= 4, "expected all rows signed, got {signed}");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn default_seal_is_v2_and_legacy_flag_seals_v1() {
    let base = scratch("versions");
    let source = base.join("source");
    let case_v2 = base.join("case-v2");
    let case_v1 = base.join("case-v1");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("note.txt"), b"version check").unwrap();

    acquire(&source, &case_v2, &[]);
    let blob = fs::read(vault_files(&case_v2).pop().unwrap()).unwrap();
    assert_eq!(blob[4], 0x02, "default seal must be v0x02");

    acquire(&source, &case_v1, &["--legacy-v1"]);
    let blob = fs::read(vault_files(&case_v1).pop().unwrap()).unwrap();
    assert_eq!(blob[4], 0x01, "legacy flag must seal v0x01");

    // Both still verify (unseal opens either version).
    for case in [&case_v2, &case_v1] {
        let out = run(
            &["verify", "--case", case.to_str().unwrap()],
            &[("ARCANA_VAULT_PASSWORD", PW)],
        );
        assert!(out.status.success(), "verify failed for {}: {}", case.display(), String::from_utf8_lossy(&out.stderr));
    }
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn tampered_vault_blob_fails_verify() {
    let base = scratch("tamper");
    let source = base.join("source");
    let case = base.join("case");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("note.txt"), b"do not alter me").unwrap();
    acquire(&source, &case, &[]);

    let vault_file = vault_files(&case).pop().unwrap();
    let mut blob = fs::read(&vault_file).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    fs::write(&vault_file, &blob).unwrap();

    let out = run(
        &["verify", "--case", case.to_str().unwrap()],
        &[("ARCANA_VAULT_PASSWORD", PW)],
    );
    assert!(!out.status.success(), "tampered blob must fail verify");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn hard_error_mid_run_rolls_back() {
    // A pre-existing directory where a .arcv file must go makes the
    // atomic rename fail mid-run: the ledger must roll back and no
    // sealed files or manifest may remain.
    let base = scratch("rollback");
    let source = base.join("source");
    let case = base.join("case");
    fs::create_dir_all(source.join("a")).unwrap();
    fs::write(source.join("a/one.txt"), b"first file").unwrap();
    fs::write(source.join("a/two.txt"), b"second file").unwrap();

    let digest_two = sha256_hex(b"second file");
    let vault_dir = case.join("vault");
    fs::create_dir_all(&vault_dir).unwrap();
    fs::create_dir_all(vault_dir.join(format!("{digest_two}.arcv"))).unwrap();

    let out = run(
        &[
            "acquire",
            "--path",
            source.to_str().unwrap(),
            "--out",
            case.to_str().unwrap(),
            "--operator",
            "tester",
        ],
        &[("ARCANA_VAULT_PASSWORD", PW)],
    );
    assert!(!out.status.success(), "acquire must fail on the blocked write");
    // No sealed files left behind (only the pre-created directory).
    assert!(vault_files(&case).is_empty());
    // No manifest left behind.
    assert!(!case.join("manifest.json").exists());
    // The ledger rolled back to zero rows.
    assert_eq!(ledger_rows(&case).len(), 0);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn malformed_signing_key_fails_cleanly() {
    let base = scratch("badkey");
    let source = base.join("source");
    let case = base.join("case");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("note.txt"), b"hi").unwrap();
    let out = run(
        &[
            "acquire",
            "--path",
            source.to_str().unwrap(),
            "--out",
            case.to_str().unwrap(),
            "--operator",
            "tester",
        ],
        &[
            ("ARCANA_VAULT_PASSWORD", PW),
            ("ARCANA_SIGNING_KEY", "not-hex"),
        ],
    );
    assert!(!out.status.success(), "malformed signing key must fail");
    assert!(vault_files(&case).is_empty());
    let _ = fs::remove_dir_all(&base);
}
