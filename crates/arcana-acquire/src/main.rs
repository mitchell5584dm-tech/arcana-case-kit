// arcana-acquire — offline-first acquisition & sealing CLI.
// Commands: keygen, acquire, verify, export-manifest.
//
// Sealing defaults to ARCN v0x02 (Argon2id, 64 MiB / 3 iter / 4 lanes);
// v0x01 (the repo's legacy 100,000-round SHA-256 KDF) is opt-in only via
// --legacy-v1, for reproducing old seals. `unseal` (in `verify`) opens
// both versions. Custody rows are signed with Ed25519 when
// ARCANA_SIGNING_KEY is set (see `keygen`); see SECURITY.md for the
// anchoring procedure (record the [ANCHOR] chain tip in a second location).

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use walkdir::WalkDir;
use zeroize::Zeroize;

use arcana_core::{
    classify_magic, confined_path, reject_special_file, sha256_bytes, unix_now, ArcanaError,
    CaseManifest, EvidenceRecord, DEFAULT_MAX_FILE_BYTES, TOOL_NAME, TOOL_VERSION,
};
use arcana_custody::{
    generate_operator_keypair, signing_key_from_seed_hex, verifying_key_from_hex, Ledger,
};
use arcana_vault::{seal, seal_v1, unseal};
use ed25519_dalek::SigningKey;

#[derive(Parser, Debug)]
#[command(
    name = "arcana-acquire",
    version = TOOL_VERSION,
    about = "Air-gapped filesystem acquisition with AES-256-GCM vault sealing and a hash-chained custody ledger."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a fresh Ed25519 operator signing keypair.
    ///
    /// Prints the verifying key (public — record it with the case) and
    /// the signing seed (SECRET — store offline, never in the case
    /// directory or in git). The seed is wiped from memory right after
    /// printing; there is no copy anywhere else unless you make one.
    Keygen,
    /// Copy regular files from an approved root into a sealed case directory.
    Acquire {
        /// Source directory to scan (must exist).
        #[arg(long)]
        path: PathBuf,
        /// Case output directory (created if missing).
        #[arg(long)]
        out: PathBuf,
        /// Operator name recorded in the ledger.
        #[arg(long)]
        operator: String,
        /// Case identifier written into the manifest.
        #[arg(long, default_value = "case-001")]
        case_id: String,
        /// Maximum regular-file size in bytes.
        #[arg(long, default_value_t = DEFAULT_MAX_FILE_BYTES)]
        max_bytes: u64,
        /// Vault passphrase (prefer --password-env in real use).
        #[arg(long, env = "ARCANA_VAULT_PASSWORD")]
        password: Option<String>,
        /// Seal with the legacy v0x01 KDF instead of the v0x02 Argon2id
        /// default. Only for reproducing old seals; do not use for new
        /// acquisitions.
        #[arg(long)]
        legacy_v1: bool,
    },
    /// Recompute hashes and verify the custody hash chain.
    Verify {
        #[arg(long)]
        case: PathBuf,
        #[arg(long, env = "ARCANA_VAULT_PASSWORD")]
        password: Option<String>,
        /// 64-hex-char verifying key: also check every row's Ed25519
        /// signature. Without it, only the hash chain is checked.
        #[arg(long)]
        verifying_key: Option<String>,
    },
    /// Print the case manifest as JSON.
    ExportManifest {
        #[arg(long)]
        case: PathBuf,
    },
}

fn read_password(explicit: Option<String>) -> Result<String, ArcanaError> {
    if let Some(p) = explicit {
        if p.len() < 12 {
            return Err(ArcanaError::Vault(
                "passphrase must be at least 12 characters".into(),
            ));
        }
        return Ok(p);
    }
    Err(ArcanaError::Other(
        "passphrase required via --password or ARCANA_VAULT_PASSWORD".into(),
    ))
}

/// Loads the operator signing key from `ARCANA_SIGNING_KEY` (64 hex
/// chars). Returns `Ok(None)` when the variable is unset — acquisition
/// then writes unsigned (legacy) rows. Returns an error on malformed hex.
fn load_signing_key_from_env() -> Result<Option<SigningKey>, ArcanaError> {
    match env::var("ARCANA_SIGNING_KEY") {
        Ok(seed_hex) => Ok(Some(signing_key_from_seed_hex(&seed_hex)?)),
        Err(_) => Ok(None),
    }
}

/// One entry the acquisition skipped instead of aborting on. Skips are
/// also written to the custody ledger (action `SKIP: <reason>`, empty
/// sha256), so a later reviewer can see exactly what was left out.
#[derive(Debug, Clone)]
struct SkippedEntry {
    /// Path relative to the source directory, as the operator would see it.
    rel_path: String,
    /// Plain-words reason, e.g. `symlink`, `special file`, `unreadable file`.
    reason: String,
}

/// Writes `data` to `path` atomically: temp file in the same directory,
/// fsync, then rename. A crash leaves the old file or nothing — never a
/// half-written `.arcv`.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), ArcanaError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_name = format!(
        ".arcv-tmp-{}-{}",
        std::process::id(),
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    );
    let tmp_path = parent.join(tmp_name);
    let result = (|| {
        let mut f = File::create(&tmp_path).map_err(|e| ArcanaError::Io(e))?;
        f.write_all(data).map_err(ArcanaError::Io)?;
        f.sync_all().map_err(ArcanaError::Io)?;
        drop(f);
        fs::rename(&tmp_path, path).map_err(ArcanaError::Io)?;
        Ok::<(), ArcanaError>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn acquire(
    source: PathBuf,
    out: PathBuf,
    operator: String,
    case_id: String,
    max_bytes: u64,
    password: String,
    legacy_v1: bool,
) -> Result<(), ArcanaError> {
    if operator.trim().is_empty() {
        return Err(ArcanaError::Other("operator is required".into()));
    }
    if !source.is_dir() {
        return Err(ArcanaError::PathNotAllowed(format!(
            "source is not a directory: {}",
            source.display()
        )));
    }
    let source = source.canonicalize()?;
    fs::create_dir_all(&out)?;
    let out = out.canonicalize()?;

    let vault_dir = out.join("vault");
    let ledger_path = out.join("custody.sqlite");
    fs::create_dir_all(&vault_dir)?;

    let signing_key = load_signing_key_from_env()?;
    let verifying_hex = signing_key
        .as_ref()
        .map(|k| hex::encode(k.verifying_key().to_bytes()));

    let ledger = Ledger::open(&ledger_path)?;
    // One transaction for the whole run: on any hard error the ledger
    // rolls back and the .arcv files written by this run are removed,
    // so a crash cannot leave a half-written chain.
    ledger.begin()?;
    let mut written: Vec<PathBuf> = Vec::new();
    let mut manifest_written = false;
    let run = (|| {
        ledger.append_signed(
            &operator,
            "case-open",
            &source.display().to_string(),
            &sha256_bytes(case_id.as_bytes()),
            signing_key.as_ref(),
        )?;

        let mut evidence = Vec::new();
        let mut skipped: Vec<SkippedEntry> = Vec::new();

        for entry in WalkDir::new(&source).follow_links(false).into_iter() {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    skipped.push(SkippedEntry {
                        rel_path: String::new(),
                        reason: "unreadable directory entry".to_string(),
                    });
                    continue;
                }
            };
            let path = entry.path();
            if entry.file_type().is_dir() {
                continue;
            }
            // Relative path first, so every skip can be named even when
            // the file itself cannot be read.
            let rel = path
                .strip_prefix(&source)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if let Err(err) = reject_special_file(path) {
                let reason = if err.to_string().contains("symlink") {
                    "symlink".to_string()
                } else {
                    "special file".to_string()
                };
                skipped.push(SkippedEntry {
                    rel_path: rel,
                    reason,
                });
                continue;
            }
            if !entry.file_type().is_file() {
                skipped.push(SkippedEntry {
                    rel_path: rel,
                    reason: "special file".to_string(),
                });
                continue;
            }

            let confined = match confined_path(&source, path) {
                Ok(p) => p,
                Err(err) => {
                    skipped.push(SkippedEntry {
                        rel_path: rel,
                        reason: format!("path escape: {err}"),
                    });
                    continue;
                }
            };

            let meta = match confined.metadata() {
                Ok(m) => m,
                Err(e) => {
                    skipped.push(SkippedEntry {
                        rel_path: rel,
                        reason: format!("unreadable file: {e}"),
                    });
                    continue;
                }
            };
            if meta.len() > max_bytes {
                skipped.push(SkippedEntry {
                    rel_path: rel,
                    reason: format!("oversized ({} bytes)", meta.len()),
                });
                continue;
            }

            // Read once; a file that cannot be read is skipped, not fatal.
            let plaintext = match fs::read(&confined) {
                Ok(b) => b,
                Err(e) => {
                    skipped.push(SkippedEntry {
                        rel_path: rel,
                        reason: format!("unreadable file: {e}"),
                    });
                    continue;
                }
            };
            let digest = sha256_bytes(&plaintext);
            let header_len = plaintext.len().min(16);
            let (ext, hint) = classify_magic(&plaintext[..header_len], &rel);

            let blob = if legacy_v1 {
                seal_v1(&plaintext, &password)?
            } else {
                seal(&plaintext, &password)?
            };
            let vault_name = format!("{digest}.arcv");
            let vault_path = vault_dir.join(&vault_name);
            write_atomic(&vault_path, &blob)?;
            written.push(vault_path);

            ledger.append_signed(&operator, "ingest-seal", &rel, &digest, signing_key.as_ref())?;

            evidence.push(EvidenceRecord {
                source_path: confined.display().to_string(),
                relative_path: rel,
                size_bytes: meta.len(),
                sha256: digest,
                claimed_extension: ext,
                magic_hint: hint,
                vault_relpath: format!("vault/{vault_name}"),
            });
        }

        let manifest = CaseManifest {
            tool: TOOL_NAME.to_string(),
            version: TOOL_VERSION.to_string(),
            case_id,
            operator: operator.clone(),
            created_unix: unix_now(),
            source_root: source.display().to_string(),
            evidence,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        fs::write(out.join("manifest.json"), &manifest_bytes)?;
        manifest_written = true;
        ledger.append_signed(
            &operator,
            "manifest-write",
            "manifest.json",
            &sha256_bytes(&manifest_bytes),
            signing_key.as_ref(),
        )?;

        // Skips go in the ledger too, after the sealed rows, so the
        // record of what was left out survives with the case.
        for skip in &skipped {
            ledger.append_signed(
                &operator,
                &format!("SKIP: {}", skip.reason),
                &skip.rel_path,
                "",
                signing_key.as_ref(),
            )?;
        }
        Ok::<(usize, Vec<SkippedEntry>), ArcanaError>((
            manifest.evidence.len(),
            skipped,
        ))
    })();

    match run {
        Ok((sealed, skipped)) => {
            ledger.commit()?;
            let (n, ok) = ledger.verify_chain()?;
            println!(
                "acquired {sealed} file(s), skipped {}, ledger events {n}, chain_ok={ok}",
                skipped.len()
            );
            for skip in &skipped {
                let name = if skip.rel_path.is_empty() {
                    "(unreadable entry)"
                } else {
                    &skip.rel_path
                };
                println!("[SKIP] {name} ({})", skip.reason);
            }
            // Anchor material: print the chain tip + verifying key so
            // the operator can record them in a second location.
            if let Ok(tip) = ledger.chain_tip() {
                println!("[ANCHOR] Chain tip (record in a second location): {tip}");
            }
            match verifying_hex {
                Some(v) => println!("[SIGNED] Custody rows signed. Verifying key: {v}"),
                None => println!(
                    "[UNSIGNED] No ARCANA_SIGNING_KEY set — custody rows are unsigned (legacy hash chain only)."
                ),
            }
            println!("case directory: {}", out.display());
            Ok(())
        }
        Err(e) => {
            let _ = ledger.rollback();
            for out_path in &written {
                let _ = fs::remove_file(out_path);
            }
            if manifest_written {
                let _ = fs::remove_file(out.join("manifest.json"));
            }
            Err(e)
        }
    }
}

fn verify(
    case: PathBuf,
    password: Option<String>,
    verifying_key: Option<String>,
) -> Result<(), ArcanaError> {
    let case = case.canonicalize()?;
    let manifest_path = case.join("manifest.json");
    let raw = fs::read(&manifest_path)?;
    let manifest: CaseManifest = serde_json::from_slice(&raw)?;
    let ledger = Ledger::open(&case.join("custody.sqlite"))?;

    // With a verifying key, also check every row's signature.
    if let Some(key_hex) = verifying_key {
        let key = verifying_key_from_hex(&key_hex)?;
        let events = ledger.verify_chain_signed(&key)?;
        println!(
            "[PASS] Custody chain verified end-to-end ({events} signed rows intact: hash chain + Ed25519 signatures)."
        );
        if let Ok(tip) = ledger.chain_tip() {
            println!("[ANCHOR] Chain tip: {tip}");
        }
    } else {
        let (events, chain_ok) = ledger.verify_chain()?;
        println!("[PASS] Custody chain verified end-to-end ({events} hash-chained rows intact).");
        if let Ok(tip) = ledger.chain_tip() {
            println!("[ANCHOR] Chain tip: {tip}");
        }
        if !chain_ok {
            return Err(ArcanaError::Other(
                "custody hash chain does not verify".into(),
            ));
        }
    }

    let mut mismatches = 0u64;
    if let Some(pw) = password {
        for ev in &manifest.evidence {
            let vault = confined_path(&case, &case.join(&ev.vault_relpath))?;
            let blob = fs::read(&vault)?;
            let plain = unseal(&blob, &pw)?;
            let digest = sha256_bytes(&plain);
            if digest != ev.sha256 || plain.len() as u64 != ev.size_bytes {
                eprintln!("mismatch: {}", ev.relative_path);
                mismatches += 1;
            }
        }
    } else {
        println!("note: pass --password or ARCANA_VAULT_PASSWORD to unseal and re-hash vault blobs");
    }

    println!(
        "manifest files={}, vault_mismatches={mismatches}",
        manifest.evidence.len()
    );
    if mismatches > 0 {
        return Err(ArcanaError::Other("verification failed".into()));
    }
    Ok(())
}

fn export_manifest(case: PathBuf) -> Result<(), ArcanaError> {
    let case = case.canonicalize()?;
    let raw = fs::read(case.join("manifest.json"))?;
    let parsed: CaseManifest = serde_json::from_slice(&raw)?;
    println!("{}", serde_json::to_string_pretty(&parsed)?);
    Ok(())
}

fn run() -> Result<(), ArcanaError> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen => {
            let (mut seed, verifying) = generate_operator_keypair();
            println!("[OK] Operator signing key generated (Ed25519).");
            println!(
                "Verifying key (public — record this with the case): {}",
                hex::encode(verifying)
            );
            println!(
                "Signing seed (SECRET — store offline, never share): {}",
                hex::encode(seed)
            );
            println!("To sign at acquisition: set ARCANA_SIGNING_KEY to the seed above.");
            seed.zeroize();
            Ok(())
        }
        Commands::Acquire {
            path,
            out,
            operator,
            case_id,
            max_bytes,
            password,
            legacy_v1,
        } => {
            let password = read_password(password)?;
            acquire(path, out, operator, case_id, max_bytes, password, legacy_v1)
        }
        Commands::Verify {
            case,
            password,
            verifying_key,
        } => verify(case, password, verifying_key),
        Commands::ExportManifest { case } => export_manifest(case),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}
