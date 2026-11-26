# Changelog

## Unreleased — port of the master bundle's Phase 1 fixes

- Vault sealing now defaults to ARCN v0x02 (Argon2id, 64 MiB / 3 iter /
  4 lanes) in both the Rust crate and Python Recon; v0x01 blobs still
  open. Cross-language v0x02 blobs verified in both directions.
- Custody ledger rows can now be signed with Ed25519
  (`arcana-acquire keygen`, `ARCANA_SIGNING_KEY`, `verify
  --verifying-key`); `SECURITY.md` now carries the written anchoring
  procedure (record the `[ANCHOR]` chain tip in a second location).
- Acquisition is transactional with rollback, writes `.arcv` files
  atomically, and logs skipped files as `SKIP` ledger rows instead of
  only counting them.
- No merge to `main` yet — this is on branch `port/bundle-phase1-fixes`
  for review. The ledger-vs-manifest cross-check gap is still open.

## 0.1.0

### Added

- Initial public release candidate
- Evidence acquisition workflows
- Cryptographic chain-of-custody validation
- Vault encryption support
- Field testing documentation
- Security baseline
- Software Bill of Materials (SBOM)

### Security

- Repository secret scanning
- Documentation hardening
- Public example credential cleanup
