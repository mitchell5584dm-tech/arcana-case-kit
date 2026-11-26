# Security Policy

## Supported versions

`0.1.x` on branch `main` is the only supported line.

## Product boundary

Arcana Forensics is an **offline-first acquisition and sealing toolkit**.

It does:

- walk an operator-specified directory of regular files
- refuse symlinks and special files
- confine output paths to the case directory
- hash files with SHA-256
- seal copies with stretched-passphrase AES-256-GCM
- append a local hash-chained SQLite custody ledger

It does **not**:

- wipe disks, run ATA Secure Erase, format NVMe namespaces, or erase LUKS headers
- phone home, upload evidence, or require a network
- treat a printed ledger line as a court-ready expert opinion by itself

Operators remain responsible for legal authority, consent, and their own evidence-handling procedures.

## Cryptography

- Key derivation: Argon2id (64 MiB memory, 3 iterations, 4 lanes, 32-byte key, Argon2 version 0x13) for new seals (ARCN v0x02). Legacy v0x01 blobs use the repo's 100,000-round SHA-256 KDF and still open; nothing seals v0x01 any more.
- Sealing: AES-256-GCM with a random 12-byte nonce per object
- Vault blob: `ARCN | version | salt(16) | nonce(12) | ciphertext+tag`
- Custody linkage: SHA-256 over canonical `ts|operator|action|path|sha256|prev_hash`; rows can also carry an Ed25519 signature over their `entry_hash` (see below)

Passphrases must be at least 12 characters. Prefer `ARCANA_VAULT_PASSWORD` from a local secret store over argv.

## Custody signing and anchoring

**Status:** prototype only. Not court-grade, not production-ready. This
procedure tells you how to use the signing that is in the tree; it does
not make a case court-ready by itself.

### In plain words: what anchoring is and why it matters

Every time files are sealed, the program writes a record book
(`custody.sqlite` in the case folder). Each row in the book has a
fingerprint, and each fingerprint includes the one before it, so the
rows form a chain.

Each row can also carry a **signature** — but only when a signing key
is used during sealing. The signature is what catches an attacker who
rewrites the book and fixes up all the fingerprints.

Anchoring is the second half of that protection. At the end of each
sealing, the program prints one fingerprint: the **chain tip** — the
fingerprint of the very last row. If you write that tip down somewhere
*other* than the case folder, you can later check that the book you are
looking at is the same book you sealed. In particular, the tip check
catches a **rollback**: someone swapping the whole book for an older,
still-validly-signed copy. Signed verification alone would pass on the
older copy (its signatures are real); only the tip comparison shows it
is not the latest book.

**Honest limit:** the tip is a fingerprint to *check against*, not a
backup. It cannot rebuild a lost record book or lost `.arcv` files. Keep
separate backups of the case folder as well. And the tip only helps if
it was recorded somewhere the attacker cannot also rewrite — that is
why the second location matters.

### The three strings — do not mix them up

| String | Length | Secret? | What it is |
|---|---|---|---|
| **Signing seed** | 64 hex characters | **YES — secret** | The private half of the operator key. Whoever holds it can sign rows. Made once by `arcana-acquire keygen`. |
| **Verifying key** | 64 hex characters | No — public | The public half. Anyone can use it to *check* signatures; it cannot *make* them. Record it with the case. |
| **Chain tip** | 64 hex characters | No — public | The fingerprint (`entry_hash`) of the last custody row after an acquisition. Changes with every acquisition. Record it in a second location, every time. |

All three look alike (long strings of letters a–f and digits). The
program always labels which one it is printing. Copy them exactly —
one wrong character and the check will fail.

### Step 1 — Make the operator key once (`arcana-acquire keygen`)

Do this once, before the first signed acquisition. Do it on the same
offline computer that will do the sealing, not on a shared machine.

1. In the repository root, run:
   ```
   cargo run -p arcana-acquire -- keygen
   ```
2. The program prints two lines. Write them down **on paper first**:
   - `Verifying key (public — record this with the case): …`
   - `Signing seed (SECRET — store offline, never share): …`
3. Store the **seed** like this:
   - On paper, in a sealed envelope, in a locked drawer or safe —
     **in a different place from the computer and the case folders.**
   - Never in the case folder, never in `git`, never in an email,
     chat message, shared document, screenshot, or cloud note.
     Never photograph it with a phone that backs photos up to the cloud.
   - The program wipes the seed from its own memory right after
     printing it. There is no copy anywhere else unless you make one.
     **If you lose every copy of the seed, you cannot make new signed
     rows with that key ever again.** (Old signed rows can still be
     *checked* with the verifying key — see Step 5.)
4. Write the **verifying key** where the case record lives (see Step 3).
   It is public, so it can go in the case notes, in git, or in an email.

### Step 2 — Seal with the key set (signed acquisition)

Before running `acquire`, set the signing key for that one terminal
session only:

```
export ARCANA_SIGNING_KEY=<the 64-hex-char seed from Step 1>
export ARCANA_VAULT_PASSWORD=<your passphrase, 12+ characters>
cargo run -p arcana-acquire -- acquire --path <source_dir> --out <case_dir> --operator <name>
```

Notes:

- Type the seed in by hand from the paper, or paste it from your
  password manager. Never save it in a file in the project folder.
- Close that terminal window when you are done, so the seed does not
  sit in the shell history of a shared machine. (On this machine the
  value is visible to other processes while it is set — that is a known
  limit of environment variables. A secret-file / keyring option is
  future work, not something this procedure pretends exists.)
- The program prints, for a signed acquisition:
  ```
  [ANCHOR] Chain tip (record in a second location): <64 hex chars>
  [SIGNED] Custody rows signed. Verifying key: <64 hex chars>
  ```
- If it prints `[UNSIGNED]` instead, no signing key was set. Those rows
  are hash-chained only — the old, weaker protection. That is fine for a
  test, but do not mistake an unsigned case for a signed one. Re-run
  with the key set if you meant to sign.

### Step 3 — Record the tip in a second location (every acquisition)

Copy the `[ANCHOR]` tip **and** the verifying key into your anchor log
within the same session, before you close the terminal. Use the template
below. Record **two** copies, in two different places — pick any two:

1. **Paper (best first copy).** A notebook kept apart from the
   computer. One line per acquisition. Paper cannot be edited silently
   by someone who gets into the computer.
2. **Git commit (good second copy).** Commit the anchor log file to a
   repository that lives somewhere else (for example, a private repo).
   A commit has a date and a history, so a changed tip shows up as a
   changed line.
3. **Email to yourself / a note on a second device.** Acceptable as the
   second copy if git is not set up. Use an account only you control.

Do **not** record the tip only inside the case folder (for example, in
a file next to `custody.sqlite`). That is the same disk, the same
attacker, the same loss — it anchors nothing.

### Anchor-log template (copy this)

```
Case: <case folder name, e.g. case-2026-11-25-a>
Date: <YYYY-MM-DD HH:MM, your local time>
Operator: <name from the acquire command>
Files sealed: <number the program printed>
Verifying key: <64 hex chars — same for every case under this operator key>
Chain tip: <64 hex chars — new after every acquisition>
Anchor copies kept at: <e.g. paper notebook p.12 + git commit abc1234>
Notes: <e.g. "first signed case" / "operator key changed — see Step 5">
```

If the tip line is missing from the program output, stop: the
acquisition may have failed part-way. Do not write down a tip from an
earlier case against a new one.

### Step 4 — Verify, and compare the tip (every time you check a case)

1. Run the signed check with the verifying key from your anchor log:
   ```
   cargo run -p arcana-acquire -- verify --case <case_dir> --verifying-key <verifying_key_hex>
   ```
2. The program prints:
   ```
   [PASS] Custody chain verified end-to-end (N signed rows intact: hash chain + Ed25519 signatures).
   [ANCHOR] Chain tip: <64 hex chars>
   ```
3. Compare, character by character, the printed tip with the tip in
   your anchor log for that case:
   - **Match, and `[PASS]`** — the book is the one you sealed, up to
     the latest row. This is the expected result.
   - **Tip does not match, even though it says `[PASS]`** — treat the
     case as suspect. The most likely cause is a rollback: the book
     was replaced with an older signed copy. **Stop. Do not unseal or
     rely on anything in the case.** Keep everything exactly as it is
     and get a second pair of eyes on it.
   - **Verification fails** — a row, a hash, or a signature does not
     check out. Same rule: stop, keep everything, do not try to fix
     the database by hand.
   - **Row count differs from the anchor log** — same as a tip
     mismatch: stop and ask. Rows were added or removed since the
     last anchoring.
4. Running `verify --case <case_dir>` with no key does the hash-only
   check. It also prints the tip, so the comparison in step 3 works
   there too — but it does **not** check signatures, so a rewritten
   book with fixed-up fingerprints would pass it. For any case that
   matters, use the signed form with the verifying key.

### Step 5 — If a key is lost, stolen, or changed

- **Seed lost, verifying key kept:** old signed rows can still be
  verified (Step 4) — verification only needs the verifying key. But
  no *new* signed rows can be made with that key. Run `keygen` again,
  store the new seed the Step 1 way, and write in the anchor log:
  `Operator key changed on <date> — old verifying key <…>, new
  verifying key <…>`. Cases sealed under the old key keep their old
  verifying key in their log lines.
- **Seed possibly seen by anyone else (stolen, photographed, pasted
  into a shared document, emailed):** stop using it immediately. Anyone
  with the seed can sign a forged chain. Generate a new keypair, note
  the change and the date in the anchor log, and treat cases sealed
  after the suspected exposure as untrusted until a reviewer has
  looked at them. There is no way to "un-share" a seed.
- **Verifying key lost:** it is printed again by every signed
  acquisition (`[SIGNED] Custody rows signed. Verifying key: …`) and
  it is in your anchor log. If both are gone, the signed rows cannot be
  checked until the key is recovered — the rows themselves are
  unchanged, but you have lost the ability to prove it. This is why
  Step 3 records the verifying key with every case, not just once.
- **Tip lost (anchor log entry missing):** the case can still be
  verified by signatures (Step 4, `[PASS]`), but the rollback check is
  gone for that case. Write down the tip the next time you verify it,
  and mark the log line `tip re-recorded on <date> — rollback check
  unavailable before this date`.

### What this procedure does not cover

- **Passphrases.** The vault passphrase (`ARCANA_VAULT_PASSWORD`,
  12+ characters) is separate from the signing seed. The same rules
  apply — never in a shared document, never in git.
- **Recon (Python).** Recon seals at ARCN v0x02 and does not sign
  custody rows at all. This procedure applies to the Rust CLI only.
- **Backups.** The tip is not a backup. Back up the case folder
  (`.arcv` files + `custody.sqlite`) separately, and keep the backup
  somewhere the anchor log is not — ideally, the backup and the anchor
  log should never be lost together.
- **Real keys.** No real operator key exists yet. When a real key is
  needed, follow Step 1 and treat that day as the start of the anchor
  log — do not back-date anything.

## Reporting a vulnerability

Email `security@arcana-forensics.com' with:

- affected commit SHA
- reproduction steps
- impact (integrity, confidentiality, or availability)

Do not open a public issue for an exploitable flaw until a fix is available.
