# nxtsOS packages (Phase 6, v0.5.0)

## Format

A package is a single file, created on the host with `tools/mkpkg.py`:

```
bytes 0-7:   "NXPKG001"
bytes 8-11:  manifest length, u32 little-endian (1..2048)
bytes 12..:  manifest text, printable ASCII + '\n', ending with '\n'
then:        file blobs, in manifest order, concatenated, no padding
```

Total package size must be exactly `12 + manifest_len + sum(file sizes)`,
at most 131,072 bytes. Each file is 1..65,536 bytes, at most 8 files
per package, at most 8 packages installed (registry size limit).

Manifest lines (exactly one `name:`, one `version:`, one `depends:`,
at least one `file:`, no unknown or duplicate lines):

```
name:hello
version:1.0
depends:hello>=1.0,greet==2.0
file:hello.elf:6208:<64 hex chars, SHA-256 of the file blob>
```

- Package name: starts with a lowercase letter, then `[a-z0-9_-]`, 1..31 chars.
- Version: digits and dots only, e.g. `1.0`, `1.1`.
- Dependency: a package name, optionally `>=version` or `==version`.
  No operator means any version satisfies it.
- Filename: 1..31 chars, printable, no `/`, not a system file
  (`packages.txt`, `users.txt`, `audit.log`, `fails.txt`), not a `.nxpkg`.

## Install, list, remove (shell, root only except list)

```
pkg list
pkg install <package-file>   # root only
pkg remove <name>            # root only, refused if another package depends on it
pkg remove <name> force      # root only, with a warning naming the dependent
sha256 <file>                # print the SHA-256 of a file (any user, readable files)
```

Install order of checks, all before any file is written:

1. Package file readable and within the size cap.
2. Manifest parses strictly; any malformed line, duplicate key, bad
   name/version/filename, or unknown line rejects the whole package.
3. Blob layout adds up exactly to the package size (a manifest lying
   about a file size is caught here, not after writing).
4. Every file's SHA-256 matches its manifest hash.
5. Dependencies: every dependency must already be installed, at a
   version satisfying its operator. A missing dependency, a
   conflicting version, a self-dependency, or a dependency cycle
   (which cannot install, because each side waits for the other)
   all refuse the install.
6. Target files must not belong to another package or be a loose file
   on disk — except, for an upgrade, files of the package itself.
7. Free-space pre-check for the new sectors needed.

Then files are written (mode 0644, owner root), and the registry is
written last. A failed write rolls back the files written in that
install (normal installs only — see the upgrade limit below).
A duplicate install of the same version is refused; installing a
different version of an installed package is an upgrade: the new
package is verified fully first, then old files it drops are deleted
and the registry version is updated. Upgrade atomicity limit: if a
disk write fails mid-upgrade, files may be mixed while the registry
still names the old version — the pre-checks make that a disk-error
path, not a normal path, and it is stated here, not hidden.

The registry is root-only `packages.txt` (mode 0600), one line per
package: `name|version|depends_csv|file,sha256hex;file,sha256hex`.
Non-root users cannot create, write, delete, or read it through the
shell, but `pkg list` (which reads it internally) works for any user.

## Load-time verification

When a program is run with `run` or `runbg`, the ELF loader checks
whether the file belongs to an installed package. If it does, its
SHA-256 must match the registry, or the program is refused to run —
even if it is still a valid ELF. Loose (non-package) files run as
before, with ELF validation only. This is how post-install tampering
is caught: the test flips a byte in an installed ELF on disk, and
the next `run` refuses it while `pkg list` still shows the package.

## Trust: what hashes do and do not prove

Hashes prove a file matches its manifest, and has not changed since
install (registry is root-only, so a non-root user cannot rewrite
the registry to match a tampered file). Hashes do **not** prove who
made the package. A package file from an untrusted source, installed
by root, is trusted by root's decision, not by any signature.
Package signing was a known gap in v0.5.0 (see `docs/SECURITY.md`).
It is closed in v1.0.0 — see "Package signatures" below. Root must
still only install packages from trusted sources: a signature
proves who signed, not that the author is safe.

## Package signatures (Phase 11, v1.0.0)

- Format NXPKG002: the v0.5.0 layout, plus a trailing
  signature block: magic `NXSG`, u16 little-endian
  length (256), and a 256-byte RSA PKCS#1 v1.5
  signature over SHA-256 of the manifest bytes.
  The manifest carries the per-file SHA-256 hashes and
  the installer verifies every blob against them, so
  a valid signature authenticates the whole package.
  Unsigned NXPKG001 packages are refused with
  `package is not signed (legacy format)`; a bad
  signature is refused with `bad package signature`.
- Signing: `tools/mkpkg.py ... --sign-key KEY.PEM`
  (uses `openssl dgst -sha256 -sign`). The verifier
  is the shared RSA helper `net/rsaverify.c`, also
  used by the TLS certificate verifier.
- Trust anchors, tried in order: (1) the compiled-in
  vendor key (`kernel/vendor_pubkey.h`, generated by
  `tools/genvendorpub.py` from `build/signing.key`
  on every build, so it can never drift from the
  signer); (2) the root-owned keyring file
  `pubkeys.txt` — one 512-hex-char RSA-2048 modulus
  per line, exponent fixed at 65537, malformed lines
  skipped with a warning. A missing keyring is not
  an error. Root adds a key by writing the file
  (disk image build or shell `write`); pubkeys.txt is
  a system file, so a non-root user can neither create
  it nor overwrite a root-owned copy. There is no
  key-add command, and no revocation list — removing
  a key means editing `pubkeys.txt` (vendor key
  rotation means regenerating the keypair, rebuilding
  the kernel, and re-signing every package).
  Ship `pubkeys.txt` root-owned, mode 0600: the kernel
  refuses non-root CREATION of system files (so an
  attacker cannot pre-create the keyring before root
  does and get their key trusted), and overwriting an
  existing keyring follows normal ownership/mode
  checks — a non-root-owned or world-writable keyring
  would defeat the whole scheme.
- Key custody: `build/signing.key` is generated once
  by `scripts/build.sh`, kept in `build/` (git-ignored,
  never in the source or distribution archives). If it
  is lost, every previously signed package becomes
  uninstallable until re-signed with the new key.

## System updates (Phase 11, v1.0.0)

- Bundle format `.nxupd` (built by
  `tools/mkupdate.py`): magic `NXUPD001`, then
  signed NXPKG002 packages concatenated unchanged
  (at most 8 packages, 512 KiB total). The bundle
  carries no separate signature — each member's own
  signature is the trust anchor.
- `sysupdate <bundle>` (root only) is two-phase:
  FIRST it verifies every package (parse, hashes,
  signature, duplicates, same-version, dependencies
  against the virtual registry of installed +
  bundle packages, reverse dependencies of installed
  packages the bundle does not touch, file conflicts,
  duplicate targets, dependency cycles) and computes
  a topological commit order — all BEFORE writing
  anything. THEN it snapshots (every file the update
  could overwrite or drop, plus a copy of
  `packages.txt`, plus a journal), checks directory
  slots and free sectors, and commits through the
  normal installer. ANY failure restores the snapshot
  (files, dropped files, registry, removal of newly
  created files). A successful update leaves the
  snapshot for `sysrollback`; a failed update
  restores it and deletes it if the restore fully
  succeeds.
- `sysrollback` (root only) restores the last
  snapshot and consumes it — a second call reports
  `no update to roll back`. One generation only.
- Snapshot files (`rollback.txt`, `rb_packages.txt`,
  `rb0`..`rb63`) are system files: a non-root user
  can neither pre-create them nor overwrite a
  root-owned copy, so rollback state cannot be
  poisoned the way the keyring could have been.
- Honest limits: snapshot and bundle share the
  32-file directory cap and the 16 MiB disk, so very
  large updates are refused up front; a single
  `pkg install` upgrade still does not check reverse
  dependencies (only `sysupdate` does); rollback
  restores file contents and the registry, not
  side effects a package's programs may have had
  while installed.

## Remote package repository (Phase 11, v1.0.0)

- Commands (all root-only except `pkg repo` with no
  argument, which prints the current repository):
  `pkg repo <host[:port][/prefix]>` (stores the URL
  in root-only `repo.txt`), `pkg update` (fetches
  and verifies the index), `pkg fetch <name>`
  (downloads a package to `<name>.nxpkg`, refuses if
  that file already exists), `pkg install <name>`
  (bare name = repository install; a local file
  wins if it exists, and a `.nxpkg` argument is
  always a local file).
- Transport is plain HTTP BY DESIGN. The kernel TLS
  client has no public CA trust store (TOFU
  self-signed roots only), so HTTPS to a public host
  cannot verify anything; signatures, not transport,
  carry authenticity — exactly like apt's signed
  Release files. A repository is a static directory:
  signed NXPKG002 packages + `index.txt` +
  `index.txt.sig` (512 hex chars = RSA signature
  over the exact index bytes). Build one with
  `tools/mkrepo.py --key KEY.PEM --out DIR
  [--version N] PACKAGE.NXPKG ...`.
- Index format: `NXREPO1`, then `version:<decimal>`
  (publisher-managed, monotonic), then one line per
  package: `name|version|file|sha256hex`. `pkg
  update` verifies the index signature (vendor key
  or keyring, same anchors as packages) and refuses
  a malformed index, a bad signature, or an index
  OLDER than the stored one (anti-rollback; equal
  versions re-update fine). The stored index
  (`repo_index.txt` + `repo_index.sig`) is
  re-verified on EVERY use, so tampering with it on
  disk cannot redirect installs — and every package
  is hash-checked against the index AND
  signature-checked again before install, so a
  tampered package, a wrong-key package, or a 404
  page served in place of a package are all
  refused.
- `repo.txt`, `repo_index.txt`, and
  `repo_index.sig` are system files: a non-root
  user can neither pre-create them nor overwrite a
  root-owned copy.
- Honest limits: the kernel TCP client is
  single-connection and HTTP/1.0 only (no chunked
  encoding); `net_http_get` counts response headers
  against the package buffer, so a repository
  package must be a little under the 132096-byte
  package cap (headers take roughly 200 bytes);
  index size is capped at 16 KiB (64 packages);
  there is no mirror/fallback, no per-package
  pinning, and no TLS — a repository URL is
  public by design, and only signatures make it
  trustworthy.
