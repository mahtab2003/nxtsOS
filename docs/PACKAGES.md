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
Package signing is a known gap in v0.5.0 (see `docs/SECURITY.md`):
it needs a key-distribution story (whose key, where it is stored,
how it is revoked) that does not exist yet, and it is not claimed.
Root must only install packages from trusted sources.
