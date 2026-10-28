# nxtsFS — on-disk layout (v0.3.0)

Sector size is 512 bytes. All integers are little-endian u32.

## Layout for a 16 MiB disk (32,768 sectors)

| Sectors | Contents |
|---|---|
| 0 | Superblock |
| 1–8 | Sector bitmap, 1 bit per sector (4096 bytes = 32,768 sectors) |
| 9–12 | Root directory, 4 sectors, 32 entries of 64 bytes |
| 13–32767 | File data |

The superblock, bitmap, and directory sectors are marked used in the
bitmap. File data is allocated as contiguous sector runs.

## Superblock (sector 0)

| Offset | Field |
|---|---|
| 0 | Magic, 8 bytes: `"NXTSFS01"` |
| 8 | Version, u32 = 1 |
| 12 | Total sectors, u32 |
| 16 | Bitmap sectors, u32 |
| 20 | Directory sector (first), u32 |
| 24 | Directory sectors, u32 |
| 28 | Data start sector, u32 |
| 32 | Max files, u32 |
| 36–511 | Reserved, zero |

Mount validation (all must hold, otherwise mount fails cleanly and the
disk is never written): magic exact, version 1, total sectors >= 100
and <= 1,000,000, bitmap sectors = ceil(total/4096) capped by the layout,
directory sector = 1 + bitmap sectors, data start = directory sector +
directory sectors, data start < total sectors, max files =
directory sectors * 8.

## Directory entry (64 bytes)

| Offset | Field |
|---|---|
| 0–31 | Name, NUL-terminated, max 31 chars, printable ASCII only, no `/` |
| 32 | Size in bytes, u32 |
| 36 | Start sector, u32 |
| 40 | Sector count, u32 |
| 44 | Owner UID, u32 |
| 48 | Mode, u32 (Unix-style bits, only 0777 accepted) |
| 52 | Flags, u32 (bit 0 = used) |
| 56–63 | Reserved, zero |

Entry validation on every use: flags used, name NUL-terminated inside
the 32 bytes and printable, size <= sector count * 512, start sector
>= data start, start + sector count <= total sectors, sector count > 0
when size > 0, mode <= 0777. An entry failing validation is skipped
with a warning, never read or written through. A superblock failing
validation prevents mounting at all.

## Safety rules

- The kernel never formats a disk automatically. A disk with no valid
  superblock is reported, not wiped. Formatting is done only by the
  host tool `tools/mkdisk.py`, with explicit user action.
- No write is issued for a block outside the disk, a size larger than
  the free space, or a name longer than 31 chars. A failed write keeps
  the previous file intact (new blocks are allocated before old blocks
  are freed).
- All ATA waits have a timeout. A missing, faulty, or timing-out disk
  returns an error; it never hangs the kernel.
- Rename (`fs_rename_as`, shell `mv`) is metadata-only: the directory
  entry keeps its uid, mode, size, and data sectors, so a rename can
  never silently re-own or re-permit a file. It refuses a missing
  source, an existing destination (never overwrites), a caller who
  may not write the source, and a non-root rename involving a system
  file name. The desktop Files list still goes stale for renames made
  outside its window until it is refreshed — the Files window's
  Refresh button re-enumerates the list in place (scroll kept,
  clamped), or the window is reopened — as for all outside-window
  changes. (This sentence used to say "until reopen" only; the
  Refresh button, added later, is the in-place path.)
- Copy (`fs_copy_as`, shell `cp`) is byte-exact and size-unlimited:
  data moves sector by sector, so unlike `cat` (text display, which
  stops a chunk at a NUL byte) plus `write` (typed text), it copies
  binary files and files of any size. The destination is a new file owned by the caller with
  the source's mode; the source is left untouched. It refuses a
  missing source and an existing destination (never overwrites,
  including a copy onto itself). It grants no new access: the source
  must already be readable by the caller, and a non-root caller may
  not create a system-named destination. A mid-copy failure leaves
  no partial file behind (sectors are unmarked and neither the
  bitmap nor the directory is saved).
- Mode change (`fs_chmod_as`, shell `chmod <file> <mode>`) is
  metadata-only: only the mode changes; owner, size, and data sectors
  are untouched, so a chmod can never silently re-own or truncate a
  file. Only root or the file's owner may change it — a non-owner is
  refused even if the file is world-writable, because changing who may
  read a file is not a write to its data. The mode is octal, 3 digits
  with an optional leading 0 (`600`, `0644`); anything else is refused,
  never masked down, and a mode over 0777 is refused by the primitive
  itself. `ls` prints the stored mode in decimal (0600 shows as 384,
  0644 as 420). Before this command landed, every user-created file
  stayed 0644 (world-readable) with no user path to restrict it, even
  though the kernel enforces owner/other bits and the system itself
  keeps private files at 0600; root or the owner can now restrict a
  file with this command or the Files window's chmod control. (This
  sentence used to read as if no restriction path existed; the shell
  `chmod` command and the Files-window chmod control, added later,
  are that path.)
