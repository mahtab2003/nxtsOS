#ifndef NXTS_CAPS_H
#define NXTS_CAPS_H
#include "common.h"
/* Capabilities (CORE_CLI.md section 15.4, redesign 5): a
   per-process bitmask checked ALONGSIDE uid 0 in every shell
   root gate. A gate passes only if uid == 0 AND the needed
   bit is set; root without the bit is refused with a message
   naming the missing capability, and non-root behaviour is
   unchanged ("root only"). The shell session holds the mask
   for its commands; each spawned process inherits a copy at
   spawn (struct proc caps, set from the session mask), so a
   process's mask is its own — later session changes do not
   rewrite a running job's mask. Bits are shell-gate level in
   this phase: user syscalls still authorise by uid only, as
   before (documented, not silently claimed otherwise).
   The fs layer keeps its own uid-0 re-check for chown, so a
   capability grant can never bypass the filesystem's owner
   rule — the two checks are defence in depth, not rivals. */
#define CAP_CAP   0 /* manage capabilities (cap drop/grant) */
#define CAP_SYS   1 /* shutdown/halt/poweroff, hostname, dmesg -c, date set */
#define CAP_USER  2 /* useradd/userdel/groupadd/groupdel/groupmod, unlock, passwd for others */
#define CAP_FS    3 /* chown, chgrp */
#define CAP_PKG   4 /* pkg install/remove/repo/update/fetch, sysupdate, sysrollback, castore, tofprints */
#define CAP_NET   5 /* fw mutations, dhcp, dnsset, privileged (<1024) srv ports */
#define CAP_AUDIT 6 /* log, last (audit-log reading) */
#define CAP_NBITS 7
#define CAP_ALL   ((1u << CAP_NBITS) - 1u)
const char *caps_name(int bit); /* "cap_sys", ...; "cap_unknown" out of range */
/* MAC/LSM hook point (documented future step, no policy
   engine yet): every root gate calls mac_check AFTER the
   capability check passes. Today it always allows (returns
   0); a future LSM policy registers here and can only
   further restrict a gate that capabilities already passed.
   A deny would print "refused by MAC policy" at the gate. */
int mac_check(const char *op); /* 0 allow, -1 deny */
#endif
