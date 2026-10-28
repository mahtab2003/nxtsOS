#ifndef NXTS_CSPRNG_H
#define NXTS_CSPRNG_H
#include "common.h"
/* ChaCha20 DRBG (web/SSL Phase 1). Replaces the timer/MAC-seeded
   xorshift for ALL crypto use: TLS ClientHello random, ECDHE
   private keys, RSA premasters, GCM padding, password salts.
   Entropy model, stated honestly: the seed pool is stirred from
   RTC (CMOS) time at boot, PS/2 keyboard scancode + timer-tick
   timing, PS/2 mouse packet timing, and (uniqueness only, NOT
   secrecy) the NIC MAC address. There is no hardware RNG on the
   target and no RDRAND assumption. Early-boot output — before
   any input event — is only as strong as RTC time + boot
   timing + MAC uniqueness; every generate() call reseeds when
   new input timing has arrived since the last reseed, so keys
   made after the user has typed are mixed with real event
   timing. This is NOT a FIPS DRBG and claims nothing more.
   Non-crypto uses (window-manager test shuffles) keep xorshift. */
void csprng_init(void);    /* seed from CMOS RTC; called at boot */
void csprng_stir(const u8 *data, u32 len); /* mix event timing in */
void csprng_generate(u8 *out, u32 len);    /* DRBG output */
int  csprng_selftest(void); /* 0 pass: RFC 8439 vector + sanity */
#endif
