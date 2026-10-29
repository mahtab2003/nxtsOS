#ifndef NXTS_SHA1_H
#define NXTS_SHA1_H
#include "common.h"
/* SHA-1 (FIPS 180-1), one-shot. Needed by web/SSL Phase 3
   (legacy): the TLS 1.1 PRF is MD5+SHA-1, SSLv3 uses SHA-1
   throughout, and legacy certificates may be SHA-1 signed.
   Test vectors (FIPS 180-1): sha1("abc") =
   a9993e364706816aba3e25717850c26c9cd0d89d, sha1("") =
   da39a3ee5e6b4b0d3255bfef95601890afd80709, sha1("abcdbcdecdef"
   "defgefghfghighijhijkijkljklmklmnlmnomnopnopq") =
   84983e441c3bd26ebaae4aa1f95129e5e54670f1, sha1("a" x 1000000) =
   34aa973cd4c4daa4f61eeb2bdbad27316534016f. */
void sha1_compute(const u8 *data, u32 len, u8 out[20]);
#endif
