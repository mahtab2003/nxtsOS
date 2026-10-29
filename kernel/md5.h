#ifndef NXTS_MD5_H
#define NXTS_MD5_H
#include "common.h"
/* MD5 (RFC 1321), one-shot. Needed by web/SSL Phase 3 (legacy):
   the TLS 1.1 PRF is MD5+SHA-1, and SSLv3 Finished uses MD5.
   Test vectors (RFC 1321): md5("") =
   d41d8cd98f00b204e9800998ecf8427e, md5("abc") =
   900150983cd24fb0d6963f7d28e17f72, md5("message digest") =
   f96b697d7cb7938d525a2f31aaf161d0, md5("abcdefghijklmnopqrstuvwxyz") =
   c3fcd3d76192e4007dfb496cca67e13b, md5("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
   "abcdefghijklmnopqrstuvwxyz0123456789") =
   d174ab98d277d9f5a5611c2c9f419d9f, md5("1234567890" x 8) =
   57edf4a22be3c955ac49da2e2107b67a. */
void md5_compute(const u8 *data, u32 len, u8 out[16]);
#endif
