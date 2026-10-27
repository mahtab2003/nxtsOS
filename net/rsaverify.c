#include "rsaverify.h"
#include "bignum.h"
#include "../kernel/sha256.h"

/* SHA-256 DigestInfo prefix (PKCS#1 v1.5). */
static const u8 SHA256_DER_PREFIX[] = {
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

int rsa_verify_sha256(const u8 *mod_be, u32 mod_len, u32 exp,
                      const u8 *sig, u32 sig_len,
                      const u8 *msg, u32 msg_len) {
    if (!mod_be || !sig || !msg) return -1;
    if (mod_len != sig_len) return -1;
    if (mod_len < 62 || mod_len > 256) return -1;
    bn_t mod, sig_bn, em;
    if (bn_from_be(&mod, mod_be, mod_len) != 0) return -1;
    if (bn_from_be(&sig_bn, sig, sig_len) != 0) return -1;
    if (bn_modexp(&em, &sig_bn, exp, &mod) != 0) return -1;
    u8 em_bytes[256];
    if (bn_to_be(&em, em_bytes, mod_len) != 0) return -1;
    if (em_bytes[0] != 0x00 || em_bytes[1] != 0x01) return -1;
    u32 i = 2;
    while (i < mod_len && em_bytes[i] == 0xFF) i++;
    if (i - 2 < 8) return -1; /* padding too short */
    if (i >= mod_len || em_bytes[i] != 0x00) return -1;
    i++;
    if (mod_len - i != sizeof(SHA256_DER_PREFIX) + 32) return -1;
    if (memcmp(em_bytes + i, SHA256_DER_PREFIX, sizeof(SHA256_DER_PREFIX)) != 0) return -1;
    u8 hash[32];
    sha256_compute(msg, msg_len, hash);
    if (memcmp(em_bytes + i + sizeof(SHA256_DER_PREFIX), hash, 32) != 0) return -1;
    return 0;
}
