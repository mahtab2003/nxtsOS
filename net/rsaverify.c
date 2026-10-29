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

/* MGF1 with SHA-256 (RFC 8017 B.2.1). The seed is always the
   32-byte H from the PSS encoding, so it is fixed-size. */
static void mgf1_sha256(const u8 seed[32], u8 *mask, u32 mask_len) {
    u8 buf[36];
    u8 h[32];
    u32 done = 0;
    u32 ctr = 0;
    memcpy(buf, seed, 32);
    while (done < mask_len) {
        buf[32] = (u8)(ctr >> 24);
        buf[33] = (u8)(ctr >> 16);
        buf[34] = (u8)(ctr >> 8);
        buf[35] = (u8)ctr;
        sha256_compute(buf, 36, h);
        u32 take = mask_len - done < 32 ? mask_len - done : 32;
        memcpy(mask + done, h, take);
        done += take;
        ctr++;
    }
}

int rsa_verify_pss_sha256(const u8 *mod_be, u32 mod_len, u32 exp,
                          const u8 *sig, u32 sig_len, const u8 *hash32) {
    if (!mod_be || !sig || !hash32) return -1;
    if (mod_len < 62 || mod_len > 256) return -1;
    if (sig_len != mod_len) return -1;
    bn_t mod, sig_bn, em;
    if (bn_from_be(&mod, mod_be, mod_len) != 0) return -1;
    if (bn_from_be(&sig_bn, sig, sig_len) != 0) return -1;
    if (bn_cmp(&sig_bn, &mod) >= 0) return -1; /* RSAVP1 range */
    if (bn_modexp(&em, &sig_bn, exp, &mod) != 0) return -1;
    u8 em_bytes[256];
    if (bn_to_be(&em, em_bytes, mod_len) != 0) return -1;
    /* emBits = bitlen(mod) - 1; emLen = ceil(emBits / 8). The
       encoded message must be emLen bytes with the leading
       (8*emLen - emBits) bits zero, and emLen must equal the
       modulus length (true for every 2048-bit key). */
    int em_bits = bn_bitlen(&mod) - 1;
    int em_len = (em_bits + 7) / 8;
    if (em_len != (int)mod_len) return -1;
    int zero_bits = 8 * em_len - em_bits;
    if (zero_bits > 0 && (em_bytes[0] >> (8 - zero_bits)) != 0) return -1;
    /* Layout: maskedDB || H || 0xBC. */
    if (em_bytes[em_len - 1] != 0xBC) return -1;
    u32 db_len = (u32)em_len - 32 - 1;
    const u8 *masked_db = em_bytes;
    const u8 *h = em_bytes + db_len;
    u8 db[223];
    if (db_len > sizeof(db)) return -1;
    mgf1_sha256(h, db, db_len);
    for (u32 i = 0; i < db_len; i++) db[i] ^= masked_db[i];
    /* RSASSA-PSS-VERIFY: clear the leftmost 8*emLen - emBits bits
       of DB after unmasking (the signer cleared those bits of
       maskedDB, so the unmasked DB inherits the mask's top bits
       there — without this step, DB[0] is 0x80 whenever
       MGF1(H)[0] has its top bit set, and verification fails
       for ~half of all valid signatures). */
    if (zero_bits > 0) db[0] &= (u8)(0xFF >> zero_bits);
    /* DB = PS (all zero) || 0x01 || salt. */
    u32 i = 0;
    while (i < db_len && db[i] == 0) i++;
    if (i >= db_len || db[i] != 0x01) return -1;
    i++;
    const u8 *salt = db + i;
    u32 salt_len = db_len - i;
    u8 hprime_input[8 + 32 + 223];
    memset(hprime_input, 0, 8);
    memcpy(hprime_input + 8, hash32, 32);
    memcpy(hprime_input + 40, salt, salt_len);
    u8 hprime[32];
    sha256_compute(hprime_input, 40 + salt_len, hprime);
    if (memcmp(hprime, h, 32) != 0) return -1;
    return 0;
}
