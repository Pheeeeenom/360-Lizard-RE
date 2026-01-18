#include "Lizard_API.h"


#define TRACE(...) do { printf(__VA_ARGS__); printf("\n"); } while (0)
static const uint8_t sess_key[16] = { 0xBE,0xBE,0xCA,0xFE,0xBE,0xBE,0xCA,0xFE,0xBE,0xBE,0xCA,0xFE,0xBE,0xBE,0xCA,0xFE };
static const uint8_t xor_key[16] = { 0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF };
/* =================== AES helpers (Standard BCrypt Wrappers) =================== */
static NTSTATUS aes_ecb_oneblock(const uint8_t in[16], const uint8_t key[16],
    uint8_t out[16], int encrypt)
{
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL; NTSTATUS st;
    DWORD objLen = 0, cb = 0; PBYTE objBuf = NULL;

    if ((st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)) != 0) goto done;
    if ((st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, (ULONG)sizeof(BCRYPT_CHAIN_MODE_ECB), 0)) != 0) goto done;
    if ((st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0)) != 0) goto done;
    objBuf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, objLen); if (!objBuf) { st = STATUS_NO_MEMORY; goto done; }
    if ((st = BCryptGenerateSymmetricKey(hAlg, &hKey, objBuf, objLen, (PUCHAR)key, 16, 0)) != 0) goto done;

    memcpy(out, in, 16);
    if (encrypt) st = BCryptEncrypt(hKey, out, 16, NULL, NULL, 0, out, 16, &cb, 0);
    else         st = BCryptDecrypt(hKey, out, 16, NULL, NULL, 0, out, 16, &cb, 0);

done:
    if (hKey) BCryptDestroyKey(hKey);
    if (objBuf) HeapFree(GetProcessHeap(), 0, objBuf);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return st;
}
static void aes_ecb_enc16(const uint8_t in[16], const uint8_t key[16], uint8_t out[16]) {
    if (aes_ecb_oneblock(in, key, out, 1) != 0) memset(out, 0, 16);
}
static void aes_ecb_dec16(const uint8_t in[16], const uint8_t key[16], uint8_t out[16]) {
    if (aes_ecb_oneblock(in, key, out, 0) != 0) memset(out, 0, 16);
}
static NTSTATUS aes_cbc_crypt(const uint8_t* in, uint8_t* out, DWORD len,
    const uint8_t key[16], const uint8_t iv[16], int encrypt)
{
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL; NTSTATUS st;
    DWORD objLen = 0, cb = 0; PBYTE objBuf = NULL; UCHAR ivbuf[16];
    if (len % 16 != 0) return STATUS_INVALID_PARAMETER;
    if ((st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)) != 0) goto done;
    if ((st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) != 0) goto done;
    if ((st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0)) != 0) goto done;
    objBuf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, objLen); if (!objBuf) { st = STATUS_NO_MEMORY; goto done; }
    if ((st = BCryptGenerateSymmetricKey(hAlg, &hKey, objBuf, objLen, (PUCHAR)key, 16, 0)) != 0) goto done;
    memcpy(ivbuf, iv, 16);
    if (encrypt) st = BCryptEncrypt(hKey, (PUCHAR)in, len, NULL, ivbuf, 16, out, len, &cb, 0);
    else         st = BCryptDecrypt(hKey, (PUCHAR)in, len, NULL, ivbuf, 16, out, len, &cb, 0);
done:
    if (hKey) BCryptDestroyKey(hKey);
    if (objBuf) HeapFree(GetProcessHeap(), 0, objBuf);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return st;
}

/* =================== Utility for AUTH =================== */
static void rand16(uint8_t out[16]) { for (int i = 0;i < 16;i++) out[i] = (uint8_t)(rand() & 0xFF); }
static void xor16(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]) {
    for (int i = 0;i < 16;i++) out[i] = (uint8_t)(a[i] ^ b[i]);
}
static int equal16(const uint8_t* a, const uint8_t* b) {
    uint8_t d = 0; for (int i = 0;i < 16;i++) d |= (uint8_t)(a[i] ^ b[i]); return d == 0;
}
int hex_to_bytes16(const char* hex, uint8_t out[16]) {
    if (!hex) return -1;
    size_t len = strlen(hex);
    if (len != 32) return -2;
    for (size_t i = 0; i < 16; ++i) {
        char hi = hex[i * 2], lo = hex[i * 2 + 1];
        if (!isxdigit((unsigned char)hi) || !isxdigit((unsigned char)lo)) return -3;
        int vhi = (hi <= '9') ? (hi - '0') : (toupper((unsigned char)hi) - 'A' + 10);
        int vlo = (lo <= '9') ? (lo - '0') : (toupper((unsigned char)lo) - 'A' + 10);
        out[i] = (uint8_t)((vhi << 4) | vlo);
    }
    return 0;
}

/* =================== AUTH 0x28 LOGIC (D5S) =================== */
static uint8_t shift_left_128(uint8_t* buf, uint8_t input_bit) {
    uint8_t carry_out = (buf[0] >> 7) & 1;
    for (int i = 0; i < 15; i++) {
        buf[i] = (buf[i] << 1) | ((buf[i + 1] >> 7) & 1);
    }
    buf[15] = (buf[15] << 1) | (input_bit & 1);
    return carry_out;
}
static void xor_128(const uint8_t* a, const uint8_t* b, uint8_t* out) {
    for (int i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
}
static void calc_aes_ecb_mac(const uint8_t* dvd_key, const uint8_t* shift_data, uint8_t* mac_out) {
    uint8_t array_low[16];
    uint8_t array_high[16];

    memcpy(array_low, shift_data, 16);
    memset(array_high, 0, 16);
    array_high[15] = 1;
    memcpy(mac_out, dvd_key, 16);

    for (int i = 0; i <= 127; i++) {
        uint8_t carry_from_low = shift_left_128(array_low, 0);
        shift_left_128(array_high, carry_from_low);
        uint8_t next_mac[16];
        aes_ecb_enc16(array_high, mac_out, next_mac);
        memcpy(mac_out, next_mac, 16);
    }
}
static void calc_genuine_sig(const uint8_t* b_keys_buff, uint8_t* out_seed) {
    uint8_t k1[16], k2[16], constant[16], tmp[16], x1[16];
    hex_to_bytes16("47454E55494E452058424F58204F4444", constant);
    memcpy(k1, b_keys_buff, 16);
    memcpy(k2, b_keys_buff + 16, 16);
    aes_ecb_enc16(constant, k1, tmp);
    xor_128(tmp, constant, x1);
    aes_ecb_enc16(x1, k2, tmp);
    xor_128(tmp, x1, out_seed);
}

int auth28(HANDLE h,
    const uint8_t dvd_key[16],
    const uint8_t sess_key[16],
    const uint8_t xor_key[16])
{
    uint8_t payload[74];
    uint8_t crypto_buf[32];
    uint8_t derived_key[16];
    uint8_t challenge[16];
    uint8_t shift_data[16];
    uint8_t signature[16];
    uint8_t response[512];
    uint8_t zero_check[16] = { 0 };
    uint8_t err = 0, sns = 0;

    rand16(challenge);
    calc_aes_ecb_mac(dvd_key, xor_key, derived_key);

    memset(payload, 0, sizeof(payload));
    payload[1] = 0x48;
    payload[8] = 0x28;
    payload[9] = 0x40;

    memcpy(crypto_buf, sess_key, 16);
    memcpy(crypto_buf + 16, challenge, 16);

    if (aes_cbc_crypt(crypto_buf, crypto_buf, 32, derived_key, xor_key, 1) != 0) {
        printf("Error: AES-CBC Encryption failed\n");
        return -3;
    }

    memcpy(payload + 10, crypto_buf, 32);
    memcpy(payload + 42, xor_key, 16);

    calc_genuine_sig(crypto_buf, shift_data);
    calc_aes_ecb_mac(derived_key, shift_data, signature);
    memcpy(payload + 58, signature, 16);

    liz_sync(h);

    {
        uint8_t cdb[12] = { 0x03,0,0,0,0x12,0,0,0,0,0,0,0 };
        uint8_t dummy[18];
        int rc = liz_atapi_cmd(h, cdb, 0, 18, 0, dummy, &err, &sns, 0);
        TRACE("AUTH28: PRE-CHECK rc=%d err=0x%02X", rc, err);
        if (rc != 0) return -1;
    }
    {
        uint8_t cdb[12] = { 0x55,0,0,0,0,0,0,0,0x4C,0,0,0 };
        int rc = liz_atapi_cmd(h, cdb, 1, 0, 74, payload, &err, &sns, 1);
        TRACE("AUTH28: SEND PAYLOAD rc=%d err=0x%02X", rc, err);
        if (rc != 0) return -1;
    }
    {
        uint8_t cdb[12] = { 0x5A,0x00,0x28,0x00,0,0,0,0,0x3A,0,0,0 };
        int rc = liz_atapi_cmd(h, cdb, 0, 58, 0, response, &err, &sns, 1);
        TRACE("AUTH28: READ RESP rc=%d err=0x%02X", rc, err);
        if (rc != 0) return -1;
        dump_hex("AUTH28 FULL PAGE RESPONSE", response, 58);
    }

    memcpy(crypto_buf, response + 10, 32);

    if (aes_cbc_crypt(crypto_buf, crypto_buf, 32, sess_key, xor_key, 0) != 0) {
        printf("Error: AES-CBC Decryption failed\n");
        return -3;
    }

    if (memcmp(crypto_buf, zero_check, 16) != 0) {
        printf("AUTH28 FAILED: Response Header not zero\n");
        dump_hex("Decrypted Header", crypto_buf, 16);
        return -2;
    }

    if (memcmp(crypto_buf + 16, challenge, 16) != 0) {
        printf("AUTH28 FAILED: Challenge mismatch\n");
        dump_hex("Sent Challenge", challenge, 16);
        dump_hex("Recv Challenge", crypto_buf + 16, 16);
        return -2;
    }

    printf("AUTH28 result = OK\n");
    return 0;
}

/* =================== AUTH 0x3B (D4S) =================== */
int auth3b(HANDLE h,
    const uint8_t dvd_key[16],
    const uint8_t sess_key[16],
    const uint8_t xor_key[16])
{
    uint8_t page[74]; memset(page, 0, sizeof(page));
    uint8_t sense[18] = { 0 }, resp[58] = { 0 }; uint8_t err = 0, sns = 0;
    uint8_t chal[16], blk1[16], blk2[16], tA[16], tB[16], tmp[16];
    page[8] = 0x3B; page[9] = 0x30; rand16(chal);
    xor16(sess_key, xor_key, blk1); aes_ecb_enc16(blk1, dvd_key, blk1); memcpy(&page[10], blk1, 16);
    for (int i = 0;i < 16;i++) blk2[i] = (uint8_t)(chal[i] ^ blk1[i]); aes_ecb_enc16(blk2, dvd_key, blk2); memcpy(&page[26], blk2, 16);
    memcpy(&page[42], xor_key, 16);

    liz_sync(h);
    {
        uint8_t cdb[12] = { 0x03,0,0,0,0x12,0,0,0,0,0,0,0 };
        int rc = liz_atapi_cmd(h, cdb, 0, 18, 0, sense, &err, &sns, 0);
        TRACE("REQ SENSE rc=%d err=0x%02X sns=0x%02X", rc, err, sns); if (rc || err != 0x50) return -1;
    }
    {
        uint8_t cdb[12] = { 0x55,0,0,0,0,0,0,0,0x3C,0,0,0 };
        int rc = liz_atapi_cmd(h, cdb, 1, 0, 74, page, &err, &sns, 1);
        TRACE("MODE SELECT rc=%d err=0x%02X sns=0x%02X", rc, err, sns); if (rc || err != 0x50) return -1;
    }
    {
        uint8_t cdb[12] = { 0x5A,0x00,0x3B,0x00,0,0,0,0,0x3A,0,0,0 };
        int rc = liz_atapi_cmd(h, cdb, 0, 58, 0, resp, &err, &sns, 1);
        TRACE("MODE SENSE rc=%d err=0x%02X sns=0x%02X", rc, err, sns); if (rc || err != 0x50) return -1;
        dump_hex("AUTH3B FULL PAGE RESPONSE", resp, 58);
    }

    memcpy(tA, &resp[26], 16); memcpy(tB, &resp[10], 16);
    aes_ecb_dec16(tA, sess_key, tmp); for (int i = 0;i < 16;i++) tmp[i] ^= tB[i];
    if (!equal16(tmp, chal)) return -1;
    printf("AUTH3B result = OK\n"); dump_hex("challenge (0x10)", chal, 16);
    return 0;
}

/* DRAMDUMP one block */
int dramdump_one(HANDLE h,
    const uint8_t sess_key[16],
    const uint8_t xor_key[16],
    uint32_t lAddress,
    uint8_t out16[16])
{
    uint8_t page58[58], tx58[58], sense18[18], resp58[58];
    uint8_t err = 0, sns = 0;

    memset(page58, 0, 58);
    page58[8] = 0x21; page58[9] = 0x30;
    memcpy(&page58[10], sess_key, 16);
    page58[42] = 0x04;
    page58[46] = (uint8_t)((lAddress >> 24) & 0xFF);
    page58[47] = (uint8_t)((lAddress >> 16) & 0xFF);
    page58[48] = (uint8_t)((lAddress >> 8) & 0xFF);
    page58[49] = (uint8_t)(lAddress & 0xFF);
    page58[53] = 16;

    memcpy(tx58, page58, 58);
    if (aes_cbc_crypt(&page58[10], &tx58[10], 48, sess_key, xor_key, 1) != 0) return -1;

    liz_sync(h);
    {
        uint8_t cdb[12] = { 0x03,0,0,0,0x12,0,0,0,0,0,0,0 };
        int rc = liz_atapi_cmd(h, cdb, 0, 18, 0, sense18, &err, &sns, 0); if (rc || err != 0x50) return -1;
    }
    {
        uint8_t cdb[12] = { 0x55,0,0,0,0,0,0,0,0x3C,0,0,0 };
        int rc = liz_atapi_cmd(h, cdb, 1, 0, 58, tx58, &err, &sns, 1); if (rc) return -1;
    }
    {
        uint8_t cdb[12] = { 0x5A,0x00,0x21,0x00,0,0,0,0,0x3A,0,0,0 };
        int rc = liz_atapi_cmd(h, cdb, 0, 58, 0, resp58, &err, &sns, 1); if (rc) return -1;
    }

    uint8_t s1_32[32];
    if (aes_cbc_crypt(&resp58[10], s1_32, 32, sess_key, xor_key, 0) != 0) return -1;

    uint8_t mid16[16], iv_ff[16], iv_00[16];
    memcpy(mid16, &s1_32[16], 16);
    memset(iv_ff, 0xFF, 16); memset(iv_00, 0x00, 16);
    if (aes_cbc_crypt(mid16, mid16, 16, sess_key, iv_ff, 0) != 0) return -1;
    if (aes_cbc_crypt(mid16, mid16, 16, sess_key, iv_00, 0) != 0) return -1;
    memcpy(out16, mid16, 16);
    return 0;
}

int dramdump(HANDLE h,
    const uint8_t sess_key[16],
    const uint8_t xor_key[16],
    const char* out_filename)
{
    FILE* f = fopen(out_filename, "wb");
    if (!f) {
        printf("Failed to open %s for writing\n", out_filename);
        return -1;
    }
    for (int i = 0; i < 20; i++) {
        uint32_t addr = 0x3088E + (uint32_t)(i * 16);
        uint8_t out16[16];
        int rc = dramdump_one(h, sess_key, xor_key, addr, out16);
        if (rc != 0) {
            printf("DRAMDUMP failed at index %d (addr=0x%X)\n", i, addr);
            fclose(f);
            return -2;
        }
        fwrite(out16, 1, 16, f);
        liz_send_etx(h); Sleep(10);
    }
    fclose(f);
    printf("DRAM dump complete! Dumped %d bytes to %s\n", 20 * 16, out_filename);
    return 0;
}