/*
 * Copyright (c) 2025 Mena Azer <emdazer@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>


#pragma region firmware parsing
// -------------------- small helpers --------------------

static void trim_copy(char* dst, size_t dstsz, const char* src) {
    while (*src == ' ' || *src == '\t' || *src == '\r' || *src == '\n') src++;
    size_t n = strlen(src);
    while (n > 0 && (src[n - 1] == ' ' || src[n - 1] == '\t' || src[n - 1] == '\r' || src[n - 1] == '\n')) n--;
    if (dstsz == 0) return;
    size_t c = (n < dstsz - 1) ? n : (dstsz - 1);
    memcpy(dst, src, c);
    dst[c] = 0;
}

static int file_exists(const char* path) {
#ifdef _WIN32
    return _access(path, 0) == 0;
#else
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
#endif
}

static int64_t file_len(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
#if defined(_WIN32)
    _fseeki64(f, 0, SEEK_END);
    int64_t sz = _ftelli64(f);
#else
    fseeko(f, 0, SEEK_END);
    int64_t sz = (int64_t)ftello(f);
#endif
    fclose(f);
    return sz;
}

static int read_exact_fw_parse(FILE* f, int64_t off, uint8_t* buf, int len) {
#if defined(_WIN32)
    if (_fseeki64(f, off, SEEK_SET) != 0) return 0;
#else
    if (fseeko(f, (off_t)off, SEEK_SET) != 0) return 0;
#endif
    return fread(buf, 1, len, f) == (size_t)len;
}

static void bytes_to_hex_upper(const uint8_t* src, int n, char* dst) {
    static const char H[] = "0123456789ABCDEF";
    for (int i = 0; i < n; i++) {
        dst[i * 2 + 0] = H[(src[i] >> 4) & 0xF];
        dst[i * 2 + 1] = H[src[i] & 0xF];
    }
    dst[n * 2] = 0;
}

static void str_upper_inplace(char* s) {
    for (; *s; s++) *s = (char)toupper((unsigned char)*s);
}

// -------------------- VB: Class12.smethod_35 --------------------
static int class12_read_bytes(const char* path, int64_t off, int len, uint8_t* out) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    int ok = read_exact_fw_parse(f, off, out, len);
    fclose(f);
    return ok;
}

// -------------------- VB: Class12.smethod_37 --------------------
static int64_t class12_find_hex_string(const char* path, const char* hex_pat, int len_bytes, int64_t start_off) {
    if (!file_exists(path)) return -1;

    int64_t sz = file_len(path);
    if (sz < 0) return -1;

    char* pat = _strdup(hex_pat);
    if (!pat) return -1;
    str_upper_inplace(pat);

    uint8_t* buf = (uint8_t*)malloc((size_t)len_bytes);
    char* hex = (char*)malloc((size_t)len_bytes * 2 + 1);
    if (!buf || !hex) { free(buf); free(hex); free(pat); return -1; }

    for (int64_t off = start_off; off <= sz - len_bytes; off++) {
        if (!class12_read_bytes(path, off, len_bytes, buf)) break;
        bytes_to_hex_upper(buf, len_bytes, hex);
        char* hit = strstr(hex, pat);
        if (hit) {
            int idx = (int)(hit - hex);
            int64_t pos = off + (int64_t)idx / 2;
            free(buf); free(hex); free(pat);
            return pos;
        }
    }

    free(buf); free(hex); free(pat);
    return -1;
}

// -------------------- Class10 (Hitachi decrypt) --------------------

static uint8_t class10_perm[32];
static int class10_inited = 0;

static void class10_smethod_0(void) {
    static const uint8_t p[32] = {
        2,8,17,24,30,23,0,13,5,31,20,12,18,10,6,26,
        21,27,11,16,14,28,7,1,22,3,19,9,29,15,25,4
    };
    memcpy(class10_perm, p, 32);
    class10_inited = 1;
}

static void u32_to_bin32(uint32_t v, char out[33]) {
    for (int i = 0; i < 32; i++) {
        int bit = (v >> (31 - i)) & 1;
        out[i] = bit ? '1' : '0';
    }
    out[32] = 0;
}

static void bin32_to_bytes_weird(const char in[33], uint8_t out[4]) {
    out[0] = out[1] = out[2] = out[3] = 0;
    for (int num = 0; num <= 7; num++) {
        if (in[0 + num] == '1') out[3] = (uint8_t)(out[3] + (1u << num));
        if (in[8 + num] == '1') out[2] = (uint8_t)(out[2] + (1u << num));
        if (in[16 + num] == '1') out[1] = (uint8_t)(out[1] + (1u << num));
        if (in[24 + num] == '1') out[0] = (uint8_t)(out[0] + (1u << num));
    }
}

static void class10_smethod_2(const uint8_t in4[4], uint8_t out4[4]) {
    if (!class10_inited) class10_smethod_0();

    uint32_t v =
        ((uint32_t)(in4[0] ^ 0x66) << 24) |
        ((uint32_t)(in4[1] ^ 0x64) << 16) |
        ((uint32_t)(in4[2] ^ 0x60) << 8) |
        ((uint32_t)(in4[3] ^ 0xF7));

    char bits[33];
    u32_to_bin32(v, bits);

    char outbits[33];
    memcpy(outbits, bits, 33);
    for (int num = 0; num <= 31; num++) {
        int dest = 31 - num;
        int src = 31 - (int)class10_perm[num];
        outbits[dest] = bits[src];
    }
    outbits[32] = 0;

    bin32_to_bytes_weird(outbits, out4);
}

static int class10_read_maybe_decrypt(const char* path, int64_t off, int len, int decrypt, uint8_t* out) {
    int64_t aligned = off & ~3LL;
    int len4 = len & ~3;

    FILE* f = fopen(path, "rb");
    if (!f) return 0;

    if (!decrypt) {
        int ok = read_exact_fw_parse(f, off, out, len);
        fclose(f);
        return ok;
    }

    if (len4 <= 0) { fclose(f); return 0; }
    if (!read_exact_fw_parse(f, aligned, out, len4)) { fclose(f); return 0; }

    for (int i = 0; i < len4; i += 4) {
        uint8_t tmp[4];
        memcpy(tmp, out + i, 4);
        uint8_t dec[4];
        class10_smethod_2(tmp, dec);
        memcpy(out + i, dec, 4);
    }

    fclose(f);
    return 1;
}

// -------------------- Class8 (graph.dll xor transform) --------------------

static uint8_t class8_byte0[256];
static uint8_t class8_byte1[256];
static uint8_t class8_byte2[256];
static int class8_inited = 0;

static void class8_smethod_0(void) {
    static const uint8_t b1[256] = {
        0xB4,0x88,0x94,0x4A,0x4D,0xC6,0x03,0xC2,0xD0,0xB5,0x0B,0x69,0xDC,0xCA,0x5F,0xF6,
        0xDF,0x0E,0xF3,0x5D,0x86,0xC4,0x0D,0x97,0x77,0x4C,0x9F,0xA5,0x43,0x47,0xD4,0xD3,
        0x96,0xFC,0xE9,0x3A,0xB1,0xFA,0x3E,0x1B,0xFF,0xAD,0x04,0x93,0x19,0x1A,0xCC,0x48,
        0x4B,0x61,0xF2,0x66,0x29,0x68,0xB6,0x53,0xA2,0x35,0x2F,0x95,0x14,0x75,0xE7,0x42,
        0xC9,0x60,0xEB,0xA1,0xA0,0x6D,0x8F,0xD5,0x05,0x8B,0xEA,0x6E,0x80,0x83,0x76,0x5A,
        0x67,0x45,0x0F,0x63,0x7D,0x27,0x79,0x41,0x8A,0x28,0xF0,0xA7,0x81,0xC8,0xC0,0x98,
        0x12,0x54,0x20,0x00,0x89,0xA8,0x31,0x74,0x5B,0x26,0xED,0x87,0x16,0xC1,0x18,0x2B,
        0x71,0xAC,0x17,0x07,0x52,0x3C,0x7B,0x57,0x34,0xDD,0xF5,0x1D,0xEC,0x9E,0x59,0x7A,
        0x38,0xFE,0x21,0x58,0x8C,0xD8,0xB8,0x56,0x7E,0x2D,0x6C,0x82,0xAE,0xE2,0x5E,0x39,
        0xE0,0x30,0xAF,0xBF,0x9D,0xCE,0x33,0xF4,0x10,0xCB,0x1E,0x2C,0x0C,0x37,0xBE,0x46,
        0xCD,0xB2,0x6A,0xBC,0xF1,0x1F,0x13,0xF9,0x65,0x23,0x84,0xF7,0x8E,0xE8,0x70,0xB3,
        0x7F,0x2A,0xA4,0xD9,0xE5,0xC5,0x72,0x9C,0xEE,0xDE,0xD7,0xCF,0xBD,0x4F,0xFB,0x99,
        0x1C,0xE6,0x3B,0x32,0x2E,0xFD,0x78,0x01,0x49,0xE4,0xD2,0x02,0xBA,0x25,0x55,0x73,
        0x90,0x92,0xD6,0xB9,0xAA,0xE3,0x9B,0x44,0xDB,0x6B,0xC7,0x0A,0x9A,0xBB,0x09,0xA9,
        0x50,0xC3,0xA6,0x11,0x3F,0xD1,0x4E,0x8D,0x7C,0x6F,0xDA,0x51,0x22,0xB7,0xF8,0x08,
        0x36,0x3D,0x40,0x91,0x64,0x85,0x15,0xE1,0x62,0x5C,0xAB,0xB0,0x24,0xEF,0x06,0xA3
    };
    memcpy(class8_byte1, b1, 256);
    for (int i = 0; i < 256; i++) class8_byte2[class8_byte1[i]] = (uint8_t)i;
}


static void class8_smethod_1(void) {
    static const uint8_t b0[256] = {
        0x00,0x10,0x20,0x30,0x01,0x11,0x21,0x31,0x02,0x12,0x22,0x32,0x03,0x13,0x23,0x33,
        0x40,0x50,0x60,0x70,0x41,0x51,0x61,0x71,0x42,0x52,0x62,0x72,0x43,0x53,0x63,0x73,
        0x80,0x90,0xA0,0xB0,0x81,0x91,0xA1,0xB1,0x82,0x92,0xA2,0xB2,0x83,0x93,0xA3,0xB3,
        0xC0,0xD0,0xE0,0xF0,0xC1,0xD1,0xE1,0xF1,0xC2,0xD2,0xE2,0xF2,0xC3,0xD3,0xE3,0xF3,
        0x04,0x14,0x24,0x34,0x05,0x15,0x25,0x35,0x06,0x16,0x26,0x36,0x07,0x17,0x27,0x37,
        0x44,0x54,0x64,0x74,0x45,0x55,0x65,0x75,0x46,0x56,0x66,0x76,0x47,0x57,0x67,0x77,
        0x84,0x94,0xA4,0xB4,0x85,0x95,0xA5,0xB5,0x86,0x96,0xA6,0xB6,0x87,0x97,0xA7,0xB7,
        0xC4,0xD4,0xE4,0xF4,0xC5,0xD5,0xE5,0xF5,0xC6,0xD6,0xE6,0xF6,0xC7,0xD7,0xE7,0xF7,
        0x08,0x18,0x28,0x38,0x09,0x19,0x29,0x39,0x0A,0x1A,0x2A,0x3A,0x0B,0x1B,0x2B,0x3B,
        0x48,0x58,0x68,0x78,0x49,0x59,0x69,0x79,0x4A,0x5A,0x6A,0x7A,0x4B,0x5B,0x6B,0x7B,
        0x88,0x98,0xA8,0xB8,0x89,0x99,0xA9,0xB9,0x8A,0x9A,0xAA,0xBA,0x8B,0x9B,0xAB,0xBB,
        0xC8,0xD8,0xE8,0xF8,0xC9,0xD9,0xE9,0xF9,0xCA,0xDA,0xEA,0xFA,0xCB,0xDB,0xEB,0xFB,
        0x0C,0x1C,0x2C,0x3C,0x0D,0x1D,0x2D,0x3D,0x0E,0x1E,0x2E,0x3E,0x0F,0x1F,0x2F,0x3F,
        0x4C,0x5C,0x6C,0x7C,0x4D,0x5D,0x6D,0x7D,0x4E,0x5E,0x6E,0x7E,0x4F,0x5F,0x6F,0x7F,
        0x8C,0x9C,0xAC,0xBC,0x8D,0x9D,0xAD,0xBD,0x8E,0x9E,0xAE,0xBE,0x8F,0x9F,0xAF,0xBF,
        0xCC,0xDC,0xEC,0xFC,0xCD,0xDD,0xED,0xFD,0xCE,0xDE,0xEE,0xFE,0xCF,0xDF,0xEF,0xFF
    };
    memcpy(class8_byte0, b0, 256);
}


static void class8_init(void) {
    if (class8_inited) return;
    class8_smethod_1();
    class8_smethod_0();
    class8_inited = 1;
}

static int class8_xform_block(const char* fw_path, const char* graph_path, int64_t fw_off, int len, int64_t graph_base, uint8_t* out) {
    class8_init();

    FILE* fw = fopen(fw_path, "rb");
    if (!fw) return 0;
    FILE* gr = fopen(graph_path, "rb");
    if (!gr) { fclose(fw); return 0; }

    uint8_t* a = (uint8_t*)malloc((size_t)len);
    uint8_t* b = (uint8_t*)malloc((size_t)len);
    if (!a || !b) { free(a); free(b); fclose(fw); fclose(gr); return 0; }

    int ok = read_exact_fw_parse(fw, fw_off, a, len) && read_exact_fw_parse(gr, graph_base + fw_off, b, len);
    if (!ok) { free(a); free(b); fclose(fw); fclose(gr); return 0; }

    for (int i = 0; i < len; i++) {
        out[i] = (uint8_t)(class8_byte0[a[i]] ^ class8_byte2[b[i]]);
    }

    free(a); free(b);
    fclose(fw); fclose(gr);
    return 1;
}

static int64_t class8_find_hex_pattern(const char* fw_path, const char* graph_path, int64_t graph_base,
    const char* hex_pat_in, int block_len, int64_t start_off, int64_t end_off) {
    char* pat = _strdup(hex_pat_in);
    if (!pat) return -1;
    str_upper_inplace(pat);

    int64_t sz = file_len(fw_path);
    if (sz < 0) { free(pat); return -1; }
    if (end_off < 0 || end_off > sz) end_off = sz;
    if (start_off < 0) start_off = 0;

    uint8_t* tmp = (uint8_t*)malloc((size_t)block_len);
    char* hex = (char*)malloc((size_t)block_len * 2 + 1);
    if (!tmp || !hex) { free(tmp); free(hex); free(pat); return -1; }

    for (int64_t off = start_off; off < end_off; off += block_len) {
        if (!class8_xform_block(fw_path, graph_path, off, block_len, graph_base, tmp)) {
            free(tmp); free(hex); free(pat);
            return -1;
        }
        bytes_to_hex_upper(tmp, block_len, hex);

        char* hit = strstr(hex, pat);
        if (hit) {
            int idx = (int)(hit - hex);
            int64_t found = off + (int64_t)idx / 2;
            free(tmp); free(hex); free(pat);
            return found;
        }
    }

    free(tmp); free(hex); free(pat);
    return -1;
}

// -------------------- Class12 ports: vendor/model/type/key checks --------------------

static int check_size_256k(const char* path, char* err, size_t errsz) {
    int64_t sz = file_len(path);
    if (sz != 262144) {
        snprintf(err, errsz, "INVALID FILE SIZE, MUST BE 256KB (got %lld)", (long long)sz);
        return 0;
    }
    err[0] = 0;
    return 1;
}

// VB Class12.cpoahSiso (Hitachi crypt flag based on header signature)
static int hitachi_is_crypted(const char* path, char* err, size_t errsz) {
    if (!check_size_256k(path, err, errsz)) return 0;
    uint8_t hdr[16];
    if (!class12_read_bytes(path, 0, 16, hdr)) { snprintf(err, errsz, "read failed"); return 0; }
    char hex[33];
    bytes_to_hex_upper(hdr, 16, hex);
    if (strcmp(hex, "F2D22E2EBE2AAE0B8E2CF7DED2DAB7A5") == 0) return 0;
    if (strcmp(hex, "D56EB91215D228221C91EE78F709F900") == 0) return 1;
    snprintf(err, errsz, "UN-IDENTIFIED VENDOR-MODEL");
    return 0;
}

static void fw_get_vendor(const char* path, char* vendor_out, size_t vendor_sz, char* err, size_t errsz) {
    vendor_out[0] = 0;
    err[0] = 0;

    if (!check_size_256k(path, err, errsz)) return;

    uint8_t b16[16];
    uint8_t b4[4];
    uint8_t b4b[4];

    if (!class12_read_bytes(path, 0, 16, b16)) { snprintf(err, errsz, "read failed"); return; }
    char hex16[33];
    bytes_to_hex_upper(b16, 16, hex16);

    if (strcmp(hex16, "F2D22E2EBE2AAE0B8E2CF7DED2DAB7A5") == 0 ||
        strcmp(hex16, "D56EB91215D228221C91EE78F709F900") == 0) {
        strncpy(vendor_out, "HITACHI   ", vendor_sz);
        return;
    }
    if (strcmp(hex16, "021C30021D924A4C0000000000000000") == 0) {
        strncpy(vendor_out, "SAMSUNG   ", vendor_sz);
        return;
    }

    if (!class12_read_bytes(path, 0, 4, b4)) { snprintf(err, errsz, "read failed"); return; }
    char hex4[9];
    bytes_to_hex_upper(b4, 4, hex4);
    int flag = (strcmp(hex4, "02003002") == 0);

    if (!class12_read_bytes(path, 12, 4, b4b)) { snprintf(err, errsz, "read failed"); return; }
    char hex4b[9];
    bytes_to_hex_upper(b4b, 4, hex4b);

    if (flag && strcmp(hex4b, "EE341CFE") == 0) {
        strncpy(vendor_out, "BENQ      ", vendor_sz);
        return;
    }

    if (strcmp(hex16, "18B21F3A5DE31800199C0C5836B7922C") == 0 ||
        strcmp(hex16, "18B21F3A5DE31852448A4E5870E6C3F8") == 0 ||
        strcmp(hex16, "187A533A5DE318F016E27509147FE4CA") == 0 ||
        strcmp(hex16, "187A533A5DE318DE72A7D0D21B71FE40") == 0 ||
        strcmp(hex16, "18B21F3A5DE318308D5AB8ECC8791E39") == 0 ||
        strcmp(hex16, "18B21F3A5DE31884B0E2CE2652850420") == 0 ||
        strcmp(hex16, "09EF6C2B03BD23D821AE092B011D558E") == 0 ||
        strcmp(hex16, "0922962B0F1223D821AE092B011D558E") == 0 ||
        strcmp(hex16, "096D882B0F1223D821AE092B011D558E") == 0 ||
        strcmp(hex16, "4DAFE66F4B84679C65FA4D6F454901DA") == 0) {
        strncpy(vendor_out, "LITEON    ", vendor_sz);
        return;
    }

    snprintf(err, errsz, "UN-IDENTIFIED VENDOR");
}

static void fw_get_model(const char* vendor, const char* path, char* model_out, size_t model_sz, char* err, size_t errsz) {
    model_out[0] = 0;
    err[0] = 0;

    if (!check_size_256k(path, err, errsz)) return;

    char vtrim[32];
    trim_copy(vtrim, sizeof(vtrim), vendor);

    uint8_t b16[16];
    uint8_t b4[4];
    uint8_t b4b[4];

    if (strcmp(vtrim, "HITACHI") == 0) {
        if (!class12_read_bytes(path, 0, 16, b16)) { snprintf(err, errsz, "read failed"); return; }
        char hex16[33]; bytes_to_hex_upper(b16, 16, hex16);
        if (strcmp(hex16, "F2D22E2EBE2AAE0B8E2CF7DED2DAB7A5") == 0 ||
            strcmp(hex16, "D56EB91215D228221C91EE78F709F900") == 0) {
            strncpy(model_out, "GDR3120L  ", model_sz);
            return;
        }
    }
    else if (strcmp(vtrim, "SAMSUNG") == 0) {
        if (!class12_read_bytes(path, 0, 16, b16)) { snprintf(err, errsz, "read failed"); return; }
        char hex16[33]; bytes_to_hex_upper(b16, 16, hex16);
        if (strcmp(hex16, "021C30021D924A4C0000000000000000") == 0) {
            strncpy(model_out, "TSH943A   ", model_sz);
            return;
        }
    }
    else if (strcmp(vtrim, "BENQ") == 0) {
        if (!class12_read_bytes(path, 0, 4, b4)) { snprintf(err, errsz, "read failed"); return; }
        char hex4[9]; bytes_to_hex_upper(b4, 4, hex4);
        int flag = (strcmp(hex4, "02003002") == 0);
        if (!class12_read_bytes(path, 12, 4, b4b)) { snprintf(err, errsz, "read failed"); return; }
        char hex4b[9]; bytes_to_hex_upper(b4b, 4, hex4b);
        if (flag && strcmp(hex4b, "EE341CFE") == 0) {
            strncpy(model_out, "VAD6038   ", model_sz);
            return;
        }
    }
    else if (strcmp(vtrim, "LITEON") == 0) {
        if (!class12_read_bytes(path, 0, 16, b16)) { snprintf(err, errsz, "read failed"); return; }
        char hex16[33]; bytes_to_hex_upper(b16, 16, hex16);

        if (strcmp(hex16, "18B21F3A5DE31800199C0C5836B7922C") == 0 ||
            strcmp(hex16, "18B21F3A5DE31852448A4E5870E6C3F8") == 0 ||
            strcmp(hex16, "187A533A5DE318F016E27509147FE4CA") == 0 ||
            strcmp(hex16, "187A533A5DE318DE72A7D0D21B71FE40") == 0 ||
            strcmp(hex16, "18B21F3A5DE318308D5AB8ECC8791E39") == 0 ||
            strcmp(hex16, "18B21F3A5DE31884B0E2CE2652850420") == 0) {
            strncpy(model_out, "DG16D2S   ", model_sz);
            return;
        }
        if (strcmp(hex16, "09EF6C2B03BD23D821AE092B011D558E") == 0 ||
            strcmp(hex16, "0922962B0F1223D821AE092B011D558E") == 0 ||
            strcmp(hex16, "096D882B0F1223D821AE092B011D558E") == 0) {
            strncpy(model_out, "DG16D4S   ", model_sz);
            return;
        }
        if (strcmp(hex16, "4DAFE66F4B84679C65FA4D6F454901DA") == 0) {
            strncpy(model_out, "DG16D5S   ", model_sz);
            return;
        }
        if (strncmp(hex16, "4DAFA16F", 8) == 0) {
            strncpy(model_out, "DG16D5S   ", model_sz);
            return;
        }
    }

    snprintf(err, errsz, "UN-IDENTIFIED VENDOR-MODEL");
}

static int hitachi_is_stock(const char* path, int crypted, char* err, size_t errsz) {
    err[0] = 0;
    uint8_t buf[4096];
    if (!class10_read_maybe_decrypt(path, 12288, 4096, crypted, buf)) {
        snprintf(err, errsz, "read failed");
        return 0;
    }
    for (int i = 0; i < 4096; i++) {
        if (buf[i] != 0xFF) return 0;
    }
    return 1;
}

static void fw_get_type(const char* vendor, const char* model, const char* path,
    char* type_out, size_t type_sz, char* err, size_t errsz) {
    type_out[0] = 0;
    err[0] = 0;

    char vtrim[32], mtrim[32];
    trim_copy(vtrim, sizeof(vtrim), vendor);
    trim_copy(mtrim, sizeof(mtrim), model);

    if (strcmp(vtrim, "HITACHI") == 0) {
        if (strcmp(mtrim, "GDR3120L") != 0) { snprintf(err, errsz, "UNKNOWN HITACHI IDENTIFIER"); return; }

        char e2[128];
        int crypted = hitachi_is_crypted(path, e2, sizeof(e2));
        if (e2[0]) { strncpy(err, e2, errsz); return; }

        uint8_t b4[4]; char h4[9];

        if (!class10_read_maybe_decrypt(path, 4136, 4, crypted, b4)) { snprintf(err, errsz, "read failed"); return; }
        bytes_to_hex_upper(b4, 4, h4);

        if (strcmp(h4, "C005A00A") == 0) {
            if (!class10_read_maybe_decrypt(path, 4580, 4, crypted, b4)) { snprintf(err, errsz, "read failed"); return; }
            bytes_to_hex_upper(b4, 4, h4);
            if (strcmp(h4, "DD00F100") == 0) { strncpy(type_out, "32        ", type_sz); return; }
            if (strcmp(h4, "DD12F000") == 0) { strncpy(type_out, "40        ", type_sz); return; }
            snprintf(err, errsz, "UNKNOWN HITACHI GDR3120 32/40 IDENTIFIER"); return;
        }

        if (strcmp(h4, "BC05A00A") == 0) { strncpy(type_out, "36        ", type_sz); return; }

        if (strcmp(h4, "C405A00A") == 0) {
            if (!class10_read_maybe_decrypt(path, 33836, 4, crypted, b4)) { snprintf(err, errsz, "read failed"); return; }
            bytes_to_hex_upper(b4, 4, h4);
            if (strcmp(h4, "CAED0200") == 0) { strncpy(type_out, "46        ", type_sz); return; }
            if (strcmp(h4, "E0ED0200") == 0) { strncpy(type_out, "47        ", type_sz); return; }
            snprintf(err, errsz, "UNKNOWN HITACHI GDR3120 46/47 IDENTIFIER"); return;
        }

        if (strcmp(h4, "C805A00A") == 0) {
            if (!class10_read_maybe_decrypt(path, 33836, 4, crypted, b4)) { snprintf(err, errsz, "read failed"); return; }
            bytes_to_hex_upper(b4, 4, h4);
            if (strcmp(h4, "00DD39F0") == 0) { strncpy(type_out, "58        ", type_sz); return; }
            if (strcmp(h4, "00DD4FF0") == 0) { strncpy(type_out, "59        ", type_sz); return; }
            snprintf(err, errsz, "UNKNOWN HITACHI GDR3120 58/59 IDENTIFIER"); return;
        }

        if (!class10_read_maybe_decrypt(path, 109936, 4, crypted, b4)) { snprintf(err, errsz, "read failed"); return; }
        bytes_to_hex_upper(b4, 4, h4);

        if (!class10_read_maybe_decrypt(path, 30540, 4, crypted, b4)) { snprintf(err, errsz, "read failed"); return; }
        char h4b[9]; bytes_to_hex_upper(b4, 4, h4b);

        if (strcmp(h4, "004B0090") == 0) {
            if (strcmp(h4b, "C809DDAF") == 0) { strncpy(type_out, "78-4B00   ", type_sz); return; }
            if (strcmp(h4b, "C809DDC5") == 0) { strncpy(type_out, "79-4B00   ", type_sz); return; }
            snprintf(err, errsz, "UNKNOWN HITACHI GDR3120 78/79 4B00 IDENTIFIER"); return;
        }
        else if (strcmp(h4, "104E0090") == 0) {
            if (strcmp(h4b, "C809DDC8") == 0) { strncpy(type_out, "78-4E10   ", type_sz); return; }
            if (strcmp(h4b, "C809DDDE") == 0) { strncpy(type_out, "79-4E10   ", type_sz); return; }
            snprintf(err, errsz, "UNKNOWN HITACHI GDR3120 78/79 4E10 IDENTIFIER"); return;
        }
        else if (strcmp(h4, "304C0090") == 0) {
            if (strcmp(h4b, "C809DD3A") == 0) { strncpy(type_out, "78-4C30   ", type_sz); return; }
            if (strcmp(h4b, "C809DD41") == 0) { strncpy(type_out, "79-4C30   ", type_sz); return; }
            snprintf(err, errsz, "UNKNOWN HITACHI GDR3120 78/79 4C30 IDENTIFIER"); return;
        }
        else if (strcmp(h4, "204D0090") == 0) {
            if (strcmp(h4b, "C809DD38") == 0) { strncpy(type_out, "78-4D20   ", type_sz); return; }
            if (strcmp(h4b, "C809DD3F") == 0) { strncpy(type_out, "79-4D20   ", type_sz); return; }
            snprintf(err, errsz, "UNKNOWN HITACHI GDR3120 78/79 4D20 IDENTIFIER"); return;
        }

        snprintf(err, errsz, "UNKNOWN HITACHI GDR3120 IDENTIFIER"); return;
    }

    if (strcmp(vtrim, "SAMSUNG") == 0) {
        if (strcmp(mtrim, "TSH943A") != 0) { snprintf(err, errsz, "UNKNOWN SAMSUNG IDENTIFIER"); return; }
        uint8_t b4[4]; char h4[9];
        if (!class12_read_bytes(path, 2152, 4, b4)) { snprintf(err, errsz, "read failed"); return; }
        bytes_to_hex_upper(b4, 4, h4);
        if (strcmp(h4, "E8460100") == 0 || strcmp(h4, "E6A00100") == 0) { strncpy(type_out, "MS25      ", type_sz); return; }
        if (strcmp(h4, "E8D30100") == 0 || strcmp(h4, "E7C10100") == 0) { strncpy(type_out, "MS28      ", type_sz); return; }
        strncpy(type_out, "MS28      ", type_sz);
        return;
    }

    if (strcmp(vtrim, "BENQ") == 0) {
        if (strcmp(mtrim, "VAD6038") != 0) { snprintf(err, errsz, "UNKNOWN BENQ IDENTIFIER"); return; }
        uint8_t b4[4]; char h4[9];
        if (!class12_read_bytes(path, 4, 4, b4)) { snprintf(err, errsz, "read failed"); return; }
        bytes_to_hex_upper(b4, 4, h4);
        if (strcmp(h4, "2E334A4C") == 0 || strcmp(h4, "34EA4A4C") == 0) { strncpy(type_out, "62430     ", type_sz); return; }
        if (strcmp(h4, "2E384A4C") == 0 || strcmp(h4, "34EF4A4C") == 0) { strncpy(type_out, "64930     ", type_sz); return; }
        if (strcmp(h4, "2E6F4A4C") == 0) { strncpy(type_out, "04421     ", type_sz); return; }
        snprintf(err, errsz, "UNKNOWN BENQ VAD6038 IDENTIFIER"); return;
    }

    if (strcmp(vtrim, "LITEON") == 0) {
        if (strcmp(mtrim, "DG16D2S") == 0) {
            const char* graph = "graph.dll";
            if (!file_exists(graph)) { snprintf(err, errsz, "graph.dll not found on the application path"); return; }

            int64_t num = class8_find_hex_pattern(path, graph, 83968, "60067408F0", 4096, 0, 65536);
            if (num != -1) {
                uint8_t b4[4]; char h4[9];
                if (!class12_read_bytes(path, 4, 4, b4)) { snprintf(err, errsz, "read failed"); return; }
                bytes_to_hex_upper(b4, 4, h4);

                if (strcmp(h4, "5DE31800") == 0 || strcmp(h4, "5DE31852") == 0) {
                    int64_t num2 = class8_find_hex_pattern(path, graph, 83968, "60067408F0000000", 4096, 0, 65536);
                    if (num2 != -1) strncpy(type_out, "93450     ", type_sz);
                    else strncpy(type_out, "74850     ", type_sz);
                    return;
                }
                if (strcmp(h4, "5DE31830") == 0) { strncpy(type_out, "93450     ", type_sz); return; }

                uint8_t b16[16]; char h16[33];
                if (!class12_read_bytes(path, 0, 16, b16)) { snprintf(err, errsz, "read failed"); return; }
                bytes_to_hex_upper(b16, 16, h16);
                if (strcmp(h16, "18B21F3A5DE31884B0E2CE2652850420") == 0) {
                    strncpy(type_out, "02510     ", type_sz);
                    return;
                }
                strncpy(type_out, "93450     ", type_sz);
                return;
            }
            else {
                uint8_t b4[4]; char h4[9];
                if (!class12_read_bytes(path, 4, 4, b4)) { snprintf(err, errsz, "read failed"); return; }
                bytes_to_hex_upper(b4, 4, h4);
                if (strcmp(h4, "5DE318F0") == 0) { strncpy(type_out, "83850     ", type_sz); return; }
                if (strcmp(h4, "5DE318DE") == 0) { strncpy(type_out, "83850V2   ", type_sz); return; }
                snprintf(err, errsz, "UNKNOWN LITEON DG16D2S IDENTIFIER"); return;
            }
        }

        if (strcmp(mtrim, "DG16D4S") == 0) {
            uint8_t b4[4]; char h4[9];
            if (!class12_read_bytes(path, 0, 4, b4)) { snprintf(err, errsz, "read failed"); return; }
            bytes_to_hex_upper(b4, 4, h4);
            if (strcmp(h4, "09EF6C2B") == 0) { strncpy(type_out, "9504      ", type_sz); return; }
            if (strcmp(h4, "0922962B") == 0) { strncpy(type_out, "0272      ", type_sz); return; }
            if (strcmp(h4, "096D882B") == 0) {
                uint8_t b4x[4]; char hx[9];
                if (!class12_read_bytes(path, 23, 4, b4x)) { snprintf(err, errsz, "read failed"); return; }
                bytes_to_hex_upper(b4x, 4, hx);
                if (strcmp(hx, "DCAD3ACD") == 0) { strncpy(type_out, "0225      ", type_sz); return; }
                if (strcmp(hx, "A24D02EC") == 0) { strncpy(type_out, "0401      ", type_sz); return; }
                if (strcmp(hx, "70AE16D4") == 0) { strncpy(type_out, "1071      ", type_sz); return; }
            }
            snprintf(err, errsz, "UNKNOWN LITEON DG16D4S IDENTIFIER"); return;
        }

        if (strcmp(mtrim, "DG16D5S") == 0) {
            uint8_t b4[4]; char h4[9];
            if (!class12_read_bytes(path, 0, 4, b4)) { snprintf(err, errsz, "read failed"); return; }
            bytes_to_hex_upper(b4, 4, h4);
            if (strcmp(h4, "4DAFE66F") == 0) { strncpy(type_out, "1175      ", type_sz); return; }
            if (strcmp(h4, "4DAFA16F") == 0) { strncpy(type_out, "1532      ", type_sz); return; }
            snprintf(err, errsz, "UNKNOWN LITEON DG16D5S IDENTIFIER"); return;
        }

        snprintf(err, errsz, "UNKNOWN LITEON IDENTIFIER"); return;
    }

    snprintf(err, errsz, "UN-IDENTIFIED VENDOR-MODEL");
}

static void fw_get_key_hitachi_only(const char* vendor, const char* model, const char* type, const char* path,
    char* key_out, size_t key_sz, int64_t* key_off_out,
    char* err, size_t errsz) {
    key_out[0] = 0;
    err[0] = 0;
    *key_off_out = -1;

    char vtrim[32], mtrim[32], ttrim[32];
    trim_copy(vtrim, sizeof(vtrim), vendor);
    trim_copy(mtrim, sizeof(mtrim), model);
    trim_copy(ttrim, sizeof(ttrim), type);

    if (strcmp(vtrim, "HITACHI") != 0 || strcmp(mtrim, "GDR3120L") != 0) {
        snprintf(err, errsz, "Key parse not implemented for this vendor/model in this build");
        return;
    }

    char e2[128];
    int crypted = hitachi_is_crypted(path, e2, sizeof(e2));
    if (e2[0]) { strncpy(err, e2, errsz); return; }

    int64_t off = -1;
    if (!strcmp(ttrim, "32") || !strcmp(ttrim, "36") || !strcmp(ttrim, "40") ||
        !strcmp(ttrim, "46") || !strcmp(ttrim, "47") || !strcmp(ttrim, "58") || !strcmp(ttrim, "59")) {
        off = 20224;
    }
    else if (!strcmp(ttrim, "78-4B00") || !strcmp(ttrim, "79-4B00")) {
        off = 19200;
    }
    else if (!strcmp(ttrim, "78-4E10") || !strcmp(ttrim, "79-4E10")) {
        off = 19984;
    }
    else if (!strcmp(ttrim, "78-4D20") || !strcmp(ttrim, "79-4D20")) {
        off = 19744;
    }
    else if (!strcmp(ttrim, "78-4C30") || !strcmp(ttrim, "79-4C30")) {
        off = 19504;
    }
    else {
        snprintf(err, errsz, "UNKNOWN HITACHI GDR3120 ROM");
        return;
    }

    uint8_t key[16]; char hex[33];
    if (!class10_read_maybe_decrypt(path, off, 16, crypted, key)) { snprintf(err, errsz, "read failed"); return; }
    bytes_to_hex_upper(key, 16, hex);
    strncpy(key_out, hex, key_sz);
    *key_off_out = off;
}


// -------------------- Missing Helpers for BenQ --------------------

// Wrapper to match the name used in benq functions
#define bytes_to_hex bytes_to_hex_upper

// Compare 16 bytes of binary data against a 32-character hex string
static int hex_equals_32(const uint8_t* bin, const char* hex_str) {
    char buf[33];
    bytes_to_hex_upper(bin, 16, buf);
    return _stricmp(buf, hex_str) == 0;
}

// Search for a byte pattern in a buffer (like memmem)
static long find_bytes(const uint8_t* haystack, long haystackLen, const uint8_t* needle, long needleLen, long startOffset) {
    if (startOffset < 0) startOffset = 0;
    for (long i = startOffset; i <= haystackLen - needleLen; i++) {
        if (memcmp(haystack + i, needle, (size_t)needleLen) == 0) return i;
    }
    return -1;
}

/* This is the repeating “scan 16-byte records” logic from VB smethod_15 (BENQ 62430/64930/04421) */
static int benq_key_from_base(const uint8_t* fw, long fwlen, long base, long* key_off_out, uint8_t key16_out[16]) {
    if (!fw || fwlen < 262144 || base < 0 || base + 16 > fwlen) return -1;

    const char* ALL_FF = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    const char* TEMPLATE = "00112233445566778899AABBCCDDEEFA";

    char hex[33];
    int num = 0;

    /* text="FFFFFFFF..." initially */
    strcpy_s(hex, sizeof(hex), ALL_FF);

    /* While text == ALL_FF OR right half == FFFFFFFFFFFFFFFF */
    while (_stricmp(hex, ALL_FF) == 0 || _stricmp(hex + 16, "FFFFFFFFFFFFFFFF") == 0) {
        long off = base + (long)num * 16;
        if (off < 0 || off + 16 > fwlen) return -2;
        bytes_to_hex(fw + off, 16, hex);
        num++;
        if (num > 0x10000) return -3; /* safety */
    }

    /* While text != ALL_FF */
    while (_stricmp(hex, ALL_FF) != 0) {
        long off = base + (long)num * 16;
        if (off < 0 || off + 16 > fwlen) return -4;
        bytes_to_hex(fw + off, 16, hex);
        num++;
        if (num > 0x10000) return -5;
    }

    /* base += (num-2)*16 */
    base += (long)(num - 2) * 16;

    if (base < 0 || base + 16 > fwlen) return -6;

    /* if current 16 bytes == template, skip it */
    if (hex_equals_32(fw + base, TEMPLATE)) base += 16;

    if (base < 0 || base + 16 > fwlen) return -7;

    memcpy(key16_out, fw + base, 16);
    if (key_off_out) *key_off_out = base;
    return 0;
}

/*
VB BENQ paths in Class12.smethod_15:
- ROM 62430/64930: base = (fw[34462] << 8)
- ROM 04421: base = search template marker, else use fw[27187]<<8 and walk in 0x1000 steps until base-range sane
*/
static int parse_benq_key(const uint8_t* fw, long fwlen, const char* rom_str,
    long* key_off_out, char key_hex_out[33]) {
    if (!fw || fwlen != 262144 || !rom_str || !key_off_out || !key_hex_out) return -1;

    uint8_t key16[16];
    long key_off = -1;

    if (_stricmp(rom_str, "62430") == 0 || _stricmp(rom_str, "64930") == 0) {
        long base = ((long)fw[34462]) << 8;
        int rc = benq_key_from_base(fw, fwlen, base, &key_off, key16);
        if (rc) return rc;
    }
    else if (_stricmp(rom_str, "04421") == 0) {
        /* template marker bytes */
        static const uint8_t tmpl[16] = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFA
        };

        long base = find_bytes(fw, fwlen, tmpl, 16, 0);
        if (base == -1) {
            /* fallback walk: base = fw[27187]<<8 ; if (base - base0) > 256 then base = base0+4096 and repeat */
            long base0 = ((long)fw[27187]) << 8;
            base = base0;
            for (;;) {
                long prev = base;
                int rc = benq_key_from_base(fw, fwlen, base, &key_off, key16);
                if (rc) return rc;
                if ((base - prev) <= 256) break; /* mirrors VB "If num2 - num3 <= 256 Then Exit For" */
                base = prev + 4096;
                if (base + 16 > fwlen) return -20;
            }
        }
        else {
            int rc = benq_key_from_base(fw, fwlen, base, &key_off, key16);
            if (rc) return rc;
        }
    }
    else {
        return -100; /* unsupported BENQ ROM */
    }

    *key_off_out = key_off;
    bytes_to_hex(key16, 16, key_hex_out);
    return 0;
}

int cmd_parse_fw(const char* path, int json) {
    char err[256];
    err[0] = 0;

    int64_t sz = file_len(path);
    if (sz < 0) {
        fprintf(stderr, "Error: cannot open %s\n", path);
        return 2;
    }

    // 1. Identify Vendor
    char vendor[16], model[16], type[16];
    fw_get_vendor(path, vendor, sizeof(vendor), err, sizeof(err));
    if (err[0]) {
        if (json) printf("{\"file\":\"%s\",\"size\":%lld,\"error\":\"%s\"}\n", path, (long long)sz, err);
        else printf("File: %s\nSize: %lld\nError: %s\n", path, (long long)sz, err);
        return (sz == 262144) ? 0 : 2;
    }

    // 2. Identify Model and Type
    fw_get_model(vendor, path, model, sizeof(model), err, sizeof(err));
    if (err[0]) model[0] = 0;

    fw_get_type(vendor, model, path, type, sizeof(type), err, sizeof(err));
    char type_err[256]; strncpy(type_err, err, sizeof(type_err)); type_err[sizeof(type_err) - 1] = 0;
    if (type[0] == 0) strncpy(type, "UNKNOWN   ", sizeof(type));

    // Prepare Trimmed Strings
    char vtrim[32], mtrim[32], ttrim[32];
    trim_copy(vtrim, sizeof(vtrim), vendor);
    trim_copy(mtrim, sizeof(mtrim), model);
    trim_copy(ttrim, sizeof(ttrim), type);

    // 3. Hitachi Specific Checks
    int crypted = -1;
    int stock = -1;
    char hit_err[128] = { 0 };
    if (strcmp(vtrim, "HITACHI") == 0 && strcmp(mtrim, "GDR3120L") == 0) {
        crypted = hitachi_is_crypted(path, hit_err, sizeof(hit_err));
        if (!hit_err[0]) {
            char s_err[128];
            stock = hitachi_is_stock(path, crypted, s_err, sizeof(s_err));
        }
    }

    // 4. Key Extraction
    char key[64] = { 0 };
    int64_t key_off = -1;
    char key_err[256] = { 0 };

    if (strcmp(vtrim, "HITACHI") == 0) {
        fw_get_key_hitachi_only(vendor, model, type, path, key, sizeof(key), &key_off, key_err, sizeof(key_err));
    }
    else if (strcmp(vtrim, "BENQ") == 0) {
        // BenQ logic requires the full file in memory
        FILE* f = fopen(path, "rb");
        if (f) {
            uint8_t* fw_buf = (uint8_t*)malloc(262144);
            if (fw_buf && fread(fw_buf, 1, 262144, f) == 262144) {
                long k_off_l = -1;
                char k_hex[33];
                int rc = parse_benq_key(fw_buf, 262144, ttrim, &k_off_l, k_hex);
                if (rc == 0) {
                    strncpy(key, k_hex, sizeof(key));
                    key_off = (int64_t)k_off_l;
                }
                else {
                    snprintf(key_err, sizeof(key_err), "BenQ parse failed (code %d)", rc);
                }
            }
            else {
                snprintf(key_err, sizeof(key_err), "Failed to load firmware into memory");
            }
            if (fw_buf) free(fw_buf);
            fclose(f);
        }
        else {
            snprintf(key_err, sizeof(key_err), "File open failed");
        }
    }
    else {
        snprintf(key_err, sizeof(key_err), "Key parse not implemented for %s", vtrim);
    }

    // 5. Output Results
    if (json) {
        printf("{");
        printf("\"file\":\"%s\",", path);
        printf("\"size\":%lld,", (long long)sz);
        printf("\"vendor\":\"%s\",", vtrim[0] ? vtrim : "UNKNOWN");
        printf("\"model\":\"%s\",", mtrim[0] ? mtrim : "UNKNOWN");
        printf("\"type\":\"%s\",", ttrim[0] ? ttrim : "UNKNOWN");

        if (strcmp(vtrim, "HITACHI") == 0 && !hit_err[0]) {
            printf("\"crypted\":%s,", crypted ? "true" : "false");
            if (stock >= 0) printf("\"stock\":%s,", stock ? "true" : "false");
        }

        if (key[0]) {
            printf("\"key\":\"%s\",", key);
            printf("\"key_offset\":%lld,", (long long)key_off);
        }
        else {
            printf("\"key\":null,");
            printf("\"key_error\":\"%s\",", key_err[0] ? key_err : "unknown");
        }
        if (type_err[0]) printf("\"type_error\":\"%s\",", type_err);
        printf("\"ok\":true");
        printf("}\n");
    }
    else {
        printf("File:   %s\n", path);
        printf("Size:   %lld bytes\n", (long long)sz);
        printf("Vendor: %s\n", vtrim[0] ? vtrim : "UNKNOWN");
        printf("Model:  %s\n", mtrim[0] ? mtrim : "UNKNOWN");
        printf("Type:   %s\n", ttrim[0] ? ttrim : "UNKNOWN");
        if (type_err[0]) printf("Type note: %s\n", type_err);

        if (strcmp(vtrim, "HITACHI") == 0 && !hit_err[0]) {
            printf("Crypted: %s\n", crypted ? "YES" : "NO");
            if (stock >= 0) printf("Stock:   %s\n", stock ? "YES" : "NO");
        }

        if (key[0]) {
            printf("Key:    %s (offset 0x%llX)\n", key, (unsigned long long)key_off);
        }
        else {
            printf("Key:    (unavailable) %s\n", key_err[0] ? key_err : "unknown");
        }
    }

    return 0;
}

#pragma endregion