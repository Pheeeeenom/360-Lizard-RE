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

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "Lizard_API.h"

/* =================== Utilities =================== */
void dump_hex(const char* tag, const uint8_t* buf, int len) {
    printf("%s (%d):", tag, len);
    for (int i = 0; i < len; i++) printf(" %02X", buf[i]);
    printf("\n");
}
#define TRACE(...) do { printf(__VA_ARGS__); printf("\n"); } while (0)

int read_exact_soft_deadline(HANDLE h, void* buf, int len, DWORD total_ms) {
    uint8_t* p = (uint8_t*)buf; int got = 0; DWORD start = GetTickCount();
    while (got < len) {
        if (GetTickCount() - start > total_ms) break;
        DWORD r = 0;
        if (!ReadFile(h, p + got, (DWORD)(len - got), &r, NULL)) return -1;
        if (r == 0) { Sleep(4); continue; }
        got += (int)r;
    }
    return (got == len) ? 0 : -2;
}

/* tiny helpers */
static int write_all(HANDLE h, const void* buf, DWORD len) {
    DWORD w = 0; if (!WriteFile(h, buf, len, &w, NULL)) return 0; return (w == len);
}
int read_exact(HANDLE h, void* buf, DWORD len) {
    DWORD got = 0;
    while (got < len) {
        DWORD r = 0; if (!ReadFile(h, (uint8_t*)buf + got, len - got, &r, NULL)) return 0;
        if (r == 0) return 0; got += r;
    }
    return 1;
}

/* =================== Lizard checksum =================== */
inline uint8_t liz_mix(uint8_t acc, uint8_t x) {
    uint8_t b = (uint8_t)((x ^ acc) & 0xFF), out = 0;
    if (b & 0x01) out ^= 0x5E; if (b & 0x02) out ^= 0xBC;
    if (b & 0x04) out ^= 0x61; if (b & 0x08) out ^= 0xC2;
    if (b & 0x10) out ^= 0x9D; if (b & 0x20) out ^= 0x23;
    if (b & 0x40) out ^= 0x46; if (b & 0x80) out ^= 0x8C;
    return out;
}
uint8_t liz_checksum(const uint8_t* buf, int len) {
    uint8_t acc = 0;
    for (int i = 0; i < len; i++) acc = liz_mix(acc, buf[i]);
    return acc;
}

/* =================== Serial open helpers =================== */
HANDLE open_serial_common(const char* port) {
    char path[64];
    if (_strnicmp(port, "\\\\.\\", 4) == 0) snprintf(path, sizeof(path), "%s", port);
    else snprintf(path, sizeof(path), "\\\\.\\%s", port);

    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    DCB dcb = { 0 }; dcb.DCBlength = sizeof dcb;
    if (!GetCommState(h, &dcb)) { CloseHandle(h); return INVALID_HANDLE_VALUE; }
    dcb.BaudRate = CBR_115200; dcb.ByteSize = 8; dcb.Parity = NOPARITY; dcb.StopBits = ONESTOPBIT;
    dcb.fOutxCtsFlow = FALSE; dcb.fOutxDsrFlow = FALSE;
    dcb.fDtrControl = DTR_CONTROL_DISABLE; dcb.fRtsControl = RTS_CONTROL_DISABLE;
    if (!SetCommState(h, &dcb)) { CloseHandle(h); return INVALID_HANDLE_VALUE; }

    SetupComm(h, 4096, 4096);
    PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR | PURGE_RXABORT | PURGE_TXABORT);
    return h;
}

/* fast scan timeouts (~100ms read, ~50ms write) */
HANDLE open_serial_for_scan(const char* port) {
    HANDLE h = open_serial_common(port);
    if (h == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    COMMTIMEOUTS t = { 0 };
    t.ReadIntervalTimeout = 100;
    t.ReadTotalTimeoutConstant = 100;
    t.WriteTotalTimeoutConstant = 50;
    SetCommTimeouts(h, &t);
    return h;
}

/* long timeouts (detail path: 5s read, 1s write) */
HANDLE open_serial_for_detail(const char* port) {
    HANDLE h = open_serial_common(port);
    if (h == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    COMMTIMEOUTS t = { 0 };
    t.ReadIntervalTimeout = 5000;
    t.ReadTotalTimeoutConstant = 5000;
    t.WriteTotalTimeoutConstant = 1000;
    SetCommTimeouts(h, &t);
    return h;
}

/* =================== Wire sync + ETX =================== */
void liz_send_etx(HANDLE h) { DWORD w = 0; const uint8_t etx = 0x03; WriteFile(h, &etx, 1, &w, NULL); }
void liz_sync(HANDLE h) {
    PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR);
    liz_send_etx(h);
    Sleep(15);
    EscapeCommFunction(h, SETDTR);
    EscapeCommFunction(h, SETRTS);
    Sleep(10);
    EscapeCommFunction(h, CLRRTS);
}

/* =================== UZ presence probe =================== */
int liz_probe_UZ(HANDLE h, uint8_t out3[3]) {
    const uint8_t UZ[4] = { 0x40,0x55,0x5A,0x40 };
    if (!write_all(h, UZ, 4)) return 2;
    if (!read_exact(h, out3, 3)) return 4;
    return (out3[2] == 0x06) ? 0 : 3;
}

/* =================== ATAPI transport =================== */
static int liz_send_preamble(HANDLE h, int continued_read) {
    DWORD w = 0;
    if (!continued_read) { const uint8_t pre[4] = { 0x40,0x55,0x78,0x40 }; if (!WriteFile(h, pre, 4, &w, NULL) || w != 4) return 129; }
    else { const uint8_t b = 0x02; if (!WriteFile(h, &b, 1, &w, NULL) || w != 1) return 129; }
    return 0;
}
int liz_atapi_cmd(HANDLE h,
    const uint8_t cdb[12],
    uint8_t direction, int rsize, int wsize,
    uint8_t* buf, uint8_t* errstat, uint8_t* sense,
    int continued_read)
{
    uint8_t tmp[514]; DWORD w = 0;
    if (liz_send_preamble(h, continued_read)) return 129;

    if (read_exact_soft_deadline(h, tmp, 1, 2000) != 0) return 132;
    if (tmp[0] != 0x06) return 136;

    memcpy(tmp, cdb, 12);
    tmp[12] = direction; tmp[13] = 0;
    tmp[14] = (uint8_t)(wsize & 0xFF); tmp[15] = (uint8_t)((wsize >> 8) & 0xFF);
    tmp[16] = (uint8_t)(rsize & 0xFF); tmp[17] = (uint8_t)((rsize >> 8) & 0xFF);
    tmp[18] = liz_checksum(tmp, 18);
    if (!WriteFile(h, tmp, 19, &w, NULL) || w != 19) return 129;

    if (read_exact_soft_deadline(h, tmp, 1, 2000) != 0) return 132;
    if (tmp[0] != 0x06) return 136;

    if (wsize > 0) {
        memcpy(tmp, buf, (size_t)wsize);
        tmp[wsize] = liz_checksum(tmp, wsize);
        if (!WriteFile(h, tmp, (DWORD)(wsize + 1), &w, NULL) || (int)w != (wsize + 1)) return 129;
        if (read_exact_soft_deadline(h, tmp, 1, 2000) != 0) return 132;
        if (tmp[0] != 0x06) return 136;
    }

    if (read_exact_soft_deadline(h, tmp, 2, 2000) != 0) return 132;
    *errstat = tmp[0]; *sense = tmp[1];

    if (*errstat != 0x50) { const uint8_t nak = 0x15; WriteFile(h, &nak, 1, &w, NULL); return 0; }
    { const uint8_t ack = 0x06; if (!WriteFile(h, &ack, 1, &w, NULL) || w != 1) return 129; }

    if (rsize > 0) {
        if (read_exact_soft_deadline(h, buf, rsize, 3000) != 0) return 132;
        uint8_t chk = 0; if (read_exact_soft_deadline(h, &chk, 1, 2000) != 0) return 132;
        const uint8_t ack2 = 0x06; if (!WriteFile(h, &ack2, 1, &w, NULL) || w != 1) return 129;
    }
    return 0;
}

/* =================== Device details =================== */

static uint64_t flash_size_from_code(const char* code4) {
    if (strncmp(code4, "BF8E", 4) == 0) return 1ULL * 1024 * 1024;
    if (strncmp(code4, "BF4A", 4) == 0) return 4ULL * 1024 * 1024;
    return 0;
}
static void smethod_1_to_string(const uint8_t* bytes, size_t buflen, int int_92, int int_93, char* out, size_t outsz) {
    if (!outsz) return; out[0] = '\0';
    size_t end = (int_92 == 0) ? (buflen ? buflen - 1 : 0) : (int_92 > 0 ? (size_t)(int_92 - 1) : 0);
    size_t start = (int_93 >= 0) ? (size_t)int_93 : 0;
    if (start >= buflen) return; if (end >= buflen) end = buflen - 1;
    size_t k = 0; for (size_t i = start;i <= end && k + 1 < outsz;i++) out[k++] = (char)bytes[i]; out[k] = '\0';
}
static void bytes_to_hex_n(const uint8_t* src, size_t n, char* dst, size_t dstsz) {
    if (!dstsz) return; static const char H[] = "0123456789ABCDEF";
    size_t maxbytes = (dstsz - 1) / 2; size_t m = n < maxbytes ? n : maxbytes;
    for (size_t i = 0;i < m;i++) { dst[i * 2 + 0] = H[(src[i] >> 4) & 0xF]; dst[i * 2 + 1] = H[src[i] & 0xF]; }
    dst[m * 2] = '\0';
}
int getdevicedetails_on_handle(HANDLE h, int turbo_on, DeviceDetails* out) {
    if (!out) return 1; memset(out, 0, sizeof(*out));
    COMMTIMEOUTS tsave = { 0 }, tcur = { 0 }; GetCommTimeouts(h, &tsave);
    tcur = tsave; tcur.ReadIntervalTimeout = 5000; tcur.ReadTotalTimeoutConstant = 5000; tcur.WriteTotalTimeoutConstant = 1000; SetCommTimeouts(h, &tcur);

    uint8_t id3[3] = { 0 }; int rc = liz_probe_UZ(h, id3); if (rc) { SetCommTimeouts(h, &tsave); return rc; }
    char first4[5] = { 0 }; snprintf(first4, sizeof(first4), "%02X%02X", id3[0], id3[1]);
    uint64_t size_bytes = flash_size_from_code(first4);
    if (!size_bytes) { SetCommTimeouts(h, &tsave); return 3; }
    out->flash_size_bytes = size_bytes;
    snprintf(out->flash_dev_id, sizeof(out->flash_dev_id), "%02X%02X  Size: %.0fMB", id3[0], id3[1], (double)size_bytes / 1024.0 / 1024.0);

    {
        const uint8_t U0[4] = { 0x40,0x55,0x30,0x40 }; DWORD w = 0;
        if (!WriteFile(h, U0, 4, &w, NULL) || w != 4) { SetCommTimeouts(h, &tsave); return 2; }
        uint8_t rsp[34] = { 0 }; if (!read_exact(h, rsp, 34) || rsp[33] != 0x06) { SetCommTimeouts(h, &tsave); return 4; }
        char prefix[64]; smethod_1_to_string(rsp, sizeof(rsp), 16, 0, prefix, sizeof(prefix));
        char tail32[33] = { 0 }; bytes_to_hex_n(rsp + 16, 16, tail32, sizeof(tail32));
        snprintf(out->serial, sizeof(out->serial), "%s-%s", prefix, tail32);
    }
    {
        const uint8_t U1[4] = { 0x40,0x55,0x31,0x40 }; DWORD w = 0;
        if (!WriteFile(h, U1, 4, &w, NULL) || w != 4) { SetCommTimeouts(h, &tsave); return 2; }
        uint8_t rsp[22] = { 0 }; if (!read_exact(h, rsp, 22) || rsp[21] != 0x06) { SetCommTimeouts(h, &tsave); return 4; }
        char ver[64]; smethod_1_to_string(rsp, sizeof(rsp), 20, 0, ver, sizeof(ver));
        size_t L = strlen(ver); while (L && isspace((unsigned char)ver[L - 1])) ver[--L] = '\0';
        size_t i = 0; while (ver[i] && isspace((unsigned char)ver[i])) i++;
        if (i) memmove(ver, ver + i, strlen(ver + i) + 1);
        snprintf(out->os_version, sizeof(out->os_version), "%s", ver);
    }
    {
        uint8_t page[1024] = { 0 }; int e = spif_readpage(h, 0x20000, 1024, page, 0, 0);
        if (!e) { liz_send_etx(h); char nm[128]; smethod_1_to_string(page, sizeof(page), 12, 2, nm, sizeof(nm)); snprintf(out->name, sizeof(out->name), "%s", nm); }
    }
    if (turbo_on) (void)turbo_set(h, 1);

    SetCommTimeouts(h, &tsave);
    return 0;
}
void print_details(const DeviceDetails* d) {
    printf("\n==== Device Details ====\n");
    printf("Port:          %s\n", d->port[0] ? d->port : "(handle)");
    if (d->flash_dev_id[0]) printf("Flash Dev ID:  %s\n", d->flash_dev_id);
    if (d->flash_size_bytes) printf("Flash Size:    %.0f MB\n", (double)d->flash_size_bytes / 1024.0 / 1024.0);
    if (d->serial[0])       printf("Serial:        %s\n", d->serial);
    if (d->os_version[0])   printf("OS Version:    %s\n", d->os_version);
    if (d->name[0])         printf("Name:          %s\n", d->name);
    printf("=======================\n");
}

/* =================== Lizard SPI flash read (@US@) =================== */
int spif_readpage(HANDLE h, int addr, int size, uint8_t* out, int continued, int sendAddr) {
    uint8_t b; DWORD w = 0;
    if (!continued) {
        const uint8_t pre[4] = { 0x40,0x55,0x53,0x40 }; // "@US@"
        if (!WriteFile(h, pre, 4, &w, NULL) || w != 4) return 129;
    }
    else {
        b = sendAddr ? 0x10 : 0x02;
        if (!WriteFile(h, &b, 1, &w, NULL) || w != 1) return 129;
    }
    if (read_exact_soft_deadline(h, &b, 1, 2000) != 0) return 132;
    if (b != 0x06) return 136;

    if (!continued || sendAddr) {
        uint8_t frame[7];
        frame[0] = (uint8_t)(addr & 0xFF);
        frame[1] = (uint8_t)((addr >> 8) & 0xFF);
        frame[2] = (uint8_t)((addr >> 16) & 0xFF);
        frame[3] = (uint8_t)((addr >> 24) & 0xFF);
        frame[4] = (uint8_t)(size & 0xFF);
        frame[5] = (uint8_t)((size >> 8) & 0xFF);
        frame[6] = liz_checksum(frame, 6);
        if (!WriteFile(h, frame, 7, &w, NULL) || w != 7) return 129;
    }

    if (read_exact_soft_deadline(h, &b, 1, 2000) != 0) return 132;
    if (b != 0x06) return 136;
    if (read_exact_soft_deadline(h, out, size, 5000) != 0) return 132;
    if (read_exact_soft_deadline(h, &b, 1, 2000) != 0) return 132;
    return 0;
}

/* =================== Turbo toggle (@U4@/@U5@) =================== */
int turbo_set(HANDLE h, int on) {
    uint8_t cmd[4] = { 0x40,0x55,(uint8_t)(on ? 0x05 : 0x04),0x40 }; DWORD w = 0, r = 0;
    if (!WriteFile(h, cmd, 4, &w, NULL) || w != 4) { printf("Cannot write turbo cmd\n"); return 0; }
    uint8_t resp = 0; if (!ReadFile(h, &resp, 1, &r, NULL) || r != 1) { printf("No turbo response\n"); return 0; }
    if (resp == 0x15) { printf("Burst Mode OFF\n"); return 1; }
    if (resp != 0x06) { printf("Bad Turbo Response: 0x%02X\n", resp); return 0; }
    printf("Burst Mode %s\n", on ? "ON" : "OFF"); return 1;
}