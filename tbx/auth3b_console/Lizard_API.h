#pragma once

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

#define TRACE(...) do { printf(__VA_ARGS__); printf("\n"); } while (0)

#ifdef __cplusplus
extern "C" {
#endif
    typedef struct {
        char port[64];
        char flash_dev_id[64];
        uint64_t flash_size_bytes;
        char serial[128];
        char os_version[64];
        char name[128];
    } DeviceDetails;

    void liz_sync(HANDLE h);
    void liz_send_etx(HANDLE h);
    inline uint8_t liz_mix(uint8_t acc, uint8_t x);
    uint8_t liz_checksum(const uint8_t* buf, int len);
    int liz_probe_UZ(HANDLE h, uint8_t out3[3]);
    int read_exact(HANDLE h, void* buf, DWORD len);
    HANDLE open_serial_for_detail(const char* port);
    HANDLE open_serial_common(const char* port);
    HANDLE open_serial_for_scan(const char* port);
    int getdevicedetails_on_handle(HANDLE h, int turbo_on, DeviceDetails* out);
    void print_details(const DeviceDetails* d);
    void dump_hex(const char* tag, const uint8_t* buf, int len);
    int read_exact_soft_deadline(HANDLE h, void* buf, int len, DWORD total_ms);
    int liz_atapi_cmd(HANDLE h,
        const uint8_t cdb[12],
        uint8_t direction, int rsize, int wsize,
        uint8_t* buf, uint8_t* errstat, uint8_t* sense,
        int continued_read);
    int spif_readpage(HANDLE h, int addr, int size, uint8_t* out, int continued, int sendAddr);
    int turbo_set(HANDLE h, int on);

#ifdef __cplusplus
}
#endif
