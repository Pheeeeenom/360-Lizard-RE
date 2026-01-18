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

#ifdef __cplusplus
extern "C" {
#endif
    const uint8_t sess_key[16] = { 0xBE,0xBE,0xCA,0xFE,0xBE,0xBE,0xCA,0xFE,0xBE,0xBE,0xCA,0xFE,0xBE,0xBE,0xCA,0xFE };
    const uint8_t xor_key[16] = { 0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF };

    int auth28(HANDLE h,
        const uint8_t dvd_key[16],
        const uint8_t sess_key[16],
        const uint8_t xor_key[16]);
    int hex_to_bytes16(const char* hex, uint8_t out[16]);
    int auth3b(HANDLE h,
        const uint8_t dvd_key[16],
        const uint8_t sess_key[16],
        const uint8_t xor_key[16]);
    int dramdump_one(HANDLE h,
        const uint8_t sess_key[16],
        const uint8_t xor_key[16],
        uint32_t lAddress,
        uint8_t out16[16]);
    int dramdump(HANDLE h,
        const uint8_t sess_key[16],
        const uint8_t xor_key[16],
        const char* out_filename);
#ifdef __cplusplus
}
#endif
