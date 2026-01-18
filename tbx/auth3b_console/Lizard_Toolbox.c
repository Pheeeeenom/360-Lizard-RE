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
#include "firmware_parser.h"
#include "Lizard_API.h"
#include "auth.h"
#pragma comment(lib, "Bcrypt.lib")



 /* =================== Fast scanner (COM1..256) =================== */
static int com_exists(int idx) {
	char name[16]; snprintf(name, sizeof(name), "COM%d", idx);
	char target[256]; DWORD len = QueryDosDeviceA(name, target, (DWORD)sizeof(target));
	return len != 0;
}
static int fast_scan_find_port(char out_port[32]) {
	for (int i = 1;i <= 256;i++) {
		if (!com_exists(i)) continue;
		char port[16]; snprintf(port, sizeof(port), "COM%d", i);
		printf("Scanning %s\n", port);
		HANDLE h = open_serial_for_scan(port);
		if (h == INVALID_HANDLE_VALUE) continue;
		uint8_t tmp[3] = { 0 }; int rc = liz_probe_UZ(h, tmp);
		CloseHandle(h);
		if (rc == 0) { snprintf(out_port, 32, "%s", port); return 0; }
	}
	return -1;
}

/* =================== INQUIRY =================== */
static int inquiry(HANDLE h)
{
	uint8_t cdb[12] = { 0x12, 0, 0, 0, 0x24, 0xC0 };
	uint8_t buf[36] = { 0 };
	uint8_t err = 0, sns = 0;
	liz_sync(h);
	int rc = liz_atapi_cmd(h, cdb, 0, 36, 0, buf, &err, &sns, 0);
	TRACE("INQUIRY rc=%d err=0x%02X sns=0x%02X", rc, err, sns);
	if (rc != 0 || err != 0x50) {
		printf("INQUIRY failed (rc=%d err=0x%02X sns=0x%02X)\n", rc, err, sns);
		return -1;
	}
	char vendor[9] = { 0 }, product[17] = { 0 }, rev[5] = { 0 };
	memcpy(vendor, &buf[8], 8);
	memcpy(product, &buf[16], 16);
	memcpy(rev, &buf[32], 4);
	printf("INQUIRY result:\n");
	printf("  Vendor : %-8s\n", vendor);
	printf("  Product: %-16s\n", product);
	printf("  Rev    : %-4s\n", rev);
	return 0;
}

/* HITACHI MODEB FW READ */

static int hit_send_stx_vb(HANDLE h) {
	const uint8_t stx = 0x02;
	DWORD w = 0;
	if (!WriteFile(h, &stx, 1, &w, NULL) || w != 1) return 129;
	return 0;
}

static int hit_getpage_vb(HANDLE h, int isize, uint8_t* buf, DWORD data_timeout_ms) {
	uint8_t b = 0;

	/* Read marker: expect STX (0x02) */
	if (read_exact_soft_deadline(h, &b, 1, 5000) != 0) return 132;
	if (b != 0x02) {
		printf("Hitachi: expected STX 0x02, got 0x%02X\n", b);
		return 136;
	}

	/* ACK STX */
	b = 0x06;
	DWORD w = 0;
	if (!WriteFile(h, &b, 1, &w, NULL) || w != 1) return 129;

	/* Read EXACTLY 1024 bytes of payload */
	if (read_exact_soft_deadline(h, buf, isize, data_timeout_ms) != 0) return 132;

	/*
	  VB's ReadUSARTw_to(..., True) behavior:
	  consume ONE trailing status/check byte after the payload.
	  This byte may be 0xA1, 0x02, etc. We discard it always.
	*/
	uint8_t trailer = 0;
	(void)read_exact_soft_deadline(h, &trailer, 1, 600); /* OK if it times out */

	return 0;
}


/* VB: method_50(): if bool_3 then reopen at 1,000,000 baud */
static int hit_reopen_if_fastbaud(const char* port_name, int hit_fastbaud, HANDLE* io_h) {
	if (!hit_fastbaud) return 0;

	if (*io_h && *io_h != INVALID_HANDLE_VALUE) {
		CloseHandle(*io_h);
		*io_h = INVALID_HANDLE_VALUE;
	}

	HANDLE h = open_serial_common(port_name);
	if (h == INVALID_HANDLE_VALUE) return 1;

	DCB dcb = { 0 }; dcb.DCBlength = sizeof(dcb);
	if (!GetCommState(h, &dcb)) { CloseHandle(h); return 1; }

	dcb.BaudRate = 1000000;
	dcb.ByteSize = 8;
	dcb.Parity = NOPARITY;
	dcb.StopBits = ONESTOPBIT;
	dcb.fOutxCtsFlow = FALSE; dcb.fOutxDsrFlow = FALSE;
	dcb.fDtrControl = DTR_CONTROL_DISABLE;
	dcb.fRtsControl = RTS_CONTROL_DISABLE;

	if (!SetCommState(h, &dcb)) { CloseHandle(h); return 1; }

	COMMTIMEOUTS t = { 0 };
	t.ReadIntervalTimeout = 5000;
	t.ReadTotalTimeoutConstant = 5000;
	t.WriteTotalTimeoutConstant = 1000;
	SetCommTimeouts(h, &t);

	SetupComm(h, 4096, 4096);
	PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR | PURGE_RXABORT | PURGE_TXABORT);

	*io_h = h;
	return 0;
}

static int hitachi_read_fw_vbflow(HANDLE* io_h,
	const char* port_name,
	const char* out_path,
	int turbo_on,
	int hit_fastbaud)
{
	HANDLE h = *io_h;

	/* reset prefetch state each run */

	if (!turbo_set(h, turbo_on ? 1 : 0)) return 2;

	/* Send @Uq@ and expect ACK */
	{
		const uint8_t UQ[4] = { 0x40,0x55,0x71,0x40 };
		DWORD w = 0;
		if (!WriteFile(h, UQ, 4, &w, NULL) || w != 4) return 129;

		uint8_t resp = 0;
		if (read_exact_soft_deadline(h, &resp, 1, 5000) != 0) return 132;
		if (resp != 0x06) {
			printf("Hitachi: expected ACK 0x06, got 0x%02X\n", resp);
			return 136;
		}
	}

	/* Optional fast-baud reopen */
	{
		int rc = hit_reopen_if_fastbaud(port_name, hit_fastbaud, io_h);
		if (rc != 0) {
			printf("Hitachi: failed to reopen at 1,000,000 baud\n");
			return 1;
		}
		h = *io_h;
	}

	FILE* f = fopen(out_path, "wb");
	if (!f) { perror("fopen"); return 1; }

	uint8_t page[1024];
	for (int i = 0; i <= 255; i++) {
		if (i == 0) {
			int rc = hit_send_stx_vb(h);
			if (rc != 0) {
				printf("Hitachi: send_STX failed rc=%d\n", rc);
				fclose(f);
				return rc;
			}
		}

		int rc = hit_getpage_vb(h, 1024, page, 5000);
		if (rc != 0) {
			printf("Hitachi: GETPAGE failed at addr 0x%X (page %d) rc=%d\n", i * 1024, i, rc);
			fclose(f);
			return rc;
		}

		if (fwrite(page, 1, 1024, f) != 1024) {
			printf("Hitachi: file write error\n");
			fclose(f);
			return 1;
		}
	}

	fclose(f);
	printf("\nHitachi FW read OK: %s (262144 bytes)\n", out_path);
	return 0;
}




/* =================== CLI / Main =================== */
static void print_usage(const char* exe) {
	printf("Usage:\n");
	printf("  %s --parse-fw <fw.bin> [--json]\n", exe);
	printf("  %s [COMx | --find] [-i] [-t0|-t1] [-v] [-v28] [-d] [-s] [-hr <file>] [-hb1] [-k <dvdkey32hex>]\n\n", exe);

	printf("Options:\n");
	printf("  --parse-fw <fw>  Parse firmware file and print detected vendor/model/type/key info (no COM required)\n");
	printf("  --json           With --parse-fw: print JSON output\n");
	printf("  --find           Fast-scan COM ports for Lizard (@UZ@ probe)\n");
	printf("  -i               Print device details (IDs/serial/OS/name); -t1 enables turbo\n");
	printf("  -t0|-t1          Turbo/Burst OFF/ON for details path and Hitachi read\n");
	printf("  -v               Run AUTH 0x3B (default) (requires -k)\n");
	printf("  -v28             Run AUTH 0x28 (Lite-On D5S) (requires -k)\n");
	printf("  -d               DRAM dump (requires -k). Uses -v28 logic if specified, else -v.\n");
	printf("  -s               INQUIRY (ATAPI identify)\n");
	printf("  -hr <file>       Hitachi MODEB read via @Uq@: dumps 256*1024 bytes to <file>\n");
	printf("  -hb1             Hitachi: reopen at 1,000,000 baud after enabling Turbo/BURST mode\n");
	printf("  -k <dvdkey>      DVD key (REQUIRED for -v, -v28, or -d): 32 hex chars (16 bytes)\n");

	printf("\nExamples:\n");
	printf("  %s --parse-fw orig.bin\n", exe);
	printf("  %s --parse-fw orig.bin --json\n", exe);
	printf("  %s --find -i -t1\n", exe);
	printf("  %s COM5 -v28 -k 00112233445566778899AABBCCDDEEFF\n", exe);
	printf("  %s COM5 -d -v28 -k 00112233445566778899AABBCCDDEEFF\n", exe);
	printf("  %s COM5 -hr src.bin -hb1 -t1\n", exe);
}


int main(int argc, char** argv) {
	const char* portArg = NULL;
	int do_find = 0, do_info = 0, turbo_on = 0;
	int do_auth_3b = 0, do_auth_28 = 0, do_dram = 0, do_inq = 0;
	const char* dvdkey_arg = NULL;

	/* Hitachi read flags */
	int do_hitread = 0;
	const char* hit_out = NULL;
	int hit_fastbaud = 0;

	/* Firmware parse flag */
	int do_parse_fw = 0;
	const char* parse_fw_path = NULL;
	int parse_fw_json = 0;

	if (argc < 2) { print_usage(argv[0]); return 1; }
	for (int i = 1; i < argc; i++) {
		const char* a = argv[i];

		if (_stricmp(a, "--find") == 0) do_find = 1;
		else if (_stricmp(a, "-i") == 0) do_info = 1;
		else if (_stricmp(a, "-t1") == 0) turbo_on = 1;
		else if (_stricmp(a, "-t0") == 0) turbo_on = 0;
		else if (_stricmp(a, "-v") == 0) do_auth_3b = 1;
		else if (_stricmp(a, "-v28") == 0) do_auth_28 = 1;
		else if (_stricmp(a, "-d") == 0) do_dram = 1;
		else if (_stricmp(a, "-s") == 0) do_inq = 1;

		else if (_stricmp(a, "-hr") == 0) {
			if (i + 1 < argc) { do_hitread = 1; hit_out = argv[++i]; }
			else { print_usage(argv[0]); return 1; }
		}
		else if (_stricmp(a, "-hb1") == 0) {
			hit_fastbaud = 1;
		}
		else if (_stricmp(a, "-k") == 0 || _stricmp(a, "--dvdkey") == 0) {
			if (i + 1 < argc) dvdkey_arg = argv[++i];
			else { print_usage(argv[0]); return 1; }
		}

		/* NEW: firmware parsing (no COM port required) */
		else if (_stricmp(a, "--parse-fw") == 0) {
			if (i + 1 < argc) { do_parse_fw = 1; parse_fw_path = argv[++i]; }
			else { print_usage(argv[0]); return 1; }
		}
		else if (_stricmp(a, "--json") == 0) {
			parse_fw_json = 1;
		}

		else {
			if (!portArg) portArg = a;
			else { print_usage(argv[0]); return 1; }
		}
	}

	/* If we're only parsing FW, do it and exit (no serial needed) */
	if (do_parse_fw) {
		if (!parse_fw_path) { print_usage(argv[0]); return 1; }
		return cmd_parse_fw(parse_fw_path, parse_fw_json);
	}

	if (!portArg && !do_find) { print_usage(argv[0]); return 1; }

	char chosen[32] = { 0 };
	if (do_find) {
		if (fast_scan_find_port(chosen) != 0) { printf("No Lizard found via scan.\n"); return 2; }
		printf("Found Lizard at %s\n", chosen);
		portArg = chosen;
	}

	HANDLE h = open_serial_for_detail(portArg);
	if (h == INVALID_HANDLE_VALUE) {
		printf("Open %s failed (GLE=%lu)\n", portArg, GetLastError());
		return 1;
	}

	if (do_info) {
		DeviceDetails dd; snprintf(dd.port, sizeof(dd.port), "%s", portArg);
		int rc = getdevicedetails_on_handle(h, turbo_on, &dd);
		if (rc != 0) { printf("getdevicedetails failed (%d)\n", rc); CloseHandle(h); return 3; }
		print_details(&dd);
	}

	if (do_inq) {
		(void)inquiry(h);
		liz_send_etx(h);
		CloseHandle(h);
		return 0;
	}

	if (do_hitread) {
		if (!hit_out) { print_usage(argv[0]); liz_send_etx(h); CloseHandle(h); return 1; }
		HANDLE hh = h; /* may be reopened at 1,000,000 baud */
		int rc = hitachi_read_fw_vbflow(&hh, portArg, hit_out, turbo_on, hit_fastbaud);
		liz_send_etx(hh);
		CloseHandle(hh);
		return (rc == 0) ? 0 : 4;
	}


	uint8_t dvd_key[16];

	if ((do_auth_3b || do_auth_28 || do_dram) && !dvdkey_arg) {
		fprintf(stderr, "Error: -k <dvdkey32hex> is required for -v, -v28 or -d\n");
		CloseHandle(h);
		return 1;
	}

	if (do_auth_3b || do_auth_28 || do_dram) {
		int rcKey = hex_to_bytes16(dvdkey_arg, dvd_key);
		if (rcKey != 0) {
			fprintf(stderr, "Invalid DVD key: must be exactly 32 hex characters. Error %d\n", rcKey);
			CloseHandle(h);
			return 1;
		}

		int rc = 0;
		if (do_auth_28) rc = auth28(h, dvd_key, sess_key, xor_key);
		else            rc = auth3b(h, dvd_key, sess_key, xor_key);

		if (rc != 0) {
			liz_send_etx(h);
			CloseHandle(h);
			return 2;
		}

		if (do_dram) {
			dramdump(h, sess_key, xor_key, "dram.bin");
		}

		liz_send_etx(h);
		CloseHandle(h);
		return 0;
	}

	CloseHandle(h);
	return 0;
}