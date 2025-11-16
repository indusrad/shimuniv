// SPDX-License-Identifier: GPL-2.0+

/*
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 * David Mosberger-Tang <davidm@hpl.hp.com>
 * Stephane Eranian <eranian@hpl.hp.com>
 *  Copyright (c) 2023 ARM Ltd.
 */

#ifndef EFI_GUID_H
#define EFI_GUID_H

#include <stdint.h>
#include <libpayload.h>

/*
 * The EFI spec defines the EFI_GUID as "128-bit buffer containing a unique identifier value.
 * Unless otherwise specified, aligned on a 64-bit boundary".
 * Page 163 of the UEFI specification v2.10 and EDK2 reference implementation both define
 * EFI_GUID as
 * struct { u32 a; u16; b; u16 c; u8 d[8]; };
 * which is 4-byte aligned.
 */
typedef struct {
	u8 b[16];
} efi_guid_t __aligned(4);

#define EFI_GUID(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7) \
	{{ (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, \
		((a) >> 24) & 0xff, \
		(b) & 0xff, ((b) >> 8) & 0xff, \
		(c) & 0xff, ((c) >> 8) & 0xff, \
		(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) } }

extern const efi_guid_t efi_leanefi_guid;      // GUID of the leanefi root node
extern const efi_guid_t efi_guid_rng_protocol; // GUID of RNG protocol
extern const efi_guid_t smbios_guid;           // GUID of the SMBIOS table
extern const efi_guid_t smbios3_guid;          // GUID of the SMBIOS3 table

// event group ExitBootServices() invoked
extern const efi_guid_t efi_guid_event_group_exit_boot_services;
// event group SetVirtualAddressMap() invoked
extern const efi_guid_t efi_guid_event_group_virtual_address_change;

static inline int guidcmp(const void *g1, const void *g2)
{
	return memcmp(g1, g2, sizeof(efi_guid_t));
}

static inline void *guidcpy(void *dst, const void *src)
{
	return memcpy(dst, src, sizeof(efi_guid_t));
}

#endif // EFI_GUID_H
