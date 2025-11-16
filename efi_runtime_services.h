// SPDX-License-Identifier: GPL-2.0+

/*
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 * David Mosberger-Tang <davidm@hpl.hp.com>
 * Stephane Eranian <eranian@hpl.hp.com>
 * Copyright (c) 2023 ARM Ltd.
 */

#ifndef EFI_RUNTIME_SERVICES_H
#define EFI_RUNTIME_SERVICES_H

#include "efi_defines.h"
#include "efi_guid.h"
#include "efi_table.h"

struct efi_runtime_services {
	struct efi_table_hdr hdr;
	efi_status_t (EFIAPI *get_time)(void *time, void *capabilities);
	efi_status_t (EFIAPI *set_time)(void *time);
	efi_status_t (EFIAPI *get_wakeup_time)(char *enabled, char *pending, void *time);
	efi_status_t (EFIAPI *set_wakeup_time)(char enabled, void *time);
	efi_status_t (EFIAPI *set_virtual_address_map)(
		size_t memory_map_size,
		size_t descriptor_size,
		uint32_t descriptor_version,
		struct efi_mem_desc *virtmap);
	efi_status_t (EFIAPI *convert_pointer)(size_t debug_disposition, void **address);
	efi_status_t (EFIAPI *get_variable)(
		u16 *variable_name,
		const efi_guid_t *vendor,
		u32 *attributes,
		size_t *data_size, void *data);
	efi_status_t (EFIAPI *get_next_variable_name)(
		size_t *variable_name_size,
		u16 *variable_name,
		efi_guid_t *vendor);
	efi_status_t (EFIAPI *set_variable)(
		u16 *variable_name,
		const efi_guid_t *vendor,
		u32 attributes,
		size_t data_size,
		const void *data);
	efi_status_t (EFIAPI *get_next_high_mono_count)(uint32_t *high_count);
	void (EFIAPI *reset_system)(
		enum efi_reset_type reset_type,
		efi_status_t reset_status,
		unsigned long data_size,
		void *reset_data);
	efi_status_t (EFIAPI *update_capsule)(
		void **capsule_header_array,
		size_t capsule_count,
		u64 scatter_gather_list);
	efi_status_t (EFIAPI *query_capsule_caps)(
		void **capsule_header_array,
		size_t capsule_count,
		u64 *maximum_capsule_size,
		u32 *reset_type);
	efi_status_t (EFIAPI *query_variable_info)(
		u32 attributes,
		u64 *maximum_variable_storage_size,
		u64 *remaining_variable_storage_size,
		u64 *maximum_variable_size);
};

extern struct efi_runtime_services efi_runtime_services;

struct efi_runtime_mmio {
	LIST_ENTRY(efi_runtime_mmio) link;
	void **ptr;
	u64 paddr;
	u64 len;
};

extern struct efi_system_table systab;

#endif
