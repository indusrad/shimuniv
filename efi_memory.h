// SPDX-License-Identifier: GPL-2.0+

/*
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 * David Mosberger-Tang <davidm@hpl.hp.com>
 * Stephane Eranian <eranian@hpl.hp.com>
 * Copyright (c) 2023 ARM Ltd.
 */

#ifndef EFI_MEMORY_H
#define EFI_MEMORY_H

#include <stddef.h>

#include "efi_enum.h"
#include "efi_defines.h"

typedef u64 efi_physical_addr_t;
typedef u64 efi_virtual_addr_t;

struct efi_memory_range {
	efi_physical_addr_t	address;
	u64			length;
};

struct efi_mem_desc {
	u32 type;
	u32 reserved;
	efi_physical_addr_t physical_start;
	efi_virtual_addr_t virtual_start;
	u64 num_pages;
	u64 attribute;
};

void *efi_alloc(size_t size);
efi_status_t efi_allocate_pool(enum efi_memory_type pool_type, size_t size, void **buffer);
void *efi_alloc_aligned_pages(u64 len, int memory_type, size_t align);
efi_status_t efi_free_pages(uint64_t memory, size_t pages);
efi_status_t efi_free_pool(void *buffer);
int efi_memory_init(void);
efi_status_t efi_get_memory_map_alloc(size_t *map_size, struct efi_mem_desc **memory_map);
efi_status_t EFIAPI efi_get_memory_map_ext(
		size_t *memory_map_size,
		struct efi_mem_desc *memory_map,
		size_t *map_key,
		size_t *descriptor_size,
		uint32_t *descriptor_version);
efi_status_t efi_allocate_pages(
	enum efi_allocate_type type,
	enum efi_memory_type memory_type,
	size_t pages,
	uint64_t *memory);
efi_status_t EFIAPI efi_allocate_pages_ext(
	int type,
	int memory_type,
	size_t pages,
	uint64_t *memory);
efi_status_t EFIAPI efi_free_pages_ext(uint64_t memory, size_t pages);
efi_status_t EFIAPI efi_allocate_pool_ext(int pool_type, size_t size, void **buffer);
efi_status_t EFIAPI efi_free_pool_ext(void *buffer);
void EFIAPI efi_copy_mem(void *destination, const void *source, size_t length);
void EFIAPI efi_set_mem(void *buffer, size_t size, uint8_t value);
efi_status_t efi_add_memory_map(u64 start, u64 size, int memory_type);

extern size_t efi_memory_map_key;

#endif
