// SPDX-License-Identifier: GPL-2.0+

#ifndef EFI_RUNTIME_H
#define EFI_RUNTIME_H

#include "efi_defines.h"
#include "efi_guid.h"
#include "efi_table.h"

efi_status_t efi_init_runtime_supported(void);
void efi_relocate_runtime_table(unsigned long offset);
void efi_runtime_relocate(unsigned long offset, struct efi_mem_desc *map);

// This list contains all runtime available mmio regions
LIST_HEAD(efi_runtime_mmio_list, efi_runtime_mmio);
extern struct efi_runtime_mmio_list efi_runtime_mmio_list;

#endif
