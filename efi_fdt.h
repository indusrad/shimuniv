// SPDX-License-Identifier: GPL-2.0+

/*
 * Copyright (c) 2023 ARM Ltd.
 */

#ifndef EFI_FDT_H
#define EFI_FDT_H

#include "efi_defines.h"

// add fdt as configuration table
efi_status_t efi_fdt_register(void);

#endif // EFI_FDT_H
