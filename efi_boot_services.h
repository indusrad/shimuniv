// SPDX-License-Identifier: GPL-2.0+

#ifndef EFI_BOOTTIME_H
#define EFI_BOOTTIME_H

#include "efi_defines.h"

extern struct efi_boot_services efi_boot_services;
efi_status_t EFIAPI efi_unimplemented(void);
efi_status_t __efi_runtime EFIAPI efi_device_error(void);

#endif
