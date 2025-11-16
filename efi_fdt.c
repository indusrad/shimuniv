// SPDX-License-Identifier: GPL-2.0+

#include "efi_defines.h"
#include "efi_table.h"

#define EFI_DEVICE_TREE_GUID \
	EFI_GUID(0xb1b621d5, 0xf19c, 0x41a5, 0x83, 0x0b, \
		 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0)

static const efi_guid_t efi_fdt_guid = EFI_DEVICE_TREE_GUID;

efi_status_t efi_fdt_register(void)
{
	extern char _fdt; // defined in linker script

	// Install the FDT in the system configuration table.
	efi_status_t ret = efi_install_configuration_table(&efi_fdt_guid, (void *)&_fdt);
	if (ret != EFI_SUCCESS) {
		printf("Failed to install FDT\n");
		return ret;
	}
	printf("FDT installed in configuration table\n");

	return EFI_SUCCESS;
}
